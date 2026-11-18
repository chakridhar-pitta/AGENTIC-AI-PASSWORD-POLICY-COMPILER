import sys
import os
import json
import time
import shutil
import hashlib
import argparse
import subprocess
import tempfile
from pathlib import Path
from typing import Optional, Dict, Any, Tuple

from .ledger import (
    Ledger,
    ROLE_PERMISSIONS,
    TRANSITION_TABLE,
    STAGE_ARTIFACTS,
    get_db_connection
)
from .envelope import (
    load_key,
    verify_signature,
    create_task_envelope,
    create_result_envelope,
    sign_gate_approval
)


class Worker:
    def __init__(self,
                 role: str,
                 worker_id: str,
                 db_path: Path,
                 workspace_dir: Path,
                 keys_dir: Path,
                 compiler_bin: Optional[Path] = None,
                 lease_seconds: float = 5.0,
                 poll_interval: float = 0.5,
                 delay: float = 0.0):
        self.role = role
        self.worker_id = worker_id
        self.db_path = Path(db_path)
        self.workspace_dir = Path(workspace_dir)
        self.keys_dir = Path(keys_dir)
        self.lease_seconds = lease_seconds
        self.poll_interval = poll_interval
        self.delay = float(delay)
        self.running = False

        if self.role not in ROLE_PERMISSIONS:
            raise ValueError(f"Unknown or unauthorized role: {self.role}. Allowed: {list(ROLE_PERMISSIONS.keys())}")

        self.permission = ROLE_PERMISSIONS[self.role]
        self.permitted_stage = self.permission['stage']
        self.permitted_action = self.permission['action']
        self.permitted_artifact = self.permission['artifact']

        if compiler_bin:
            self.compiler_bin = Path(compiler_bin)
        else:
            self.compiler_bin = Path("policy_compiler.exe" if os.name == 'nt' else "./policy_compiler")

        self.ledger = Ledger(self.db_path)
        self.role_key = load_key(self.role, self.keys_dir)
        self.broker_key = load_key('broker', self.keys_dir)

    def lease_task(self) -> Optional[Dict[str, Any]]:
        """Atomically leases an available READY task matching this worker's role."""
        now = time.time()
        lease_exp = now + self.lease_seconds

        with get_db_connection(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE;")
            row = conn.execute("""
                SELECT s.job_id, s.stage, s.input_hash, s.attempts,
                       j.policy_path, j.policy_hash, j.approved_repair
                FROM stages s
                JOIN jobs j ON s.job_id = j.job_id
                WHERE s.stage = ? AND s.status = 'READY'
                LIMIT 1;
            """, (self.permitted_stage,)).fetchone()

            if not row:
                conn.execute("ROLLBACK;")
                return None

            job_id = row['job_id']
            stage = row['stage']
            attempts = row['attempts'] + 1

            conn.execute("""
                UPDATE stages
                SET status = 'LEASED', worker_id = ?, lease_expires = ?, attempts = ?
                WHERE job_id = ? AND stage = ? AND status = 'READY';
            """, (self.worker_id, lease_exp, attempts, job_id, stage))
            conn.execute("COMMIT;")

        # Construct task envelope signed by broker
        task_env = create_task_envelope(
            broker_key=self.broker_key,
            job_id=job_id,
            stage=stage,
            input_hash=row['input_hash'],
            deadline=lease_exp,
            action=self.permitted_action,
            approved_repair=row['approved_repair'],
            policy_path=row['policy_path'],
            policy_hash=row['policy_hash']
        )

        self.ledger.log_event(job_id, stage, "STAGE_LEASED", {
            "worker_id": self.worker_id,
            "role": self.role,
            "attempts": attempts,
            "deadline": lease_exp
        })
        return task_env

    def heartbeat(self, job_id: str, stage: str):
        """Renews active lease."""
        lease_exp = time.time() + self.lease_seconds
        with get_db_connection(self.db_path) as conn:
            conn.execute("""
                UPDATE stages
                SET lease_expires = ?
                WHERE job_id = ? AND stage = ? AND worker_id = ? AND status = 'LEASED';
            """, (lease_exp, job_id, stage, self.worker_id))

    def validate_task_envelope(self, task_env: Dict[str, Any]) -> Tuple[bool, str]:
        """A worker accepts a task only if:
        1. signature valid
        2. action equals its role's single permitted action
        3. input file hash equals input_hash
        4. deadline not passed
        5. nonce unseen
        """
        # 1. Signature valid
        if not verify_signature(self.broker_key, task_env):
            return False, "Broker task signature invalid"

        # 2. Action check
        if task_env.get('action') != self.permitted_action:
            return False, f"Action '{task_env.get('action')}' not permitted for role '{self.role}'"

        # 3. Deadline check
        if time.time() > task_env.get('deadline', 0):
            return False, "Task deadline already expired"

        # 4. Nonce unseen check
        nonce = task_env.get('nonce', '')
        if not self.ledger.record_seen_nonce(nonce):
            return False, f"Replayed task nonce detected: {nonce}"

        # 5. Input file hash check
        job_id = task_env['job_id']
        expected_hash = task_env.get('input_hash')

        if self.permitted_stage == 'lex':
            policy_path = Path(task_env['policy_path'])
            if not policy_path.exists():
                return False, f"Policy file not found: {policy_path}"
            actual_hash = hashlib.sha256(policy_path.read_bytes()).hexdigest()
        else:
            # Check preceding stage's artifact hash
            curr_idx = TRANSITION_TABLE.index(self.permitted_stage)
            prev_stage = TRANSITION_TABLE[curr_idx - 1]
            prev_artifact_name = STAGE_ARTIFACTS[prev_stage]
            prev_artifact_path = self.workspace_dir / job_id / "artifacts" / prev_artifact_name
            if not prev_artifact_path.exists():
                return False, f"Preceding artifact missing: {prev_artifact_path}"
            actual_hash = hashlib.sha256(prev_artifact_path.read_bytes()).hexdigest()

        if expected_hash and actual_hash != expected_hash:
            return False, f"Input hash mismatch: expected {expected_hash}, got {actual_hash}"

        return True, "Task envelope verified"

    def execute_stage(self, task_env: Dict[str, Any]) -> Dict[str, Any]:
        """Executes compiler stage and generates signed result envelope."""
        job_id = task_env['job_id']
        stage = task_env['stage']
        policy_path = Path(task_env['policy_path'])
        approved_repair = task_env.get('approved_repair')

        job_dir = self.workspace_dir / job_id
        stage_dir = job_dir / "stages" / stage
        artifacts_dir = job_dir / "artifacts"
        stage_dir.mkdir(parents=True, exist_ok=True)
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        # Heartbeat before invoking compiler
        self.heartbeat(job_id, stage)

        if self.delay > 0:
            time.sleep(self.delay)

        cmd = [
            str(self.compiler_bin),
            "--stage", self.permitted_action,
            "--policy", str(policy_path),
            "--out-dir", str(stage_dir)
        ]
        if approved_repair:
            cmd.extend(["--approve-repair", approved_repair])

        proc = subprocess.run(cmd, capture_output=True, text=True)
        self.heartbeat(job_id, stage)

        sr_path = stage_dir / "stage_result.json"
        if not sr_path.exists():
            return create_result_envelope(
                role_key=self.role_key,
                job_id=job_id,
                stage=stage,
                worker_id=self.worker_id,
                role=self.role,
                output_hash="",
                status="FAILED",
                artifact_name="",
                decision="BLOCK",
                extra={"error": f"stage_result.json missing. Returncode {proc.returncode}"}
            )

        sr = json.loads(sr_path.read_text(encoding='utf-8'))

        # Check for Human-In-The-Loop syntax repair
        if proc.returncode == 20 or sr.get("decision") == "NEEDS_HUMAN":
            return create_result_envelope(
                role_key=self.role_key,
                job_id=job_id,
                stage=stage,
                worker_id=self.worker_id,
                role=self.role,
                output_hash="",
                status="NEEDS_HUMAN",
                artifact_name="",
                decision="NEEDS_HUMAN",
                extra={"candidates": sr.get("candidates", [])}
            )

        if proc.returncode != 0 or not sr.get("ok", False):
            return create_result_envelope(
                role_key=self.role_key,
                job_id=job_id,
                stage=stage,
                worker_id=self.worker_id,
                role=self.role,
                output_hash="",
                status="FAILED",
                artifact_name="",
                decision=sr.get("decision", "BLOCK"),
                extra={"stderr": proc.stderr}
            )

        # Verify only permitted artifact was written
        artifact_path = stage_dir / self.permitted_artifact
        if not artifact_path.exists():
            return create_result_envelope(
                role_key=self.role_key,
                job_id=job_id,
                stage=stage,
                worker_id=self.worker_id,
                role=self.role,
                output_hash="",
                status="FAILED",
                artifact_name=self.permitted_artifact,
                decision="BLOCK",
                extra={"error": f"Expected artifact {self.permitted_artifact} missing"}
            )

        stage_files = set(os.listdir(stage_dir))
        allowed_files = {self.permitted_artifact, "stage_result.json"}
        unexpected_files = stage_files - allowed_files
        if unexpected_files:
            return create_result_envelope(
                role_key=self.role_key,
                job_id=job_id,
                stage=stage,
                worker_id=self.worker_id,
                role=self.role,
                output_hash="",
                status="FAILED",
                artifact_name=self.permitted_artifact,
                decision="BLOCK",
                extra={"error": f"Worker violated role permissions, wrote unexpected files: {unexpected_files}"}
            )

        artifact_bytes = artifact_path.read_bytes()
        output_hash = hashlib.sha256(artifact_bytes).hexdigest()

        # Copy artifact to canonical artifacts directory
        canonical_artifact_path = artifacts_dir / self.permitted_artifact
        shutil.copy2(artifact_path, canonical_artifact_path)

        extra = {}

        # Semantic Gate-1 approval signing
        if self.role == 'semantic':
            # Deterministically obtain validator_hash by running codegen in an isolated temp dir
            temp_cg_dir = Path(tempfile.mkdtemp(prefix="semantic_cg_"))
            try:
                cg_cmd = [
                    str(self.compiler_bin),
                    "--stage", "codegen",
                    "--policy", str(policy_path),
                    "--out-dir", str(temp_cg_dir)
                ]
                if approved_repair:
                    cg_cmd.extend(["--approve-repair", approved_repair])
                subprocess.run(cg_cmd, capture_output=True, text=True)
                v_path = temp_cg_dir / "validator.cpp"
                if v_path.exists():
                    v_hash = hashlib.sha256(v_path.read_bytes()).hexdigest()
                    gate1_token = sign_gate_approval(
                        key_bytes=self.role_key,
                        gate_name="Gate-1",
                        job_id=job_id,
                        validator_hash=v_hash,
                        decision="APPROVE"
                    )
                    (artifacts_dir / "gate1_approval.json").write_text(
                        json.dumps(gate1_token, indent=2), encoding='utf-8'
                    )
                    extra["gate1_approval"] = gate1_token
            finally:
                shutil.rmtree(temp_cg_dir, ignore_errors=True)

        # Auditor Gate-2 approval signing
        if self.role == 'auditor':
            # Target validator exists in artifacts
            v_canonical = artifacts_dir / "validator.cpp"
            if v_canonical.exists():
                v_hash = hashlib.sha256(v_canonical.read_bytes()).hexdigest()
                gate2_token = sign_gate_approval(
                    key_bytes=self.role_key,
                    gate_name="Gate-2",
                    job_id=job_id,
                    validator_hash=v_hash,
                    decision="APPROVE"
                )
                (artifacts_dir / "gate2_approval.json").write_text(
                    json.dumps(gate2_token, indent=2), encoding='utf-8'
                )
                extra["gate2_approval"] = gate2_token

        return create_result_envelope(
            role_key=self.role_key,
            job_id=job_id,
            stage=stage,
            worker_id=self.worker_id,
            role=self.role,
            output_hash=output_hash,
            status="DONE",
            artifact_name=self.permitted_artifact,
            decision=sr.get("decision", "PROCEED"),
            extra=extra
        )

    def submit_result(self, result_env: Dict[str, Any]) -> bool:
        """Atomically submits result envelope with idempotency and conflict checking."""
        job_id = result_env['job_id']
        stage = result_env['stage']
        res_status = result_env['status']
        res_out_hash = result_env['output_hash']

        with get_db_connection(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE;")
            curr = conn.execute("SELECT status, output_hash, worker_id FROM stages WHERE job_id = ? AND stage = ?;",
                                (job_id, stage)).fetchone()

            if not curr:
                conn.execute("ROLLBACK;")
                return False

            curr_status = curr['status']
            stored_hash = curr['output_hash']

            # Idempotency check:
            # If two workers finish the same (job, stage, input_hash) with the same output_hash, accept the first.
            # Different hashes -> ALERT and job FAILED.
            if curr_status == 'DONE':
                if stored_hash == res_out_hash:
                    # Duplicate identical result accepted cleanly
                    conn.execute("COMMIT;")
                    return True
                else:
                    # Conflicting hashes from multiple workers!
                    conn.execute("UPDATE stages SET status = 'FAILED' WHERE job_id = ? AND stage = ?;", (job_id, stage))
                    conn.execute("UPDATE jobs SET status = 'FAILED', updated_at = ? WHERE job_id = ?;", (time.time(), job_id))
                    conn.execute("COMMIT;")
                    self.ledger.log_event(job_id, stage, "ALERT", {
                        "alert": "Conflicting output hash from duplicate worker detected",
                        "first_hash": stored_hash,
                        "second_hash": res_out_hash,
                        "worker_id": self.worker_id
                    })
                    return False

            if res_status == 'NEEDS_HUMAN':
                conn.execute("UPDATE stages SET status = 'NEEDS_HUMAN' WHERE job_id = ? AND stage = ?;", (job_id, stage))
                conn.execute("UPDATE jobs SET status = 'NEEDS_HUMAN', updated_at = ? WHERE job_id = ?;", (time.time(), job_id))
                conn.execute("COMMIT;")
                self.ledger.log_event(job_id, stage, "NEEDS_HUMAN", result_env['extra'])
                return True

            if res_status == 'FAILED':
                conn.execute("UPDATE stages SET status = 'FAILED' WHERE job_id = ? AND stage = ?;", (job_id, stage))
                conn.execute("UPDATE jobs SET status = 'FAILED', updated_at = ? WHERE job_id = ?;", (time.time(), job_id))
                conn.execute("COMMIT;")
                self.ledger.log_event(job_id, stage, "STAGE_FAILED", result_env['extra'])
                return False

            # Update stage to DONE
            conn.execute("""
                UPDATE stages
                SET status = 'DONE', output_hash = ?
                WHERE job_id = ? AND stage = ?;
            """, (res_out_hash, job_id, stage))
            conn.execute("COMMIT;")

        self.ledger.log_event(job_id, stage, "STAGE_DONE", {
            "worker_id": self.worker_id,
            "output_hash": res_out_hash,
            "artifact": result_env['artifact_name']
        })
        return True

    def run_cycle(self) -> bool:
        """Executes one polling and work cycle. Returns True if task was processed."""
        task_env = self.lease_task()
        if not task_env:
            return False

        valid, reason = self.validate_task_envelope(task_env)
        if not valid:
            self.ledger.log_event(task_env['job_id'], task_env['stage'], "ALERT", {
                "alert": "Worker rejected task envelope",
                "worker_id": self.worker_id,
                "reason": reason
            })
            # Mark stage failed due to invalid task envelope
            with get_db_connection(self.db_path) as conn:
                conn.execute("BEGIN IMMEDIATE;")
                conn.execute("UPDATE stages SET status = 'FAILED' WHERE job_id = ? AND stage = ?;",
                             (task_env['job_id'], task_env['stage']))
                conn.execute("UPDATE jobs SET status = 'FAILED' WHERE job_id = ?;", (task_env['job_id'],))
                conn.execute("COMMIT;")
            return True

        result_env = self.execute_stage(task_env)
        self.submit_result(result_env)
        return True

    def run(self):
        self.running = True
        try:
            while self.running:
                worked = self.run_cycle()
                if not worked:
                    time.sleep(self.poll_interval)
        except KeyboardInterrupt:
            self.running = False


def main():
    parser = argparse.ArgumentParser(description="Generic Resilient Worker")
    parser.add_argument("--role", type=str, required=True, help="Worker role name (e.g. lexer, parser, codegen)")
    parser.add_argument("--id", type=str, required=True, help="Worker instance identifier (e.g. codegen-1)")
    parser.add_argument("--db", type=str, default="resilient.db", help="Path to SQLite ledger database")
    parser.add_argument("--workspace", type=str, default="resilient_workspace", help="Path to workspace directory")
    parser.add_argument("--keys-dir", type=str, default="keys", help="Path to keys directory")
    parser.add_argument("--compiler-bin", type=str, default="policy_compiler.exe", help="Path to compiler binary")
    parser.add_argument("--lease-seconds", type=float, default=5.0, help="Lease timeout duration in seconds")
    parser.add_argument("--poll-interval", type=float, default=0.5, help="Polling interval in seconds")
    parser.add_argument("--delay", type=float, default=0.0, help="Artificial delay during execution in seconds (for fault injection)")
    args = parser.parse_args()

    worker = Worker(
        role=args.role,
        worker_id=args.id,
        db_path=Path(args.db),
        workspace_dir=Path(args.workspace),
        keys_dir=Path(args.keys_dir),
        compiler_bin=Path(args.compiler_bin),
        lease_seconds=args.lease_seconds,
        poll_interval=args.poll_interval,
        delay=args.delay
    )
    print(f"[WORKER] Starting worker {args.id} (Role: {args.role}, PID {os.getpid()})...")
    worker.run()


if __name__ == '__main__':
    main()
