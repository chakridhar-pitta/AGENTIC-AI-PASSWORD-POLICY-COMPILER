import os
import time
import hashlib
from pathlib import Path
from typing import Optional, Tuple, Dict, Any

from .ledger import Ledger, get_db_connection
from .gates import IntakeGateManager
from .envelope import load_key


class Coordinator:
    """
    Agent 0 = Coordinator.
    Has NO approval power.
    Only submits jobs, checks intake gates, and reads status.
    """
    def __init__(self,
                 db_path: Path,
                 workspace_dir: Path,
                 keys_dir: Path,
                 compiler_bin: Optional[Path] = None,
                 instance_id: str = "coordinator-active"):
        self.db_path = Path(db_path)
        self.workspace_dir = Path(workspace_dir)
        self.keys_dir = Path(keys_dir)
        self.instance_id = instance_id

        if compiler_bin:
            self.compiler_bin = Path(compiler_bin)
        else:
            self.compiler_bin = Path("policy_compiler.exe" if os.name == 'nt' else "./policy_compiler")

        self.ledger = Ledger(self.db_path)
        self.coordinator_key = load_key('coordinator', self.keys_dir)
        self.gate_manager = IntakeGateManager(self.compiler_bin, self.keys_dir, self.ledger)

    def submit_job(self,
                   policy_path: Path,
                   gate_a_override: Optional[str] = None) -> Tuple[bool, str, str]:
        """
        Submits a policy into the resilient compiler pipeline.
        Runs intake gates.
        Enters queue only if consensus passes.
        Returns: (success, job_id, message)
        """
        policy_path = Path(policy_path)
        if not policy_path.exists():
            return False, "", f"Policy file not found: {policy_path}"

        policy_bytes = policy_path.read_bytes()
        policy_hash = hashlib.sha256(policy_bytes).hexdigest()
        job_id = f"job_{policy_hash[:12]}_{int(time.time()*1000)%100000}"

        # Initialize job workspace
        job_dir = self.workspace_dir / job_id
        artifacts_dir = job_dir / "artifacts"
        artifacts_dir.mkdir(parents=True, exist_ok=True)

        # Store canonical policy copy in artifacts
        canonical_policy_path = artifacts_dir / "policy.txt"
        canonical_policy_path.write_bytes(policy_bytes)

        # Create job entry in ledger
        self.ledger.create_job(job_id, str(canonical_policy_path), policy_hash)

        # Evaluate Intake Gates
        consensus_pass, votes, is_degraded = self.gate_manager.evaluate_policy(
            policy_path=canonical_policy_path,
            job_id=job_id,
            gate_a_override=gate_a_override
        )

        if is_degraded:
            with get_db_connection(self.db_path) as conn:
                conn.execute("UPDATE jobs SET degraded = 1 WHERE job_id = ?;", (job_id,))

        if not consensus_pass:
            self.ledger.set_job_status(job_id, "FAILED")
            self.ledger.log_event(job_id, "gates", "ALERT", {
                "alert": "Job rejected at intake gate consensus",
                "votes": {g: v['vote'] for g, v in votes.items()}
            })
            return False, job_id, "Policy blocked by intake gates. Job rejected."

        # Mark gates stage as DONE with policy_hash
        with get_db_connection(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE;")
            conn.execute("""
                UPDATE stages
                SET status = 'DONE', output_hash = ?
                WHERE job_id = ? AND stage = 'gates';
            """, (policy_hash, job_id))
            conn.execute("COMMIT;")

        # Transition to next stage (lex)
        self.ledger.move_to_next_stage(job_id, "gates", policy_hash)
        self.ledger.set_job_status(job_id, "RUNNING")

        return True, job_id, f"Job {job_id} accepted and queued for lexer."

    def get_status(self, job_id: str) -> Optional[Dict[str, Any]]:
        job = self.ledger.get_job(job_id)
        if not job:
            return None
        stages = self.ledger.get_stages(job_id)
        return {
            "job": job,
            "stages": stages
        }
