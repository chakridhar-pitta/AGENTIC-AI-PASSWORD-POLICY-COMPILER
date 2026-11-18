import os
import json
import time
import shutil
import hashlib
from pathlib import Path
from typing import Tuple, Dict, Any, Optional

from .ledger import Ledger, get_db_connection
from .envelope import load_key, verify_signature, sign_payload, canonical_json


class Releaser:
    def __init__(self,
                 db_path: Path,
                 workspace_dir: Path,
                 keys_dir: Path,
                 release_base_dir: Path = Path("release")):
        self.db_path = Path(db_path)
        self.workspace_dir = Path(workspace_dir)
        self.keys_dir = Path(keys_dir)
        self.release_base_dir = Path(release_base_dir)

        self.ledger = Ledger(self.db_path)
        self.releaser_key = load_key('releaser', self.keys_dir)
        self.semantic_key = load_key('semantic', self.keys_dir)
        self.auditor_key = load_key('auditor', self.keys_dir)

    def release_job(self, job_id: str) -> Tuple[bool, Optional[Path], str]:
        """
        Releaser is the only holder of the release key.
        Signs only if:
        1. Ledger chain verifies
        2. Artifact hashes chain policy->tokens->ast->constraints->ir->validator->test->audit
        3. The semantic Gate-1 approval and auditor Gate-2 approval (distinct keys) both reference the same validator hash
        4. All tests passed.
        """
        job = self.ledger.get_job(job_id)
        if not job:
            return False, None, f"Job {job_id} not found"

        # 1. Verify ledger event chain
        chain_ok, chain_msg = self.ledger.verify_event_chain()
        if not chain_ok:
            self.ledger.log_event(job_id, "release", "ALERT", {
                "alert": "Release aborted: Tamper-evident ledger chain verification failed",
                "reason": chain_msg
            })
            return False, None, f"Ledger chain verification failed: {chain_msg}"

        # 2. Verify artifact hash chain
        artifacts_dir = self.workspace_dir / job_id / "artifacts"
        if not artifacts_dir.exists():
            return False, None, f"Artifacts directory missing: {artifacts_dir}"

        required_artifacts = {
            'tokens': 'tokens.json',
            'ast': 'ast.json',
            'constraints': 'constraints.json',
            'ir': 'ir.json',
            'validator': 'validator.cpp',
            'test_report': 'test_report.json',
            'audit_report': 'audit_report.json'
        }

        # Check all artifact files physically exist and compute actual hashes
        computed_hashes = {'policy': job['policy_hash']}
        for key, fname in required_artifacts.items():
            fpath = artifacts_dir / fname
            if not fpath.exists():
                return False, None, f"Required artifact {fname} missing from artifacts directory"
            computed_hashes[key] = hashlib.sha256(fpath.read_bytes()).hexdigest()

        # Check stages table matches computed hashes and chains sequentially
        stages_map = {s['stage']: s for s in self.ledger.get_stages(job_id)}
        expected_chain = [
            ('lex', 'policy', 'tokens'),
            ('parse', 'tokens', 'ast'),
            ('semantic', 'ast', 'constraints'),
            ('ir', 'constraints', 'ir'),
            ('codegen', 'ir', 'validator'),
            ('test', 'validator', 'test_report'),
            ('audit', 'test_report', 'audit_report')
        ]

        for st_name, in_key, out_key in expected_chain:
            st = stages_map.get(st_name)
            if not st:
                return False, None, f"Stage {st_name} missing from ledger"
            if st['status'] != 'DONE':
                return False, None, f"Stage {st_name} is not DONE (status: {st['status']})"
            if st['input_hash'] != computed_hashes[in_key]:
                return False, None, f"Stage {st_name} input_hash mismatch: recorded {st['input_hash']} != actual {computed_hashes[in_key]}"
            if st['output_hash'] != computed_hashes[out_key]:
                return False, None, f"Stage {st_name} output_hash mismatch: recorded {st['output_hash']} != actual {computed_hashes[out_key]}"

        # 3. Verify Gate-1 and Gate-2 approvals
        gate1_file = artifacts_dir / "gate1_approval.json"
        gate2_file = artifacts_dir / "gate2_approval.json"
        if not gate1_file.exists():
            return False, None, "Semantic Gate-1 approval token missing"
        if not gate2_file.exists():
            return False, None, "Auditor Gate-2 approval token missing"

        gate1_token = json.loads(gate1_file.read_text(encoding='utf-8'))
        gate2_token = json.loads(gate2_file.read_text(encoding='utf-8'))

        if not verify_signature(self.semantic_key, gate1_token):
            return False, None, "Gate-1 approval signature invalid (wrong semantic key)"
        if not verify_signature(self.auditor_key, gate2_token):
            return False, None, "Gate-2 approval signature invalid (wrong auditor key)"

        val_hash = computed_hashes['validator']
        if gate1_token.get('validator_hash') != val_hash:
            return False, None, f"Gate-1 approval validator hash mismatch: {gate1_token.get('validator_hash')} != {val_hash}"
        if gate2_token.get('validator_hash') != val_hash:
            return False, None, f"Gate-2 approval validator hash mismatch: {gate2_token.get('validator_hash')} != {val_hash}"
        if gate1_token.get('decision') != 'APPROVE' or gate2_token.get('decision') != 'APPROVE':
            return False, None, "Gate-1 or Gate-2 approval decision is not APPROVE"

        # 4. Verify all tests passed
        test_rep = json.loads((artifacts_dir / "test_report.json").read_text(encoding='utf-8'))
        if not test_rep.get('all_passed', False):
            return False, None, "Runtime conformance tests did not pass"

        # Collect gate votes from ledger events
        with get_db_connection(self.db_path) as conn:
            vote_events = conn.execute(
                "SELECT payload FROM events WHERE job_id = ? AND event_type = 'GATE_VOTE' ORDER BY id ASC;",
                (job_id,)
            ).fetchall()

        gate_votes = {}
        for row in vote_events:
            p = json.loads(row['payload'])
            gate_votes[p['gate']] = p['vote']

        # Construct release package
        job_release_dir = self.release_base_dir / job_id
        job_release_dir.mkdir(parents=True, exist_ok=True)

        shutil.copy2(artifacts_dir / "validator.cpp", job_release_dir / "validator.cpp")
        shutil.copy2(artifacts_dir / "audit_report.json", job_release_dir / "audit_report.json")

        manifest = {
            "job_id": job_id,
            "policy_hash": job['policy_hash'],
            "artifact_hashes": computed_hashes,
            "gate_votes": gate_votes,
            "degraded": bool(job['degraded']),
            "gate1_approval": gate1_token,
            "gate2_approval": gate2_token,
            "tests_passed": True,
            "released_at": time.time()
        }

        manifest_str = canonical_json(manifest)
        manifest_path = job_release_dir / "manifest.json"
        manifest_path.write_text(json.dumps(manifest, indent=2), encoding='utf-8')

        # Sign canonical manifest
        sig = sign_payload(self.releaser_key, manifest)
        (job_release_dir / "manifest.sig").write_text(sig, encoding='utf-8')

        # Update ledger
        with get_db_connection(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE;")
            conn.execute("""
                INSERT INTO stages (job_id, stage, status, input_hash, output_hash, worker_id, lease_expires, attempts)
                VALUES (?, 'release', 'DONE', ?, ?, 'releaser', 0.0, 1)
                ON CONFLICT(job_id, stage) DO UPDATE SET status='DONE', output_hash=excluded.output_hash;
            """, (job_id, computed_hashes['audit_report'], sig))
            conn.execute("UPDATE jobs SET status = 'DONE', updated_at = ? WHERE job_id = ?;", (time.time(), job_id))
            conn.execute("COMMIT;")

        self.ledger.log_event(job_id, "release", "RELEASE_SIGNED", {
            "release_dir": str(job_release_dir),
            "manifest_sig": sig,
            "validator_hash": val_hash
        })

        return True, job_release_dir, "Release signed successfully"


def verify_release(release_dir: Path, keys_dir: Path) -> Tuple[bool, str]:
    """
    Independent verification of a release package:
    Recomputes hashes and signature, checks Gate-1 & Gate-2 approvals.
    """
    release_dir = Path(release_dir)
    keys_dir = Path(keys_dir)

    manifest_path = release_dir / "manifest.json"
    sig_path = release_dir / "manifest.sig"
    val_path = release_dir / "validator.cpp"
    audit_path = release_dir / "audit_report.json"

    if not manifest_path.exists():
        return False, "manifest.json missing in release directory"
    if not sig_path.exists():
        return False, "manifest.sig missing in release directory"
    if not val_path.exists():
        return False, "validator.cpp missing in release directory"
    if not audit_path.exists():
        return False, "audit_report.json missing in release directory"

    manifest = json.loads(manifest_path.read_text(encoding='utf-8'))
    expected_sig = sig_path.read_text(encoding='utf-8').strip()

    releaser_key = load_key('releaser', keys_dir)
    semantic_key = load_key('semantic', keys_dir)
    auditor_key = load_key('auditor', keys_dir)

    # 1. Verify manifest signature
    computed_sig = sign_payload(releaser_key, manifest)
    if not hashlib.sha256(expected_sig.encode()).digest() == hashlib.sha256(computed_sig.encode()).digest():
        return False, f"Manifest release signature verification FAILED. Signature mismatch."

    # 2. Recompute validator.cpp sha256
    val_bytes = val_path.read_bytes()
    actual_val_hash = hashlib.sha256(val_bytes).hexdigest()
    recorded_val_hash = manifest.get("artifact_hashes", {}).get("validator")
    if actual_val_hash != recorded_val_hash:
        return False, f"validator.cpp integrity verification FAILED. Hash mismatch: actual {actual_val_hash} != manifest {recorded_val_hash}"

    # 3. Recompute audit_report.json sha256
    actual_audit_hash = hashlib.sha256(audit_path.read_bytes()).hexdigest()
    recorded_audit_hash = manifest.get("artifact_hashes", {}).get("audit_report")
    if actual_audit_hash != recorded_audit_hash:
        return False, f"audit_report.json integrity verification FAILED. Hash mismatch: actual {actual_audit_hash} != manifest {recorded_audit_hash}"

    # 4. Verify Gate-1 and Gate-2 approval tokens
    gate1 = manifest.get("gate1_approval")
    gate2 = manifest.get("gate2_approval")
    if not gate1 or not gate2:
        return False, "Gate approvals missing in manifest"

    if not verify_signature(semantic_key, gate1):
        return False, "Gate-1 approval signature verification FAILED"
    if not verify_signature(auditor_key, gate2):
        return False, "Gate-2 approval signature verification FAILED"

    if gate1.get("validator_hash") != actual_val_hash:
        return False, f"Gate-1 approval validator hash mismatch: {gate1.get('validator_hash')} != {actual_val_hash}"
    if gate2.get("validator_hash") != actual_val_hash:
        return False, f"Gate-2 approval validator hash mismatch: {gate2.get('validator_hash')} != {actual_val_hash}"

    # 5. Check tests_passed flag
    if not manifest.get("tests_passed", False):
        return False, "Manifest tests_passed flag is False"

    return True, "[VERIFIED] Release integrity and zero-trust provenance valid."
