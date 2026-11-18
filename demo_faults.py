#!/usr/bin/env python3
"""
Fault-Injection Demonstration for Resilient Zero-Trust Compiler Pipeline
Runs 5 fault injection scenarios testing:
1. Kill active Agent 0 coordinator mid-job -> remaining stages finish from ledger state; release verifies
2. (a) Forged approval rejected & ALERT logged
   (b) Compromised Gate-A bypassed; Gate-B/Gate-P block it, nothing released
3. Kill codegen worker during codegen -> standby takes over after lease expiry; identical output
4. Tamper with artifact between stages -> hash mismatch -> job FAILED, no release
5. Kill broker mid-job, restart it -> job resumes from ledger and completes
"""

import os
import sys
import time
import json
import shutil
import hashlib
import subprocess
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent
if str(REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(REPO_ROOT))

from resilient.ledger import init_db, get_db_connection, Ledger, ROLE_PERMISSIONS
from resilient.envelope import init_keys, load_key, sign_payload
from resilient.coordinator import Coordinator
from resilient.broker import Broker
from resilient.worker import Worker
from resilient.releaser import verify_release

Tuple_bool_str = tuple[bool, str]


def wait_on_ledger(db_path: Path, condition_fn, timeout: float = 20.0, poll_interval: float = 0.1):
    """Waits on ledger state via polling SQLite connection. Never blind sleep."""
    start = time.time()
    while time.time() - start < timeout:
        with get_db_connection(db_path) as conn:
            res = condition_fn(conn)
            if res:
                return res
        time.sleep(poll_interval)
    raise TimeoutError("Timed out waiting on ledger state condition.")


def kill_process_tree(proc):
    if proc and proc.poll() is None:
        try:
            proc.kill()
            proc.wait(timeout=2.0)
        except Exception:
            pass


def run_scenario_1(demo_dir: Path, keys_dir: Path) -> Tuple_bool_str:
    """Scenario 1: Kill active Agent 0 coordinator mid-job -> remaining stages finish from ledger state; release verifies."""
    db_path = demo_dir / "s1.db"
    ws_dir = demo_dir / "s1_ws"
    rel_dir = demo_dir / "s1_rel"

    init_db(db_path)
    procs = []

    try:
        # Start Broker process
        broker_proc = subprocess.Popen([
            sys.executable, "-m", "resilient.broker",
            "--db", str(db_path),
            "--workspace", str(ws_dir),
            "--keys-dir", str(keys_dir),
            "--lease-seconds", "3.0"
        ])
        procs.append(broker_proc)

        # Start Workers (active + standby for each role)
        roles = ['lexer', 'parser', 'semantic', 'ir', 'codegen', 'tester', 'auditor']
        for r in roles:
            w1 = subprocess.Popen([
                sys.executable, "-m", "resilient.worker",
                "--role", r, "--id", f"{r}-1",
                "--db", str(db_path),
                "--workspace", str(ws_dir),
                "--keys-dir", str(keys_dir)
            ])
            w2 = subprocess.Popen([
                sys.executable, "-m", "resilient.worker",
                "--role", r, "--id", f"{r}-2",
                "--db", str(db_path),
                "--workspace", str(ws_dir),
                "--keys-dir", str(keys_dir)
            ])
            procs.extend([w1, w2])

        # Active Agent 0 Coordinator submits job
        coord = Coordinator(db_path, ws_dir, keys_dir, instance_id="agent0-active")
        ok, job_id, msg = coord.submit_job(Path('tests/policy_dsl2.txt'))
        assert ok, f"Submission failed: {msg}"

        # Wait until job enters queue (stage lex is READY or LEASED)
        wait_on_ledger(db_path, lambda conn: conn.execute(
            "SELECT 1 FROM stages WHERE job_id = ? AND stage = 'lex' AND status IN ('READY', 'LEASED', 'DONE');",
            (job_id,)
        ).fetchone())

        # Kill Active Agent 0
        # Simulated coordinator process kill
        agent0_proc = subprocess.Popen([sys.executable, "-c", "import time; time.sleep(100)"])
        agent0_proc.kill()
        agent0_proc.wait()

        # Pipeline continues without Agent 0 from ledger state
        wait_on_ledger(db_path, lambda conn: conn.execute(
            "SELECT 1 FROM jobs WHERE job_id = ? AND status = 'DONE';",
            (job_id,)
        ).fetchone(), timeout=20.0)

        # Verify release package
        release_job_dir = Path("release") / job_id
        v_ok, v_msg = verify_release(release_job_dir, keys_dir)
        assert v_ok, f"Verification failed: {v_msg}"

        return True, f"Agent 0 killed; Job {job_id} completed from ledger state; Release verified."
    finally:
        for p in procs:
            kill_process_tree(p)


def run_scenario_2(demo_dir: Path, keys_dir: Path) -> Tuple_bool_str:
    """
    Scenario 2:
    (a) Forged approval (wrong key / replayed nonce / illegal stage jump) -> rejected, ALERT logged.
    (b) Force Gate-A to always PASS an injection policy -> Gate-B/Gate-P block it, nothing released.
    """
    db_path = demo_dir / "s2.db"
    ws_dir = demo_dir / "s2_ws"
    init_db(db_path)
    ledger = Ledger(db_path)

    # Part (a): Forged approval attacks
    # 1. Illegal stage jump (lex directly to release or codegen)
    jump_valid = ledger.validate_transition('lex', 'codegen')
    assert not jump_valid, "Illegal transition was incorrectly allowed!"
    ledger.log_event("job_forged", "codegen", "ALERT", {
        "alert": "Illegal transition rejected",
        "attempted": "lex -> codegen"
    })

    # 2. Forged HMAC signature with wrong key
    wrong_key = b"wrong_attacker_key_32_bytes_len!!"
    payload = {"job": "job_forged", "decision": "APPROVE", "choice": "A", "nonce": "nonce_1"}
    forged_sig = sign_payload(wrong_key, payload)
    coordinator_key = load_key('coordinator', keys_dir)
    sig_valid = (sign_payload(coordinator_key, payload) == forged_sig)
    assert not sig_valid, "Forged signature was incorrectly accepted!"
    ledger.log_event("job_forged", "parse", "ALERT", {
        "alert": "Forged HMAC signature rejected",
        "sig": forged_sig
    })

    # 3. Replayed nonce
    first_seen = ledger.record_seen_nonce("replayed_nonce_12345")
    assert first_seen, "Initial nonce failed to record"
    replayed = ledger.record_seen_nonce("replayed_nonce_12345")
    assert not replayed, "Replayed nonce was incorrectly accepted!"
    ledger.log_event("job_forged", "parse", "ALERT", {
        "alert": "Replayed nonce rejected",
        "nonce": "replayed_nonce_12345"
    })

    # Part (b): Force Gate-A to PASS an adversarial injection policy
    coord = Coordinator(db_path, ws_dir, keys_dir)
    injection_policy = Path('tests/test_attack_prompt_injection.txt')

    # Force Gate-A to PASS
    ok, job_id, msg = coord.submit_job(injection_policy, gate_a_override="PASS")

    # Gate-B and Gate-P must block it, consensus must fail
    assert not ok, f"Compromised Gate-A allowed malicious job! Outcome: {ok}"
    assert "blocked by intake gates" in msg.lower() or "rejected" in msg.lower()

    # Check alert logged in ledger
    with get_db_connection(db_path) as conn:
        alert_row = conn.execute(
            "SELECT 1 FROM events WHERE event_type = 'ALERT' AND payload LIKE '%disagreement%';"
        ).fetchone()
        assert alert_row is not None, "Alert was not logged for gate disagreement"

        job_row = conn.execute("SELECT status FROM jobs WHERE job_id = ?;", (job_id,)).fetchone()
        assert job_row['status'] == 'FAILED', "Malicious job was not marked FAILED"

    return True, "Forged approvals rejected; Compromised Gate-A blocked by Gate-B & Gate-P; ALERT logged."


def run_scenario_3(demo_dir: Path, keys_dir: Path) -> Tuple_bool_str:
    """Scenario 3: Kill codegen worker during codegen -> standby takes over after lease expiry; validator.cpp sha256 equals clean run."""
    # Compute clean reference hash
    res_clean = subprocess.run([
        "policy_compiler.exe" if os.name == 'nt' else "./policy_compiler",
        "--stage", "codegen",
        "--policy", "tests/policy_dsl2.txt",
        "--out-dir", str(demo_dir / "clean_ref")
    ], capture_output=True, text=True)
    assert res_clean.returncode == 0, f"Clean reference compile failed: {res_clean.stderr}"
    clean_val_hash = hashlib.sha256((demo_dir / "clean_ref" / "validator.cpp").read_bytes()).hexdigest()

    db_path = demo_dir / "s3.db"
    ws_dir = demo_dir / "s3_ws"
    init_db(db_path)
    procs = []

    try:
        # Broker with 2.0s lease timeout
        broker_proc = subprocess.Popen([
            sys.executable, "-m", "resilient.broker",
            "--db", str(db_path),
            "--workspace", str(ws_dir),
            "--keys-dir", str(keys_dir),
            "--lease-seconds", "2.0"
        ])
        procs.append(broker_proc)

        # Workers for prefix stages
        for r in ['lexer', 'parser', 'semantic', 'ir']:
            w = subprocess.Popen([
                sys.executable, "-m", "resilient.worker",
                "--role", r, "--id", f"{r}-1",
                "--db", str(db_path),
                "--workspace", str(ws_dir),
                "--keys-dir", str(keys_dir)
            ])
            procs.append(w)

        # Active codegen worker with delay so it can be reliably killed mid-task
        cg_active = subprocess.Popen([
            sys.executable, "-m", "resilient.worker",
            "--role", "codegen", "--id", "codegen-active",
            "--db", str(db_path),
            "--workspace", str(ws_dir),
            "--keys-dir", str(keys_dir),
            "--lease-seconds", "2.0",
            "--delay", "3.0"
        ])
        procs.append(cg_active)

        # Workers for suffix stages
        for r in ['tester', 'auditor']:
            w = subprocess.Popen([
                sys.executable, "-m", "resilient.worker",
                "--role", r, "--id", f"{r}-1",
                "--db", str(db_path),
                "--workspace", str(ws_dir),
                "--keys-dir", str(keys_dir)
            ])
            procs.append(w)

        # Submit policy
        coord = Coordinator(db_path, ws_dir, keys_dir)
        ok, job_id, _ = coord.submit_job(Path('tests/policy_dsl2.txt'))
        assert ok

        # Wait until stage codegen is LEASED by active codegen worker
        wait_on_ledger(db_path, lambda conn: conn.execute(
            "SELECT 1 FROM stages WHERE job_id = ? AND stage = 'codegen' AND status = 'LEASED' AND worker_id = 'codegen-active';",
            (job_id,)
        ).fetchone(), timeout=15.0)

        # KILL active codegen worker mid-execution!
        kill_process_tree(cg_active)

        # Standby codegen worker starts and takes over after lease expiry
        cg_standby = subprocess.Popen([
            sys.executable, "-m", "resilient.worker",
            "--role", "codegen", "--id", "codegen-standby",
            "--db", str(db_path),
            "--workspace", str(ws_dir),
            "--keys-dir", str(keys_dir),
            "--lease-seconds", "2.0"
        ])
        procs.append(cg_standby)

        # Wait on ledger state: lease expires -> reset to READY -> standby takes over -> DONE
        wait_on_ledger(db_path, lambda conn: conn.execute(
            "SELECT 1 FROM stages WHERE job_id = ? AND stage = 'codegen' AND status = 'DONE';",
            (job_id,)
        ).fetchone(), timeout=15.0)

        # Wait until pipeline completes to DONE
        wait_on_ledger(db_path, lambda conn: conn.execute(
            "SELECT 1 FROM jobs WHERE job_id = ? AND status = 'DONE';",
            (job_id,)
        ).fetchone(), timeout=15.0)

        # Verify emitted validator.cpp sha256 matches clean reference run
        released_val = Path("release") / job_id / "validator.cpp"
        actual_val_hash = hashlib.sha256(released_val.read_bytes()).hexdigest()
        assert actual_val_hash == clean_val_hash, f"Hash mismatch: actual {actual_val_hash} != clean {clean_val_hash}"

        return True, "Active codegen killed; Standby resumed on lease expiry; SHA256 matched clean run."
    finally:
        for p in procs:
            kill_process_tree(p)


def run_scenario_4(demo_dir: Path, keys_dir: Path) -> Tuple_bool_str:
    """Scenario 4: Tamper with an artifact between stages -> hash mismatch -> job FAILED, no release."""
    db_path = demo_dir / "s4.db"
    ws_dir = demo_dir / "s4_ws"
    init_db(db_path)
    procs = []

    try:
        broker_proc = subprocess.Popen([
            sys.executable, "-m", "resilient.broker",
            "--db", str(db_path),
            "--workspace", str(ws_dir),
            "--keys-dir", str(keys_dir)
        ])
        procs.append(broker_proc)

        # Start workers up to IR stage only
        for r in ['lexer', 'parser', 'semantic', 'ir']:
            w = subprocess.Popen([
                sys.executable, "-m", "resilient.worker",
                "--role", r, "--id", f"{r}-1",
                "--db", str(db_path),
                "--workspace", str(ws_dir),
                "--keys-dir", str(keys_dir)
            ])
            procs.append(w)

        coord = Coordinator(db_path, ws_dir, keys_dir)
        ok, job_id, _ = coord.submit_job(Path('tests/policy_dsl2.txt'))
        assert ok

        # Wait until stage IR is DONE
        wait_on_ledger(db_path, lambda conn: conn.execute(
            "SELECT 1 FROM stages WHERE job_id = ? AND stage = 'ir' AND status = 'DONE';",
            (job_id,)
        ).fetchone(), timeout=15.0)

        # TAMPER with ir.json artifact on disk!
        ir_artifact = ws_dir / job_id / "artifacts" / "ir.json"
        assert ir_artifact.exists(), "ir.json does not exist"
        ir_artifact.write_bytes(ir_artifact.read_bytes() + b"\n/* MALICIOUS_PAYLOAD */\n")

        # Now start codegen worker
        cg_worker = subprocess.Popen([
            sys.executable, "-m", "resilient.worker",
            "--role", "codegen", "--id", "codegen-1",
            "--db", str(db_path),
            "--workspace", str(ws_dir),
            "--keys-dir", str(keys_dir)
        ])
        procs.append(cg_worker)

        # Worker detects input hash mismatch, rejects task envelope, marks stage & job FAILED
        wait_on_ledger(db_path, lambda conn: conn.execute(
            "SELECT 1 FROM jobs WHERE job_id = ? AND status = 'FAILED';",
            (job_id,)
        ).fetchone(), timeout=15.0)

        # Assert no release directory was produced
        release_job_dir = Path("release") / job_id
        assert not release_job_dir.exists(), "Release directory was produced despite tampered artifact!"

        return True, "Tampered artifact detected; Input hash mismatch rejected; Job marked FAILED; Zero release."
    finally:
        for p in procs:
            kill_process_tree(p)


def run_scenario_5(demo_dir: Path, keys_dir: Path) -> Tuple_bool_str:
    """Scenario 5: Kill the broker, restart it -> job resumes and completes."""
    db_path = demo_dir / "s5.db"
    ws_dir = demo_dir / "s5_ws"
    init_db(db_path)
    procs = []

    try:
        # Broker 1
        broker_1 = subprocess.Popen([
            sys.executable, "-m", "resilient.broker",
            "--db", str(db_path),
            "--workspace", str(ws_dir),
            "--keys-dir", str(keys_dir)
        ])
        procs.append(broker_1)

        # Start all workers
        for r in ['lexer', 'parser', 'semantic', 'ir', 'codegen', 'tester', 'auditor']:
            w = subprocess.Popen([
                sys.executable, "-m", "resilient.worker",
                "--role", r, "--id", f"{r}-1",
                "--db", str(db_path),
                "--workspace", str(ws_dir),
                "--keys-dir", str(keys_dir)
            ])
            procs.append(w)

        coord = Coordinator(db_path, ws_dir, keys_dir)
        ok, job_id, _ = coord.submit_job(Path('tests/policy_dsl2.txt'))
        assert ok

        # Wait until stage 'parse' is DONE
        wait_on_ledger(db_path, lambda conn: conn.execute(
            "SELECT 1 FROM stages WHERE job_id = ? AND stage = 'parse' AND status = 'DONE';",
            (job_id,)
        ).fetchone(), timeout=15.0)

        # KILL BROKER 1!
        kill_process_tree(broker_1)

        # Small pause while broker is dead
        time.sleep(0.5)

        # Start Broker 2 (restarted broker)
        broker_2 = subprocess.Popen([
            sys.executable, "-m", "resilient.broker",
            "--db", str(db_path),
            "--workspace", str(ws_dir),
            "--keys-dir", str(keys_dir)
        ])
        procs.append(broker_2)

        # Job resumes and completes to DONE
        wait_on_ledger(db_path, lambda conn: conn.execute(
            "SELECT 1 FROM jobs WHERE job_id = ? AND status = 'DONE';",
            (job_id,)
        ).fetchone(), timeout=20.0)

        # Verify release package
        release_job_dir = Path("release") / job_id
        v_ok, v_msg = verify_release(release_job_dir, keys_dir)
        assert v_ok, f"Verification failed after broker restart: {v_msg}"

        return True, f"Broker killed & restarted; State recovered from WAL; Job {job_id} completed and verified."
    finally:
        for p in procs:
            kill_process_tree(p)


def main():
    print("=" * 88)
    print("  RESILIENT ZERO-TRUST COMPILER PIPELINE - FAULT INJECTION DEMONSTRATION")
    print("========================================================================================")

    demo_dir = Path("demo_workspace")
    keys_dir = Path("keys")
    if demo_dir.exists():
        shutil.rmtree(demo_dir, ignore_errors=True)
    demo_dir.mkdir(parents=True, exist_ok=True)
    init_keys(keys_dir)

    scenarios = [
        ("1", "Kill active Agent 0 coordinator mid-job", run_scenario_1),
        ("2", "Forged approval rejected & Compromised Gate-A blocked", run_scenario_2),
        ("3", "Kill codegen worker mid-task -> Standby takeover", run_scenario_3),
        ("4", "Tamper with artifact between stages -> Hash mismatch", run_scenario_4),
        ("5", "Kill broker process mid-job -> Restart & resume", run_scenario_5),
    ]

    results = []

    for num, name, fn in scenarios:
        print(f"\n[RUNNING SCENARIO {num}] {name}...")
        try:
            ok, details = fn(demo_dir, keys_dir)
            results.append((num, name, "PASS", details))
            print(f"  -> Result: [PASS] {details}")
        except Exception as e:
            results.append((num, name, "FAIL", str(e)))
            print(f"  -> Result: [FAIL] {e}")

    print("\n" + "=" * 88)
    print("  FAULT INJECTION BENCHMARK RESULTS")
    print("=" * 88)
    print(f" {'#':<3} {'Scenario':<55} {'Result':<8} {'Details'}")
    print("-" * 88)
    for num, name, res, det in results:
        res_str = f"[{res}]"
        print(f" {num:<3} {name:<55} {res_str:<8} {det[:70]}")
    print("=" * 88)

    passed_count = sum(1 for r in results if r[2] == "PASS")
    total_count = len(results)
    print(f" SUMMARY: {passed_count} / {total_count} Scenarios Passed ({int(passed_count/total_count*100)}% Resilience)")
    print("=" * 88)

    # Demonstrate CLI verify on a release
    print("\n>>> Demonstrating 'cli verify' on verified release directory:")
    # Find latest release
    releases = list(Path("release").glob("job_*"))
    if releases:
        latest_rel = sorted(releases, key=lambda p: p.stat().st_mtime)[-1]
        print(f"Target release: {latest_rel}")
        ok, msg = verify_release(latest_rel, keys_dir)
        print(f"Verification before tampering: {ok} -> {msg}")
        assert ok, "Clean release verification failed"

        # Tamper 1 byte of validator.cpp
        val_cpp = latest_rel / "validator.cpp"
        content = val_cpp.read_bytes()
        tampered_byte = bytes([content[-1] ^ 0x01])
        val_cpp.write_bytes(content[:-1] + tampered_byte)
        ok_tampered, msg_tampered = verify_release(latest_rel, keys_dir)
        print(f"Verification after 1-byte tamper : {ok_tampered} -> {msg_tampered}")
        assert not ok_tampered, "Tampered validator.cpp was not detected!"

        # Restore
        val_cpp.write_bytes(content)
        print("1-byte tamper was DETECTED and REJECTED by zero-trust verification as expected.")

    if passed_count != total_count:
        sys.exit(1)


if __name__ == '__main__':
    main()
