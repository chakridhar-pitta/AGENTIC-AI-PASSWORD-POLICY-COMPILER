import sys
import os
import json
import argparse
from pathlib import Path

from .ledger import Ledger, init_db
from .envelope import init_keys
from .coordinator import Coordinator
from .releaser import verify_release


def cmd_init(args):
    keys_dir = Path(args.keys_dir)
    db_path = Path(args.db)
    print(f"[*] Initializing resilient pipeline keys in: {keys_dir}")
    keys = init_keys(keys_dir)
    for role, path in keys.items():
        print(f"  - Key for role '{role}': {path}")

    print(f"[*] Initializing SQLite ledger in WAL mode: {db_path}")
    init_db(db_path)
    print("[✓] Pipeline environment initialized successfully.")


def cmd_submit(args):
    coord = Coordinator(
        db_path=Path(args.db),
        workspace_dir=Path(args.workspace),
        keys_dir=Path(args.keys_dir),
        compiler_bin=Path(args.compiler_bin) if args.compiler_bin else None
    )
    policy_path = Path(args.policy)
    print(f"[*] Submitting policy: {policy_path}...")
    success, job_id, msg = coord.submit_job(policy_path)
    if success:
        print(f"[✓] {msg}")
        print(f"Job ID: {job_id}")
    else:
        print(f"[✗] Submission FAILED: {msg}")
        if job_id:
            print(f"Job ID: {job_id} (Marked FAILED)")
        sys.exit(1)


def cmd_status(args):
    ledger = Ledger(Path(args.db))
    job = ledger.get_job(args.job)
    if not job:
        print(f"[✗] Job '{args.job}' not found.")
        sys.exit(1)

    print(f"==================================================")
    print(f"  JOB STATUS: {job['job_id']}")
    print(f"==================================================")
    print(f"Overall Status   : {job['status']}")
    print(f"Policy Path      : {job['policy_path']}")
    print(f"Policy Hash      : {job['policy_hash']}")
    print(f"Degraded Mode    : {'YES (Isolated Gate Active)' if job['degraded'] else 'NO'}")
    print(f"Approved Repair  : {job['approved_repair'] or 'None'}")
    print(f"Created At       : {job['created_at']}")
    print(f"--------------------------------------------------")
    print(f"STAGES:")
    stages = ledger.get_stages(args.job)
    for st in stages:
        w = st['worker_id'] or '-'
        att = st['attempts']
        in_h = (st['input_hash'][:8] + '...') if st['input_hash'] else '-'
        out_h = (st['output_hash'][:8] + '...') if st['output_hash'] else '-'
        print(f"  [{st['stage']:<10}] Status: {st['status']:<11} Worker: {w:<12} Att: {att:<2} In: {in_h:<12} Out: {out_h}")

    if job['status'] == 'NEEDS_HUMAN':
        print(f"\n[!] HUMAN APPROVAL REQUIRED:")
        # Look for candidates in events
        with ledger.get_db_connection(ledger.db_path) as conn:
            ev = conn.execute(
                "SELECT payload FROM events WHERE job_id = ? AND event_type = 'NEEDS_HUMAN' ORDER BY id DESC LIMIT 1;",
                (args.job,)
            ).fetchone()
            if ev:
                p = json.loads(ev['payload'])
                for c in p.get('candidates', []):
                    print(f"    Candidate [{c.get('id')}]: {c.get('candidateText')} ({c.get('rationale')})")
        print(f"\nTo authorize a candidate, run:")
        print(f"  cli.py approve {args.job} <A|B>")
    print(f"==================================================")


def cmd_approve(args):
    ledger = Ledger(Path(args.db))
    choice = args.choice.upper()
    if choice not in ('A', 'B'):
        print("[✗] Error: Choice must be 'A' or 'B'")
        sys.exit(1)

    job = ledger.get_job(args.job)
    if not job:
        print(f"[✗] Job '{args.job}' not found.")
        sys.exit(1)

    ledger.set_human_approval(args.job, choice)
    print(f"[✓] Human authorization recorded: Candidate [{choice}] approved for job '{args.job}'.")
    print(f"Stage 'parse' reset to READY. Worker will resume compilation.")


def cmd_isolate(args):
    ledger = Ledger(Path(args.db))
    gate = args.gate
    if gate not in ('Gate-A', 'Gate-B', 'Gate-P'):
        print(f"[!] Warning: Isolating non-standard gate '{gate}'. Expected Gate-A, Gate-B, or Gate-P.")

    ledger.isolate_gate(gate)
    print(f"[✓] Gate '{gate}' is now ISOLATED.")
    print("Safe Degraded Mode active: Future policy evaluations will ignore this gate and require unanimous agreement from remaining gates.")


def cmd_verify(args):
    release_dir = Path(args.release_dir)
    keys_dir = Path(args.keys_dir)
    ok, msg = verify_release(release_dir, keys_dir)
    if ok:
        print(msg)
        sys.exit(0)
    else:
        print(f"[✗] VERIFICATION FAILED: {msg}")
        sys.exit(1)


def main():
    parent_parser = argparse.ArgumentParser(add_help=False)
    parent_parser.add_argument("--db", type=str, default="resilient.db", help="Path to SQLite database")
    parent_parser.add_argument("--keys-dir", type=str, default="keys", help="Path to keys directory")
    parent_parser.add_argument("--workspace", type=str, default="resilient_workspace", help="Path to workspace directory")
    parent_parser.add_argument("--compiler-bin", type=str, default=None, help="Path to policy_compiler binary")

    parser = argparse.ArgumentParser(description="Resilient Zero-Trust Compiler CLI", parents=[parent_parser])

    subparsers = parser.add_subparsers(dest="command", required=True)

    # init
    p_init = subparsers.add_parser("init", parents=[parent_parser], help="Initialize cryptographic keys and SQLite ledger")

    # submit
    p_submit = subparsers.add_parser("submit", parents=[parent_parser], help="Submit policy through intake gates into pipeline")
    p_submit.add_argument("policy", type=str, help="Path to policy file")

    # status
    p_status = subparsers.add_parser("status", parents=[parent_parser], help="Query job and stage status")
    p_status.add_argument("job", type=str, help="Job identifier")

    # approve
    p_approve = subparsers.add_parser("approve", parents=[parent_parser], help="Authorize ambiguous syntax repair candidate")
    p_approve.add_argument("job", type=str, help="Job identifier")
    p_approve.add_argument("choice", type=str, help="Choice identifier (e.g. A or B)")

    # isolate
    p_isolate = subparsers.add_parser("isolate", parents=[parent_parser], help="Isolate a compromised intake gate into degraded mode")
    p_isolate.add_argument("gate", type=str, help="Gate identifier (e.g. Gate-A, Gate-B, Gate-P)")

    # verify
    p_verify = subparsers.add_parser("verify", parents=[parent_parser], help="Verify integrity and signatures of a release directory")
    p_verify.add_argument("release_dir", type=str, help="Path to release directory")

    args = parser.parse_args()

    dispatch = {
        "init": cmd_init,
        "submit": cmd_submit,
        "status": cmd_status,
        "approve": cmd_approve,
        "isolate": cmd_isolate,
        "verify": cmd_verify
    }
    dispatch[args.command](args)


if __name__ == '__main__':
    main()
