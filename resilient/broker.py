import sys
import os
import json
import time
import argparse
from pathlib import Path
from typing import Optional, Dict, Any, List

from .ledger import (
    Ledger,
    TRANSITION_TABLE,
    STAGE_ARTIFACTS,
    ROLE_PERMISSIONS,
    get_db_connection
)
from .envelope import (
    load_key,
    verify_signature,
    create_task_envelope,
    ALL_ROLES
)
from .releaser import Releaser


class Broker:
    def __init__(self,
                 db_path: Path,
                 workspace_dir: Path,
                 keys_dir: Path,
                 lease_seconds: float = 5.0,
                 poll_interval: float = 0.2,
                 release_base_dir: Path = Path("release")):
        self.db_path = Path(db_path)
        self.workspace_dir = Path(workspace_dir)
        self.keys_dir = Path(keys_dir)
        self.lease_seconds = lease_seconds
        self.poll_interval = poll_interval
        self.release_base_dir = Path(release_base_dir)
        self.running = False

        self.ledger = Ledger(self.db_path)
        self.broker_key = load_key('broker', self.keys_dir)

    def recover_state(self):
        """Recovers in-flight state upon startup or restart."""
        now = time.time()
        with get_db_connection(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE;")
            # Any leased stage whose lease has expired returns to READY
            expired_rows = conn.execute(
                "SELECT job_id, stage, worker_id FROM stages WHERE status = 'LEASED' AND lease_expires < ?;",
                (now,)
            ).fetchall()
            for r in expired_rows:
                conn.execute(
                    "UPDATE stages SET status = 'READY', worker_id = NULL WHERE job_id = ? AND stage = ?;",
                    (r['job_id'], r['stage'])
                )
            conn.execute("COMMIT;")

        for r in expired_rows:
            self.ledger.log_event(r['job_id'], r['stage'], "LEASE_EXPIRED_RESTART", {
                "worker_id": r['worker_id'],
                "action": "reclaimed_on_broker_restart"
            })

    def check_expired_leases(self):
        """Scans for expired leases and resets them to READY so standby worker can take over."""
        now = time.time()
        with get_db_connection(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE;")
            expired_rows = conn.execute(
                "SELECT job_id, stage, worker_id, attempts FROM stages WHERE status = 'LEASED' AND lease_expires < ?;",
                (now,)
            ).fetchall()
            for r in expired_rows:
                conn.execute(
                    "UPDATE stages SET status = 'READY', worker_id = NULL WHERE job_id = ? AND stage = ?;",
                    (r['job_id'], r['stage'])
                )
            conn.execute("COMMIT;")

        for r in expired_rows:
            self.ledger.log_event(r['job_id'], r['stage'], "LEASE_EXPIRED", {
                "expired_worker": r['worker_id'],
                "attempts": r['attempts']
            })

    def check_stage_advancement(self):
        """Advances jobs whose current stage is DONE to the next stage in TRANSITION_TABLE."""
        with get_db_connection(self.db_path) as conn:
            active_jobs = conn.execute(
                "SELECT job_id, status FROM jobs WHERE status IN ('RUNNING', 'PENDING');"
            ).fetchall()

        for j in active_jobs:
            job_id = j['job_id']
            stages = self.ledger.get_stages(job_id)
            if not stages:
                continue

            # Find the latest stage in progress or completed
            for stage_info in stages:
                st_name = stage_info['stage']
                st_status = stage_info['status']
                if st_status == 'DONE':
                    curr_idx = TRANSITION_TABLE.index(st_name)
                    if curr_idx + 1 < len(TRANSITION_TABLE):
                        next_stage = TRANSITION_TABLE[curr_idx + 1]
                        if next_stage == 'release':
                            existing_release = self.ledger.get_stage(job_id, 'release')
                            if not existing_release or existing_release['status'] != 'DONE':
                                releaser = Releaser(self.db_path, self.workspace_dir, self.keys_dir, release_base_dir=self.release_base_dir)
                                ok, rel_dir, msg = releaser.release_job(job_id)
                                if ok:
                                    self.ledger.set_job_status(job_id, 'DONE')
                        else:
                            # Check if next stage already exists
                            existing_next = self.ledger.get_stage(job_id, next_stage)
                            if not existing_next:
                                out_hash = stage_info['output_hash']
                                self.ledger.move_to_next_stage(job_id, st_name, out_hash)
                    else:
                        # At release stage and DONE
                        job_row = self.ledger.get_job(job_id)
                        if job_row and job_row['status'] != 'DONE':
                            self.ledger.set_job_status(job_id, 'DONE')

    def run_tick(self):
        """Executes a single broker scheduling and audit tick."""
        self.check_expired_leases()
        self.check_stage_advancement()

    def run(self):
        self.running = True
        self.recover_state()
        try:
            while self.running:
                self.run_tick()
                time.sleep(self.poll_interval)
        except KeyboardInterrupt:
            self.running = False


def main():
    parser = argparse.ArgumentParser(description="Resilient Pipeline Broker")
    parser.add_argument("--db", type=str, default="resilient.db", help="Path to SQLite ledger database")
    parser.add_argument("--workspace", type=str, default="resilient_workspace", help="Path to workspace directory")
    parser.add_argument("--keys-dir", type=str, default="keys", help="Path to keys directory")
    parser.add_argument("--lease-seconds", type=float, default=5.0, help="Stage lease timeout in seconds")
    parser.add_argument("--poll-interval", type=float, default=0.2, help="Broker polling loop interval")
    args = parser.parse_args()

    broker = Broker(
        db_path=Path(args.db),
        workspace_dir=Path(args.workspace),
        keys_dir=Path(args.keys_dir),
        lease_seconds=args.lease_seconds,
        poll_interval=args.poll_interval
    )
    print(f"[BROKER] Starting resilient broker (PID {os.getpid()}) on {args.db}...")
    broker.run()


if __name__ == '__main__':
    main()
