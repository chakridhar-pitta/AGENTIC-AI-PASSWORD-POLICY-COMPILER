import sqlite3
import hashlib
import json
import time
from pathlib import Path
from typing import Dict, List, Optional, Tuple, Any
from contextlib import contextmanager

GENESIS_HASH = "0" * 64

TRANSITION_TABLE = [
    'gates',
    'lex',
    'parse',
    'semantic',
    'ir',
    'codegen',
    'test',
    'audit',
    'release'
]

STAGE_ARTIFACTS = {
    'lex': 'tokens.json',
    'parse': 'ast.json',
    'semantic': 'constraints.json',
    'ir': 'ir.json',
    'codegen': 'validator.cpp',
    'test': 'test_report.json',
    'audit': 'audit_report.json'
}

ROLE_PERMISSIONS = {
    'lexer': {'stage': 'lex', 'action': 'lex', 'artifact': 'tokens.json'},
    'parser': {'stage': 'parse', 'action': 'parse', 'artifact': 'ast.json'},
    'semantic': {'stage': 'semantic', 'action': 'semantic', 'artifact': 'constraints.json'},
    'ir': {'stage': 'ir', 'action': 'ir', 'artifact': 'ir.json'},
    'codegen': {'stage': 'codegen', 'action': 'codegen', 'artifact': 'validator.cpp'},
    'tester': {'stage': 'test', 'action': 'test', 'artifact': 'test_report.json'},
    'auditor': {'stage': 'audit', 'action': 'audit', 'artifact': 'audit_report.json'}
}


@contextmanager
def get_db_connection(db_path: Path):
    conn = sqlite3.connect(str(db_path), timeout=30.0, isolation_level=None)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL;")
    conn.execute("PRAGMA synchronous=NORMAL;")
    conn.execute("PRAGMA busy_timeout=10000;")
    try:
        yield conn
    finally:
        conn.close()


def init_db(db_path: Path):
    db_path.parent.mkdir(parents=True, exist_ok=True)
    with get_db_connection(db_path) as conn:
        conn.execute("BEGIN IMMEDIATE;")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS jobs (
                job_id TEXT PRIMARY KEY,
                policy_path TEXT NOT NULL,
                policy_hash TEXT NOT NULL,
                status TEXT NOT NULL,
                approved_repair TEXT,
                degraded INTEGER DEFAULT 0,
                created_at REAL NOT NULL,
                updated_at REAL NOT NULL
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS stages (
                job_id TEXT NOT NULL,
                stage TEXT NOT NULL,
                status TEXT NOT NULL,
                input_hash TEXT,
                output_hash TEXT,
                worker_id TEXT,
                lease_expires REAL,
                attempts INTEGER DEFAULT 0,
                PRIMARY KEY (job_id, stage),
                FOREIGN KEY (job_id) REFERENCES jobs(job_id)
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                job_id TEXT NOT NULL,
                stage TEXT,
                event_type TEXT NOT NULL,
                payload TEXT NOT NULL,
                prev_hash TEXT NOT NULL,
                event_hash TEXT NOT NULL,
                created_at REAL NOT NULL
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS isolated_gates (
                gate_name TEXT PRIMARY KEY,
                isolated_at REAL NOT NULL
            );
        """)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS seen_nonces (
                nonce TEXT PRIMARY KEY,
                seen_at REAL NOT NULL
            );
        """)
        conn.execute("COMMIT;")


def compute_event_hash(job_id: str, stage: Optional[str], event_type: str, payload: str, prev_hash: str, created_at: float) -> str:
    raw = f"{job_id}|{stage or ''}|{event_type}|{payload}|{prev_hash}|{created_at:.6f}"
    return hashlib.sha256(raw.encode('utf-8')).hexdigest()


class Ledger:
    def __init__(self, db_path: Path):
        self.db_path = Path(db_path)
        init_db(self.db_path)

    def log_event(self, job_id: str, stage: Optional[str], event_type: str, payload: Any) -> str:
        payload_str = json.dumps(payload, sort_keys=True) if not isinstance(payload, str) else payload
        now = time.time()
        with get_db_connection(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE;")
            row = conn.execute("SELECT event_hash FROM events ORDER BY id DESC LIMIT 1;").fetchone()
            prev_hash = row['event_hash'] if row else GENESIS_HASH
            ev_hash = compute_event_hash(job_id, stage, event_type, payload_str, prev_hash, now)
            conn.execute(
                "INSERT INTO events (job_id, stage, event_type, payload, prev_hash, event_hash, created_at) VALUES (?, ?, ?, ?, ?, ?, ?);",
                (job_id, stage, event_type, payload_str, prev_hash, ev_hash, now)
            )
            conn.execute("COMMIT;")
            return ev_hash

    def verify_event_chain(self) -> Tuple[bool, str]:
        with get_db_connection(self.db_path) as conn:
            rows = conn.execute("SELECT * FROM events ORDER BY id ASC;").fetchall()
            prev = GENESIS_HASH
            for row in rows:
                if row['prev_hash'] != prev:
                    return False, f"Broken prev_hash link at event id {row['id']}: expected {prev}, got {row['prev_hash']}"
                expected_hash = compute_event_hash(
                    row['job_id'], row['stage'], row['event_type'], row['payload'], row['prev_hash'], row['created_at']
                )
                if row['event_hash'] != expected_hash:
                    return False, f"Tampered event payload at id {row['id']}: hash mismatch"
                prev = row['event_hash']
            return True, "Chain valid"

    def record_seen_nonce(self, nonce: str) -> bool:
        """Returns True if nonce was new and recorded, False if replay."""
        with get_db_connection(self.db_path) as conn:
            try:
                conn.execute("BEGIN IMMEDIATE;")
                conn.execute("INSERT INTO seen_nonces (nonce, seen_at) VALUES (?, ?);", (nonce, time.time()))
                conn.execute("COMMIT;")
                return True
            except sqlite3.IntegrityError:
                conn.execute("ROLLBACK;")
                return False

    def is_gate_isolated(self, gate_name: str) -> bool:
        with get_db_connection(self.db_path) as conn:
            row = conn.execute("SELECT 1 FROM isolated_gates WHERE gate_name = ?;", (gate_name,)).fetchone()
            return row is not None

    def isolate_gate(self, gate_name: str):
        with get_db_connection(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE;")
            conn.execute("INSERT OR REPLACE INTO isolated_gates (gate_name, isolated_at) VALUES (?, ?);", (gate_name, time.time()))
            conn.execute("COMMIT;")
        self.log_event("SYSTEM", None, "GATE_ISOLATED", {"gate": gate_name})

    def list_isolated_gates(self) -> List[str]:
        with get_db_connection(self.db_path) as conn:
            rows = conn.execute("SELECT gate_name FROM isolated_gates ORDER BY isolated_at ASC;").fetchall()
            return [r['gate_name'] for r in rows]

    def create_job(self, job_id: str, policy_path: str, policy_hash: str, degraded: bool = False) -> bool:
        now = time.time()
        with get_db_connection(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE;")
            conn.execute(
                "INSERT INTO jobs (job_id, policy_path, policy_hash, status, degraded, created_at, updated_at) VALUES (?, ?, ?, ?, ?, ?, ?);",
                (job_id, policy_path, policy_hash, "PENDING", 1 if degraded else 0, now, now)
            )
            # Initial stage is gates
            conn.execute(
                "INSERT INTO stages (job_id, stage, status, input_hash, output_hash, worker_id, lease_expires, attempts) VALUES (?, ?, ?, ?, ?, ?, ?, ?);",
                (job_id, "gates", "READY", policy_hash, None, None, 0.0, 0)
            )
            conn.execute("COMMIT;")
        self.log_event(job_id, "gates", "JOB_SUBMITTED", {
            "policy_path": policy_path,
            "policy_hash": policy_hash,
            "degraded": degraded
        })
        return True

    def get_job(self, job_id: str) -> Optional[Dict[str, Any]]:
        with get_db_connection(self.db_path) as conn:
            row = conn.execute("SELECT * FROM jobs WHERE job_id = ?;", (job_id,)).fetchone()
            return dict(row) if row else None

    def get_stages(self, job_id: str) -> List[Dict[str, Any]]:
        with get_db_connection(self.db_path) as conn:
            rows = conn.execute("SELECT * FROM stages WHERE job_id = ? ORDER BY rowid ASC;", (job_id,)).fetchall()
            return [dict(r) for r in rows]

    def get_stage(self, job_id: str, stage: str) -> Optional[Dict[str, Any]]:
        with get_db_connection(self.db_path) as conn:
            row = conn.execute("SELECT * FROM stages WHERE job_id = ? AND stage = ?;", (job_id, stage)).fetchone()
            return dict(row) if row else None

    def validate_transition(self, current_stage: str, next_stage: str) -> bool:
        if current_stage not in TRANSITION_TABLE or next_stage not in TRANSITION_TABLE:
            return False
        curr_idx = TRANSITION_TABLE.index(current_stage)
        next_idx = TRANSITION_TABLE.index(next_stage)
        return next_idx == curr_idx + 1

    def move_to_next_stage(self, job_id: str, current_stage: str, output_hash: str) -> Tuple[bool, Optional[str]]:
        """Advance job to next stage strictly according to transition table."""
        if current_stage not in TRANSITION_TABLE:
            return False, f"Unknown stage: {current_stage}"
        curr_idx = TRANSITION_TABLE.index(current_stage)
        if curr_idx + 1 >= len(TRANSITION_TABLE):
            # Already at final stage (release)
            return True, None

        next_stage = TRANSITION_TABLE[curr_idx + 1]
        with get_db_connection(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE;")
            # Check current stage is DONE
            curr_row = conn.execute("SELECT status FROM stages WHERE job_id = ? AND stage = ?;", (job_id, current_stage)).fetchone()
            if not curr_row or curr_row['status'] != 'DONE':
                conn.execute("ROLLBACK;")
                return False, f"Current stage {current_stage} is not DONE"

            # Insert next stage as READY
            conn.execute(
                """INSERT INTO stages (job_id, stage, status, input_hash, output_hash, worker_id, lease_expires, attempts)
                   VALUES (?, ?, 'READY', ?, NULL, NULL, 0.0, 0)
                   ON CONFLICT(job_id, stage) DO UPDATE SET status='READY', input_hash=excluded.input_hash;""",
                (job_id, next_stage, output_hash)
            )
            conn.execute("UPDATE jobs SET status = 'RUNNING', updated_at = ? WHERE job_id = ?;", (time.time(), job_id))
            conn.execute("COMMIT;")

        self.log_event(job_id, next_stage, "STAGE_READY", {"input_hash": output_hash, "from_stage": current_stage})
        return True, next_stage

    def set_job_status(self, job_id: str, status: str):
        with get_db_connection(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE;")
            conn.execute("UPDATE jobs SET status = ?, updated_at = ? WHERE job_id = ?;", (status, time.time(), job_id))
            conn.execute("COMMIT;")
        self.log_event(job_id, None, "JOB_STATUS_CHANGE", {"status": status})

    def set_human_approval(self, job_id: str, approved_choice: str):
        with get_db_connection(self.db_path) as conn:
            conn.execute("BEGIN IMMEDIATE;")
            conn.execute(
                "UPDATE jobs SET approved_repair = ?, status = 'RUNNING', updated_at = ? WHERE job_id = ?;",
                (approved_choice, time.time(), job_id)
            )
            # Reset parse stage to READY so worker can re-execute with approved candidate
            conn.execute(
                "UPDATE stages SET status = 'READY', worker_id = NULL, lease_expires = 0.0 WHERE job_id = ? AND stage = 'parse';",
                (job_id,)
            )
            conn.execute("COMMIT;")
        self.log_event(job_id, "parse", "HUMAN_APPROVED", {"choice": approved_choice})
