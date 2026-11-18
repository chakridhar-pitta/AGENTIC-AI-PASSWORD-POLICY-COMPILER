import re
import os
import json
import shutil
import tempfile
import subprocess
import hashlib
from pathlib import Path
from typing import Dict, Any, Tuple, Optional

from .envelope import load_key, sign_gate_vote
from .ledger import Ledger

MAX_POLICY_BYTES = 65536

# Allowlist line grammar for Gate-B
GRAMMAR_PATTERNS = [
    re.compile(r'^\s*$'),                                                               # Empty / whitespace
    re.compile(r'^\s*#.*$'),                                                             # Comment
    re.compile(r'^\s*minLength\s+\d+\s*$'),                                              # minLength N
    re.compile(r'^\s*maxLength\s+\d+\s*$'),                                              # maxLength N
    re.compile(r'^\s*require\s+(uppercase|lowercase|digit|special)(\s+\d+)?\s*$'),      # require cat [N]
    re.compile(r'^\s*forbid\s+spaces\s*$'),                                              # forbid spaces
    re.compile(r'^\s*forbid\s+sequence\s+\d+\s*$'),                                      # forbid sequence N
    re.compile(r'^\s*forbid\s+repeated\s+\d+\s*$'),                                      # forbid repeated N
    re.compile(r'^\s*blacklist\s+"([^"\\]|\\.)*"\s*$'),                                 # blacklist "term"
    re.compile(r'^\s*strength\s+minimum\s+(weak|medium|strong|very\s+strong)\s*$')       # strength minimum tier
]

# Control / Bidi / Zero-width disallowed Unicode codepoint ranges
DISALLOWED_CODEPOINTS = [
    (0x00, 0x08), (0x0B, 0x0C), (0x0E, 0x1F), (0x7F, 0x9F),                           # C0 and C1 control
    (0x200B, 0x200F),                                                                    # Zero-width spaces & bidi marks
    (0x202A, 0x202E),                                                                    # Bidi embedding / override
    (0x2066, 0x2069),                                                                    # Bidi isolates
    (0xFEFF, 0xFEFF),                                                                    # Byte order mark
]


def check_gate_b(policy_text: str, policy_bytes: bytes) -> Tuple[bool, str]:
    """Gate-B: Python default-deny parser."""
    # 1. 64 KB limit
    if len(policy_bytes) > MAX_POLICY_BYTES:
        return False, f"Size {len(policy_bytes)} bytes exceeds 64 KB limit"

    # 2. Reject control and bidi/unicode tricks
    for idx, ch in enumerate(policy_text):
        cp = ord(ch)
        # Check standard ASCII printable limit
        if cp > 126:
            return False, f"Non-ASCII character '{ch}' (U+{cp:04X}) rejected at index {idx}"
        for low, high in DISALLOWED_CODEPOINTS:
            if low <= cp <= high:
                return False, f"Disallowed control/bidi character (U+{cp:04X}) at index {idx}"

    # 3. Allowlisted line grammar & string-literal escaping
    lines = policy_text.splitlines()
    for line_num, line in enumerate(lines, start=1):
        # Check match with allowlisted grammar patterns
        matched = any(pat.match(line) for pat in GRAMMAR_PATTERNS)
        if not matched:
            return False, f"Grammar violation on line {line_num}: '{line.strip()}'"

        # Validate string literal escaping in blacklist line
        if 'blacklist' in line:
            first_q = line.find('"')
            last_q = line.rfind('"')
            if first_q == -1 or last_q == -1 or first_q == last_q:
                return False, f"Malformed string quotation on line {line_num}"
            inner = line[first_q + 1:last_q]
            # Verify escape sequences inside string
            i = 0
            while i < len(inner):
                if inner[i] == '\\':
                    if i + 1 >= len(inner):
                        return False, f"Dangling escape backslash on line {line_num}"
                    esc = inner[i + 1]
                    if esc not in ('"', '\\', 'n', 't', 'r'):
                        return False, f"Invalid escape sequence '\\{esc}' on line {line_num}"
                    i += 2
                else:
                    i += 1

    return True, "Policy adheres to default-deny allowlist grammar"


def run_gate_a(policy_path: Path, compiler_bin: Path, temp_dir: Path) -> Tuple[bool, str]:
    """Gate-A: inspectPolicyInput via compiler --stage guard."""
    out_dir = temp_dir / "gate_a_out"
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        str(compiler_bin),
        "--stage", "guard",
        "--policy", str(policy_path),
        "--out-dir", str(out_dir)
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    sr_path = out_dir / "stage_result.json"
    if not sr_path.exists():
        return False, f"Gate-A execution failed (code {res.returncode}): {res.stderr.strip()}"
    try:
        sr = json.loads(sr_path.read_text(encoding='utf-8'))
        is_ok = sr.get("ok", False)
        decision = sr.get("decision", "BLOCK")
        return (is_ok and decision == "PASS"), f"Gate-A decision: {decision}"
    except Exception as e:
        return False, f"Gate-A result parsing error: {e}"


def run_gate_p(policy_path: Path, compiler_bin: Path, temp_dir: Path) -> Tuple[bool, str]:
    """Gate-P: real lexer + parser deterministic acceptance."""
    out_dir = temp_dir / "gate_p_out"
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd = [
        str(compiler_bin),
        "--stage", "parse",
        "--policy", str(policy_path),
        "--out-dir", str(out_dir)
    ]
    res = subprocess.run(cmd, capture_output=True, text=True)
    sr_path = out_dir / "stage_result.json"
    if not sr_path.exists():
        return False, f"Gate-P execution failed (code {res.returncode}): {res.stderr.strip()}"
    try:
        sr = json.loads(sr_path.read_text(encoding='utf-8'))
        is_ok = sr.get("ok", False)
        decision = sr.get("decision", "BLOCK")
        return (is_ok and decision == "PROCEED"), f"Gate-P decision: {decision}"
    except Exception as e:
        return False, f"Gate-P result parsing error: {e}"


class IntakeGateManager:
    def __init__(self, compiler_bin: Path, keys_dir: Path, ledger: Ledger):
        self.compiler_bin = Path(compiler_bin)
        self.keys_dir = Path(keys_dir)
        self.ledger = ledger

    def evaluate_policy(self,
                        policy_path: Path,
                        job_id: str,
                        gate_a_override: Optional[str] = None) -> Tuple[bool, Dict[str, Any], bool]:
        """
        Runs Gate-A, Gate-B, Gate-P.
        Returns: (consensus_passed, signed_votes, is_degraded)
        """
        policy_bytes = policy_path.read_bytes()
        policy_text = policy_bytes.decode('utf-8', errors='replace')
        policy_hash = hashlib.sha256(policy_bytes).hexdigest()

        key_a = load_key('gate_a', self.keys_dir)
        key_b = load_key('gate_b', self.keys_dir)
        key_p = load_key('gate_p', self.keys_dir)

        temp_dir = Path(tempfile.mkdtemp(prefix=f"gates_{job_id}_"))
        try:
            # 1. Gate-A
            if gate_a_override:
                vote_a = gate_a_override
                expl_a = f"Gate-A override forced: {gate_a_override}"
            else:
                ok_a, expl_a = run_gate_a(policy_path, self.compiler_bin, temp_dir)
                vote_a = "PASS" if ok_a else "BLOCK"
            token_a = sign_gate_vote(key_a, "Gate-A", vote_a, policy_hash, expl_a)

            # 2. Gate-B
            ok_b, expl_b = check_gate_b(policy_text, policy_bytes)
            vote_b = "PASS" if ok_b else "BLOCK"
            token_b = sign_gate_vote(key_b, "Gate-B", vote_b, policy_hash, expl_b)

            # 3. Gate-P
            ok_p, expl_p = run_gate_p(policy_path, self.compiler_bin, temp_dir)
            vote_p = "PASS" if ok_p else "BLOCK"
            token_p = sign_gate_vote(key_p, "Gate-P", vote_p, policy_hash, expl_p)

            signed_votes = {
                "Gate-A": token_a,
                "Gate-B": token_b,
                "Gate-P": token_p
            }

            for gate_name, t in signed_votes.items():
                self.ledger.log_event(job_id, "gates", "GATE_VOTE", {
                    "gate": gate_name,
                    "vote": t["vote"],
                    "explanation": t.get("explanation", ""),
                    "sig": t["sig"]
                })

            # Consensus logic
            isolated = set(self.ledger.list_isolated_gates())
            active_gates = {name: token for name, token in signed_votes.items() if name not in isolated}
            is_degraded = len(isolated) > 0

            # Disagreement check
            raw_votes = {name: token["vote"] for name, token in active_gates.items()}
            distinct_votes = set(raw_votes.values())
            if len(distinct_votes) > 1:
                self.ledger.log_event(job_id, "gates", "ALERT", {
                    "alert": "Intake gate disagreement detected",
                    "votes": raw_votes,
                    "isolated": list(isolated),
                    "degraded": is_degraded
                })

            if is_degraded:
                # Degraded mode: remaining gates must agree unanimously
                consensus_pass = all(v == "PASS" for v in raw_votes.values()) and len(raw_votes) > 0
            else:
                # Normal mode: >=2 of 3 PASS, Gate-P mandatory
                pass_count = sum(1 for v in raw_votes.values() if v == "PASS")
                gate_p_pass = raw_votes.get("Gate-P") == "PASS"
                consensus_pass = (pass_count >= 2) and gate_p_pass

            self.ledger.log_event(job_id, "gates", "GATE_CONSENSUS", {
                "consensus_passed": consensus_pass,
                "degraded": is_degraded,
                "votes": raw_votes,
                "isolated": list(isolated)
            })

            return consensus_pass, signed_votes, is_degraded
        finally:
            shutil.rmtree(temp_dir, ignore_errors=True)
