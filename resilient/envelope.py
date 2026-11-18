import os
import json
import hmac
import hashlib
import time
import secrets
from pathlib import Path
from typing import Dict, Any, Optional

ALL_ROLES = [
    'coordinator',
    'broker',
    'gate_a',
    'gate_b',
    'gate_p',
    'lexer',
    'parser',
    'semantic',
    'ir',
    'codegen',
    'tester',
    'auditor',
    'releaser'
]


def canonical_json(data: Dict[str, Any]) -> str:
    """Produces deterministic canonical JSON serialization for cryptographic signing."""
    return json.dumps(data, sort_keys=True, separators=(',', ':'), ensure_ascii=False)


def generate_nonce() -> str:
    return secrets.token_hex(16)


def init_keys(keys_dir: Path) -> Dict[str, Path]:
    keys_dir = Path(keys_dir)
    keys_dir.mkdir(parents=True, exist_ok=True)
    key_paths = {}
    for role in ALL_ROLES:
        k_path = keys_dir / f"{role}.key"
        if not k_path.exists():
            key_hex = secrets.token_hex(32)
            k_path.write_text(key_hex, encoding='utf-8')
        key_paths[role] = k_path
    return key_paths


def load_key(role: str, keys_dir: Path) -> bytes:
    k_path = Path(keys_dir) / f"{role}.key"
    if not k_path.exists():
        raise FileNotFoundError(f"Key for role '{role}' not found in {keys_dir}")
    raw = k_path.read_text(encoding='utf-8').strip()
    return bytes.fromhex(raw)


def sign_payload(key_bytes: bytes, payload_dict: Dict[str, Any]) -> str:
    """Signs payload dictionary without 'sig' field using HMAC-SHA256."""
    unsigned = {k: v for k, v in payload_dict.items() if k != 'sig'}
    canonical_bytes = canonical_json(unsigned).encode('utf-8')
    return hmac.new(key_bytes, canonical_bytes, hashlib.sha256).hexdigest()


def verify_signature(key_bytes: bytes, envelope_dict: Dict[str, Any]) -> bool:
    if 'sig' not in envelope_dict:
        return False
    provided_sig = envelope_dict['sig']
    computed_sig = sign_payload(key_bytes, envelope_dict)
    return hmac.compare_digest(provided_sig, computed_sig)


def create_task_envelope(broker_key: bytes,
                         job_id: str,
                         stage: str,
                         input_hash: str,
                         deadline: float,
                         action: str,
                         approved_repair: Optional[str] = None,
                         policy_path: Optional[str] = None,
                         policy_hash: Optional[str] = None) -> Dict[str, Any]:
    envelope = {
        'job_id': job_id,
        'stage': stage,
        'input_hash': input_hash,
        'deadline': deadline,
        'action': action,
        'approved_repair': approved_repair,
        'policy_path': policy_path,
        'policy_hash': policy_hash,
        'nonce': generate_nonce()
    }
    envelope['sig'] = sign_payload(broker_key, envelope)
    return envelope


def create_result_envelope(role_key: bytes,
                           job_id: str,
                           stage: str,
                           worker_id: str,
                           role: str,
                           output_hash: str,
                           status: str,
                           artifact_name: str,
                           decision: str,
                           extra: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    envelope = {
        'job_id': job_id,
        'stage': stage,
        'worker_id': worker_id,
        'role': role,
        'output_hash': output_hash,
        'status': status,
        'artifact_name': artifact_name,
        'decision': decision,
        'extra': extra or {},
        'nonce': generate_nonce(),
        'timestamp': time.time()
    }
    envelope['sig'] = sign_payload(role_key, envelope)
    return envelope


def sign_gate_vote(gate_key: bytes, gate_name: str, vote: str, policy_hash: str, explanation: str = "") -> Dict[str, Any]:
    token = {
        'gate': gate_name,
        'vote': vote,
        'policy_hash': policy_hash,
        'explanation': explanation,
        'nonce': generate_nonce(),
        'timestamp': time.time()
    }
    token['sig'] = sign_payload(gate_key, token)
    return token


def sign_gate_approval(key_bytes: bytes, gate_name: str, job_id: str, validator_hash: str, decision: str = "APPROVE") -> Dict[str, Any]:
    token = {
        'gate': gate_name,
        'job_id': job_id,
        'validator_hash': validator_hash,
        'decision': decision,
        'nonce': generate_nonce(),
        'timestamp': time.time()
    }
    token['sig'] = sign_payload(key_bytes, token)
    return token
