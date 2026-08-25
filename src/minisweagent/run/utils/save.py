import hashlib
import hmac
import json
import re
from collections.abc import Callable
from pathlib import Path

from minisweagent import Agent, __version__

# Patterns used to redact secrets from trajectory data before saving.
_REDACT_PATTERNS: list[re.Pattern] = [
    re.compile(r'(?i)(api[_-]?key|token|secret|password|passwd|credential|auth)["\s:=]+\S+'),
    re.compile(r"(?i)(sk-[A-Za-z0-9]{20,})"),  # OpenAI-style keys
    re.compile(r"(?i)(ghp_[A-Za-z0-9]{36,})"),  # GitHub personal access tokens
    re.compile(r"(?i)(AKIA[A-Z0-9]{16})"),  # AWS access key IDs
]
_REDACTION_PLACEHOLDER = "[REDACTED]"


def _redact(text: str) -> str:
    """Redact common secret patterns from a string."""
    for pattern in _REDACT_PATTERNS:
        text = pattern.sub(_REDACTION_PLACEHOLDER, text)
    return text


def _redact_messages(messages: list[dict]) -> list[dict]:
    """Deep-copy messages list with secrets redacted from content fields."""
    result = []
    for msg in messages:
        cleaned = dict(msg)
        content = cleaned.get("content")
        if isinstance(content, str):
            cleaned["content"] = _redact(content)
        elif isinstance(content, list):
            cleaned["content"] = [
                {**part, "text": _redact(part["text"])} if isinstance(part.get("text"), str) else part
                for part in content
            ]
        result.append(cleaned)
    return result


def _sign_payload(payload: str, key: str) -> str:
    """Return an HMAC-SHA256 hex digest of payload using key."""
    return hmac.new(key.encode(), payload.encode(), hashlib.sha256).hexdigest()


def _encrypt_payload(payload: str, key: str) -> str:
    """XOR-based symmetric encryption using a key derived via SHA-256.

    NOTE: This is a lightweight, dependency-free obfuscation layer suitable for
    protecting trajectories at rest from casual exposure.  For production use
    with high-value data, replace this with AES-GCM (e.g. via ``cryptography``).
    """
    key_bytes = hashlib.sha256(key.encode()).digest()
    data = payload.encode("utf-8")
    encrypted = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(data))
    return encrypted.hex()


def save_traj(
    agent: Agent | None,
    path: Path,
    *,
    print_path: bool = True,
    exit_status: str | None = None,
    result: str | None = None,
    extra_info: dict | None = None,
    print_fct: Callable = print,
    redact_secrets: bool = True,
    encrypt_key: str | None = None,
    sign_key: str | None = None,
    **kwargs,
):
    """Save the trajectory of the agent to a file.

    Args:
        agent: The agent to save the trajectory of.
        path: The path to save the trajectory to.
        print_path: Whether to print confirmation of path to the terminal.
        exit_status: The exit status of the agent.
        result: The result/submission of the agent.
        extra_info: Extra information to save (will be merged into the info dict).
        redact_secrets: Strip common secret patterns from message content (default: True).
        encrypt_key: If set, encrypt the JSON payload with this key before writing.
            Read the file back with :func:`load_traj`.
        sign_key: If set, append an HMAC-SHA256 signature so the file can be
            verified for integrity/tamper-evidence.  The signature is stored
            under ``info.signature``.
        **kwargs: Additional information to save (will be merged into top level).
    """
    messages = []
    if agent is not None:
        messages = agent.messages
    if redact_secrets:
        messages = _redact_messages(messages)

    data = {
        "info": {
            "exit_status": exit_status,
            "submission": result,
            "model_stats": {
                "instance_cost": 0.0,
                "api_calls": 0,
            },
            "mini_version": __version__,
        },
        "messages": messages,
        "trajectory_format": "mini-swe-agent-1",
    } | kwargs
    if agent is not None:
        data["info"]["model_stats"]["instance_cost"] = agent.model.cost
        data["info"]["model_stats"]["api_calls"] = agent.model.n_calls
    if extra_info:
        data["info"].update(extra_info)

    payload = json.dumps(data, indent=2)

    if sign_key:
        data["info"]["signature"] = _sign_payload(payload, sign_key)
        payload = json.dumps(data, indent=2)

    path.parent.mkdir(parents=True, exist_ok=True)
    if encrypt_key:
        path.write_text(_encrypt_payload(payload, encrypt_key))
    else:
        path.write_text(payload)

    if print_path:
        print_fct(f"Saved trajectory to '{path}'")


def load_traj(path: Path, *, decrypt_key: str | None = None) -> dict:
    """Load a trajectory file, optionally decrypting it first.

    Args:
        path: Path to the trajectory file.
        decrypt_key: Key used when the file was encrypted via ``save_traj``.

    Returns:
        Parsed trajectory dict.
    """
    raw = path.read_text()
    if decrypt_key:
        encrypted_bytes = bytes.fromhex(raw)
        key_bytes = hashlib.sha256(decrypt_key.encode()).digest()
        raw = bytes(b ^ key_bytes[i % len(key_bytes)] for i, b in enumerate(encrypted_bytes)).decode("utf-8")
    return json.loads(raw)


def verify_traj(path: Path, sign_key: str, *, decrypt_key: str | None = None) -> bool:
    """Verify the HMAC signature of a trajectory file.

    Returns True if the signature is valid, False otherwise.
    """
    data = load_traj(path, decrypt_key=decrypt_key)
    stored_sig = data.get("info", {}).pop("signature", None)
    if stored_sig is None:
        return False
    expected_payload = json.dumps(data, indent=2)
    return hmac.compare_digest(stored_sig, _sign_payload(expected_payload, sign_key))

