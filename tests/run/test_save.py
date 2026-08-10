import json
import tempfile
from pathlib import Path
from unittest.mock import Mock

import pytest

from minisweagent.run.utils.save import _redact, _sign_payload, load_traj, save_traj, verify_traj


# ---------------------------------------------------------------------------
# save_traj — basic behaviour (unchanged from original API)
# ---------------------------------------------------------------------------


def _make_agent(messages=None, cost=0.5, n_calls=3):
    agent = Mock()
    agent.messages = messages or [{"role": "user", "content": "hello"}]
    agent.model.cost = cost
    agent.model.n_calls = n_calls
    return agent


def test_save_traj_basic(tmp_path):
    path = tmp_path / "traj.json"
    save_traj(_make_agent(), path, print_path=False, redact_secrets=False)
    data = json.loads(path.read_text())
    assert data["info"]["model_stats"]["instance_cost"] == 0.5
    assert data["info"]["model_stats"]["api_calls"] == 3
    assert data["messages"] == [{"role": "user", "content": "hello"}]
    assert "mini_version" in data["info"]


def test_save_traj_none_agent(tmp_path):
    path = tmp_path / "traj.json"
    save_traj(None, path, print_path=False)
    data = json.loads(path.read_text())
    assert data["messages"] == []
    assert data["info"]["model_stats"]["api_calls"] == 0


def test_save_traj_extra_info(tmp_path):
    path = tmp_path / "traj.json"
    save_traj(None, path, print_path=False, extra_info={"custom_key": "custom_value"})
    data = json.loads(path.read_text())
    assert data["info"]["custom_key"] == "custom_value"


# ---------------------------------------------------------------------------
# Secret redaction
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("raw", "should_redact"),
    [
        ('{"api_key": "sk-abc123def456"}', True),
        ("password = supersecret123", True),
        ("sk-abcdefghijklmnopqrst12345", True),
        ("AKIAIOSFODNN7EXAMPLE", True),
        ("echo hello world", False),
        ("ls -la /tmp", False),
    ],
)
def test_redact_patterns(raw, should_redact):
    result = _redact(raw)
    if should_redact:
        assert "[REDACTED]" in result
    else:
        assert result == raw


def test_save_traj_redacts_secrets_by_default(tmp_path):
    agent = _make_agent(messages=[{"role": "user", "content": "my api_key: sk-supersecretkey1234567"}])
    path = tmp_path / "traj.json"
    save_traj(agent, path, print_path=False)
    data = json.loads(path.read_text())
    assert "[REDACTED]" in data["messages"][0]["content"]
    assert "sk-supersecretkey" not in data["messages"][0]["content"]


def test_save_traj_redacts_list_content(tmp_path):
    agent = _make_agent(
        messages=[{"role": "user", "content": [{"type": "text", "text": "api_key: sk-supersecretkey1234567"}]}]
    )
    path = tmp_path / "traj.json"
    save_traj(agent, path, print_path=False)
    data = json.loads(path.read_text())
    assert "[REDACTED]" in data["messages"][0]["content"][0]["text"]



    content = "my api_key: sk-supersecretkey1234567"
    agent = _make_agent(messages=[{"role": "user", "content": content}])
    path = tmp_path / "traj.json"
    save_traj(agent, path, print_path=False, redact_secrets=False)
    data = json.loads(path.read_text())
    assert data["messages"][0]["content"] == content


# ---------------------------------------------------------------------------
# Encryption + load_traj
# ---------------------------------------------------------------------------


def test_save_and_load_traj_encrypted(tmp_path):
    path = tmp_path / "traj.enc"
    agent = _make_agent()
    save_traj(agent, path, print_path=False, redact_secrets=False, encrypt_key="secret-key")

    raw = path.read_text()
    # Encrypted file must not be valid JSON
    with pytest.raises(json.JSONDecodeError):
        json.loads(raw)

    data = load_traj(path, decrypt_key="secret-key")
    assert data["info"]["model_stats"]["api_calls"] == 3


def test_load_traj_unencrypted(tmp_path):
    path = tmp_path / "traj.json"
    agent = _make_agent()
    save_traj(agent, path, print_path=False, redact_secrets=False)
    data = load_traj(path)
    assert data["messages"] == agent.messages


# ---------------------------------------------------------------------------
# HMAC signing + verify_traj
# ---------------------------------------------------------------------------


def test_save_traj_signature_stored(tmp_path):
    path = tmp_path / "traj.json"
    save_traj(None, path, print_path=False, sign_key="signing-key")
    data = json.loads(path.read_text())
    assert "signature" in data["info"]
    assert len(data["info"]["signature"]) == 64  # SHA-256 hex digest


def test_verify_traj_valid(tmp_path):
    path = tmp_path / "traj.json"
    save_traj(None, path, print_path=False, sign_key="signing-key")
    assert verify_traj(path, "signing-key") is True


def test_verify_traj_wrong_key(tmp_path):
    path = tmp_path / "traj.json"
    save_traj(None, path, print_path=False, sign_key="signing-key")
    assert verify_traj(path, "wrong-key") is False


def test_verify_traj_tampered(tmp_path):
    path = tmp_path / "traj.json"
    save_traj(None, path, print_path=False, sign_key="signing-key")
    data = json.loads(path.read_text())
    data["info"]["exit_status"] = "tampered"
    path.write_text(json.dumps(data))
    assert verify_traj(path, "signing-key") is False


def test_verify_traj_unsigned(tmp_path):
    path = tmp_path / "traj.json"
    save_traj(None, path, print_path=False)
    assert verify_traj(path, "any-key") is False


def test_save_traj_encrypted_and_signed(tmp_path):
    path = tmp_path / "traj.enc"
    save_traj(None, path, print_path=False, encrypt_key="enc-key", sign_key="sign-key")
    assert verify_traj(path, "sign-key", decrypt_key="enc-key") is True
    assert verify_traj(path, "wrong-sign-key", decrypt_key="enc-key") is False
