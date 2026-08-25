import pytest
import typer

from minisweagent.run.auth import check_api_key


def test_no_required_key_passes(monkeypatch):
    monkeypatch.delenv("MINI_SWE_AGENT_KEY", raising=False)
    check_api_key(None)
    check_api_key("anything")


def test_correct_key_passes(monkeypatch):
    monkeypatch.setenv("MINI_SWE_AGENT_KEY", "secret123")
    check_api_key("secret123")


@pytest.mark.parametrize("provided", [
    None,
    "",
    "wrong-key",
])
def test_wrong_or_missing_key_aborts(monkeypatch, provided):
    monkeypatch.setenv("MINI_SWE_AGENT_KEY", "secret123")
    with pytest.raises(typer.Exit):
        check_api_key(provided)
