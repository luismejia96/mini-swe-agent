from pathlib import Path
from unittest.mock import patch

import pytest

from minisweagent.run.vuln_scan import DEFAULT_CONFIG, _build_task, _SCANNERS, main


def test_build_task_includes_target():
    task = _build_task("/code", ["bandit"])
    assert "/code" in task
    assert "bandit" in task


def test_build_task_unknown_scanner_ignored():
    task = _build_task("/code", ["nonexistent_tool"])
    # Unknown scanner is skipped, task still generated without error
    assert "/code" in task


def test_build_task_all_known_scanners():
    task = _build_task("/code", list(_SCANNERS))
    for scanner in _SCANNERS:
        assert scanner in task


def test_vuln_scan_configure_called():
    """Test that configure_if_first_time is called."""
    with (
        patch("minisweagent.run.vuln_scan.configure_if_first_time") as mock_configure,
        patch("minisweagent.run.vuln_scan.get_model"),
        patch("minisweagent.run.vuln_scan.LocalEnvironment"),
        patch("minisweagent.run.vuln_scan.InteractiveAgent") as mock_agent_cls,
        patch("minisweagent.run.vuln_scan.save_traj"),
        patch("minisweagent.run.vuln_scan.yaml.safe_load") as mock_yaml,
        patch("minisweagent.run.vuln_scan.get_config_path") as mock_cfg_path,
    ):
        mock_yaml.return_value = {"agent": {}, "environment": {}, "model": {}}
        mock_cfg_path.return_value.read_text.return_value = "test"
        mock_agent = mock_agent_cls.return_value
        mock_agent.run.return_value = (0, "ok")

        main(target="/tmp", model="test-model", config=DEFAULT_CONFIG, output=None, docker=False, yolo=True, scanners=["bandit"])

        mock_configure.assert_called_once()


def test_vuln_scan_uses_docker_environment():
    """Test that Docker environment is used when --docker flag is set."""
    with (
        patch("minisweagent.run.vuln_scan.configure_if_first_time"),
        patch("minisweagent.run.vuln_scan.get_model"),
        patch("minisweagent.run.vuln_scan.DockerEnvironment") as mock_docker,
        patch("minisweagent.run.vuln_scan.InteractiveAgent") as mock_agent_cls,
        patch("minisweagent.run.vuln_scan.save_traj"),
        patch("minisweagent.run.vuln_scan.yaml.safe_load") as mock_yaml,
        patch("minisweagent.run.vuln_scan.get_config_path") as mock_cfg_path,
    ):
        mock_yaml.return_value = {"agent": {}, "environment": {}, "model": {}}
        mock_cfg_path.return_value.read_text.return_value = "test"
        mock_agent_cls.return_value.run.return_value = (0, "ok")

        main(target="python:3.11", model="test-model", config=DEFAULT_CONFIG, output=None, docker=True, yolo=True, scanners=["trivy"])

        mock_docker.assert_called_once()
        assert mock_docker.call_args.kwargs["image"] == "python:3.11"
