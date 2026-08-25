#!/usr/bin/env python3
"""Run mini-SWE-agent as a vulnerability scanner on a local path or Docker image."""

import os
from pathlib import Path

import typer
import yaml
from rich.console import Console

from minisweagent.agents.interactive import InteractiveAgent
from minisweagent.config import builtin_config_dir, get_config_path
from minisweagent.environments.docker import DockerEnvironment
from minisweagent.environments.local import LocalEnvironment
from minisweagent.models import get_model
from minisweagent.run.extra.config import configure_if_first_time
from minisweagent.run.utils.save import save_traj

DEFAULT_CONFIG = Path(
    os.getenv("MSWEA_VULN_SCAN_CONFIG_PATH", builtin_config_dir / "cyber_triage.yaml")
)
console = Console(highlight=False)
app = typer.Typer(rich_markup_mode="rich", add_completion=False)

_SCANNERS = {
    "bandit": "bandit -r {target} -f json 2>/dev/null || true",
    "semgrep": "semgrep --config=auto {target} --json 2>/dev/null || true",
    "trivy": "trivy fs --format json {target} 2>/dev/null || true",
    "grype": "grype {target} -o json 2>/dev/null || true",
}


def _build_task(target: str, scanners: list[str]) -> str:
    scanner_cmds = "\n".join(
        f"- `{_SCANNERS[s].format(target=target)}`" for s in scanners if s in _SCANNERS
    )
    return f"""Perform an automated vulnerability scan of the target: `{target}`

Run the following available security scanners and interpret their output:
{scanner_cmds}

For each finding:
1. Parse scanner output (JSON where available)
2. Deduplicate findings across scanners
3. Classify by severity (CRITICAL/HIGH/MEDIUM/LOW/INFO)
4. Cross-reference with MITRE ATT&CK where applicable
5. Produce a prioritized remediation plan

Target: {target}
"""


@app.command()
def main(
    target: str = typer.Argument(help="Path or Docker image to scan"),
    config: Path = typer.Option(DEFAULT_CONFIG, "-c", "--config", help="Path to config file"),
    model: str | None = typer.Option(None, "-m", "--model", help="Model to use"),
    output: Path | None = typer.Option(Path("vuln_scan.traj.json"), "-o", "--output", help="Output trajectory file"),
    docker: bool = typer.Option(False, "-d", "--docker", help="Treat target as a Docker image and scan inside it"),
    scanners: list[str] = typer.Option(
        ["bandit", "semgrep", "trivy"],
        "-s",
        "--scanner",
        help=f"Scanners to use. Available: {', '.join(_SCANNERS)}",
    ),
    yolo: bool = typer.Option(False, "-y", "--yolo", help="Run without confirmation"),
) -> InteractiveAgent:
    """Run automated vulnerability scanning using AI-driven triage."""
    configure_if_first_time()

    _config = yaml.safe_load(get_config_path(config).read_text())
    _agent_config = _config.get("agent", {})
    _agent_config["mode"] = "yolo" if yolo else "confirm"

    task = _build_task(target, scanners)

    if docker:
        env: LocalEnvironment | DockerEnvironment = DockerEnvironment(
            image=target,
            **_config.get("environment", {}),
        )
    else:
        env = LocalEnvironment(
            cwd=target if Path(target).is_dir() else str(Path(target).parent),
            **_config.get("environment", {}),
        )

    agent = InteractiveAgent(
        get_model(model, _config.get("model", {})),
        env,
        **_agent_config,
    )

    exit_status, result = None, None
    try:
        exit_status, result = agent.run(task)
    except KeyboardInterrupt:
        console.print("\n[bold red]KeyboardInterrupt -- goodbye[/bold red]")
    finally:
        if output:
            save_traj(agent, output, exit_status=exit_status, result=result)
    return agent


if __name__ == "__main__":
    app()
