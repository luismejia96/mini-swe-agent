"""API key authentication for mini-swe-agent.

Set MINI_SWE_AGENT_KEY in the global .env file or environment to require
callers to provide a matching key via the --api-key option or the same
environment variable.  If the variable is not set, authentication is disabled
and the agent runs without any key check.
"""

import os

import typer
from rich.console import Console

_console = Console(highlight=False)
_ENV_VAR = "MINI_SWE_AGENT_KEY"


def check_api_key(provided: str | None) -> None:
    """Abort if the required key is set but the provided key doesn't match."""
    required = os.getenv(_ENV_VAR)
    if not required:
        return
    if provided != required:
        _console.print("[bold red]Authentication failed:[/bold red] invalid or missing API key.")
        raise typer.Exit(code=1)
