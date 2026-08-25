import os
import platform
import re
from dataclasses import asdict, dataclass, field
from typing import Any

from minisweagent.environments.local import LocalEnvironment, LocalEnvironmentConfig

_SAFE_ENV_VARS = {"PAGER", "MANPAGER", "LESS", "TERM", "PATH", "LANG", "HOME", "SHELL"}


@dataclass
class ReadOnlyLocalEnvironmentConfig(LocalEnvironmentConfig):
    blocked_commands: list[str] = field(
        default_factory=lambda: [
            "rm",
            "rmdir",
            "mv",
            "dd",
            "mkfs",
            "fdisk",
            "chmod",
            "chown",
            "truncate",
            "shred",
            "wipefs",
            "tee",
            ">",
            ">>",
        ]
    )
    """Commands and shell operators that are blocked in read-only mode."""


class ReadOnlyLocalEnvironment(LocalEnvironment):
    """A local environment that blocks write/destructive commands.

    Safe for deployment near OT/ICS systems and critical infrastructure where
    analysis is required but no modifications must be made.
    """

    def __init__(self, *, config_class: type = ReadOnlyLocalEnvironmentConfig, **kwargs):
        super().__init__(config_class=config_class, **kwargs)

    def _is_blocked(self, command: str) -> str | None:
        """Return the blocked token if the command is forbidden, else None."""
        assert isinstance(self.config, ReadOnlyLocalEnvironmentConfig)
        for token in self.config.blocked_commands:
            if token in (">", ">>"):
                # Shell operator — literal substring match is correct
                if token in command:
                    return token
            else:
                # Command name — require a word boundary to avoid false positives
                if re.search(rf"(?:^|[\s;|&`$(]){re.escape(token)}\b", command):
                    return token
        return None

    def execute(self, command: str, cwd: str = "") -> dict[str, Any]:
        if blocked := self._is_blocked(command):
            return {
                "output": f"[ReadOnlyLocalEnvironment] Command blocked: '{blocked}' is not permitted in read-only mode.",
                "returncode": 1,
            }
        return super().execute(command, cwd)

    def get_template_vars(self) -> dict[str, Any]:
        safe_env = {k: v for k, v in os.environ.items() if k in _SAFE_ENV_VARS}
        return asdict(self.config) | platform.uname()._asdict() | safe_env | {"readonly_mode": True}
