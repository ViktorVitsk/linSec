"""Versioned configuration, deliberately without arbitrary commands or AI settings."""

from dataclasses import asdict, dataclass
import os
from pathlib import Path
import stat
import tomllib

from .model import InvalidInput, digest


@dataclass(frozen=True)
class Config:
    schema_version: int = 1
    interval_seconds: int = 300
    stale_seconds: int = 900
    storage_mib: int = 512
    notifications: bool = False
    llm_enabled: bool = False
    persistence: tuple[str, ...] = ("crontab", "rc_local", "ld_preload", "profile", "bashrc")
    privileged_groups: tuple[str, ...] = (
        "root",
        "sudo",
        "admin",
        "wheel",
        "docker",
        "lxd",
        "disk",
        "shadow",
        "libvirt",
        "adm",
        "systemd-journal",
    )

    @property
    def fingerprint(self) -> str:
        return digest(asdict(self))

    def validate(self) -> None:
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise InvalidInput("unsupported_config_version")
        for value, low, high in (
            (self.interval_seconds, 30, 86400),
            (self.stale_seconds, self.interval_seconds * 2, 604800),
            (self.storage_mib, 8, 512),
        ):
            if type(value) is not int or not low <= value <= high:
                raise InvalidInput("invalid_config_limit")
        if type(self.notifications) is not bool or self.llm_enabled is not False:
            raise InvalidInput("AI_is_not_implemented")
        known = {"crontab", "rc_local", "ld_preload", "profile", "bashrc", "bash_profile", "zshrc"}
        if (
            not isinstance(self.persistence, (list, tuple))
            or not self.persistence
            or any(not isinstance(p, str) or p not in known for p in self.persistence)
            or len(set(self.persistence)) != len(self.persistence)
        ):
            raise InvalidInput("invalid_persistence_selection")
        if (
            not isinstance(self.privileged_groups, (list, tuple))
            or not 1 <= len(self.privileged_groups) <= 64
            or any(
                not isinstance(g, str)
                or not g
                or len(g) > 64
                or not all(c.isascii() and (c.isalnum() or c in "_-") for c in g)
                for g in self.privileged_groups
            )
        ):
            raise InvalidInput("invalid_privileged_groups")


def load_config(path: Path | None) -> Config:
    try:
        if path is None:
            config = Config()
        else:
            fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
            with os.fdopen(fd, "rb") as stream:
                if not stat.S_ISREG(os.fstat(stream.fileno()).st_mode):
                    raise InvalidInput("config_requires_regular_file")
                data = stream.read(65537)
            if len(data) > 65536:
                raise InvalidInput("config_limit")
            config = Config(**tomllib.loads(data.decode("utf-8")))
        config.validate()
        if os.environ.get("LLM_ENABLED", "false").lower() != "false":
            raise InvalidInput("set_LLM_ENABLED_false")
        return config
    except (OSError, TypeError, UnicodeError, tomllib.TOMLDecodeError) as error:
        raise InvalidInput("invalid_config_contents_omitted") from error
