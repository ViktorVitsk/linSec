"""Read-only repository hygiene; run Ruff separately for Python analysis.

This development check is not a sandbox, secret scanner, or host audit.
Only known project configuration files are read. Git supplies path metadata.
"""

from __future__ import annotations

import os
from pathlib import Path
import re
import shutil
import subprocess
import tomllib


ROOT = Path(__file__).resolve().parents[1]
REQUIRED_FILES = ("AGENTS.md", ".gitignore", ".python-version", "README.md", "pyproject.toml", "uv.lock")
LOCAL_DIRECTORIES = {"runtime", "state", ".cache", "tmp", "logs", "secrets", ".ssh", ".venv", "venv"}
IGNORE_PROBES = (
    ".venv/probe", ".env", ".env.local", "nested/.env", "secrets/probe", ".ssh/probe",
    "runtime/probe", "state/probe", "logs/probe", "tmp/probe", ".cache/probe",
    "events.db", "events.db-wal", "events.sqlite", "events.sqlite-shm",
    "events.sqlite3", "events.sqlite3-journal", "probe.log", "probe.log.1",
)


def _forbidden_local_file(path: Path) -> bool:
    """Classify names without reading potentially sensitive contents."""
    name = path.name.lower()
    if name == ".env" or (name.startswith(".env.") and name != ".env.example"):
        return True
    return bool(re.search(r"\.(?:db|sqlite|sqlite3)(?:-.*)?$|\.log(?:\..*)?$", name))


def _forbidden_repository_path(path: Path) -> bool:
    return _forbidden_local_file(path) or bool(set(path.parts) & LOCAL_DIRECTORIES)


def _git(root: Path, args: tuple[str, ...], data: bytes | None = None) -> tuple[int, bytes]:
    git = shutil.which("git")
    if git is None:
        raise RuntimeError("Git is required for repository hygiene checks")
    # Fixed read-only Git subcommands; no telemetry or shell command strings.
    result = subprocess.run(  # noqa: S603
        [git, "-C", str(root), *args], input=data, stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL, timeout=10, check=False,
    )
    return result.returncode, result.stdout


def _table(value: object) -> dict:
    return value if isinstance(value, dict) else {}


def _configuration_violations(root: Path) -> list[str]:
    try:
        config = tomllib.loads((root / "pyproject.toml").read_text(encoding="utf-8"))
        pin = (root / ".python-version").read_text(encoding="utf-8").strip()
    except (OSError, UnicodeError, tomllib.TOMLDecodeError):
        return ["cannot read valid Python project configuration (contents omitted)"]
    violations = []
    if not re.fullmatch(r"3\.\d+", pin):
        return [".python-version must contain a Python 3 major.minor pin"]
    if _table(config.get("project")).get("requires-python") != f">={pin}":
        violations.append("requires-python must match the .python-version minimum")
    ruff = _table(_table(config.get("tool")).get("ruff"))
    if ruff.get("target-version") != "py" + pin.replace(".", ""):
        violations.append("Ruff target-version must match .python-version")
    selected = _table(ruff.get("lint")).get("select", [])
    if not isinstance(selected, list) or not all(item in selected for item in ("S", "TID251")):
        violations.append("Ruff must enable security and banned-API checks")
    dev = _table(config.get("dependency-groups")).get("dev", [])
    if not isinstance(dev, list) or not any(
        isinstance(item, str) and re.match(r"ruff(?:$|[<>=!~\[])", item) for item in dev
    ):
        violations.append("declare Ruff in the dev dependency group")
    # Runtime dependencies and packaging may evolve with the application.
    return violations


def collect_violations(root: Path = ROOT) -> list[str]:
    violations = []
    for name in REQUIRED_FILES:
        path = root / name
        if path.is_symlink() or not path.is_file():
            violations.append(f"missing regular project file: {name}")
    if violations:
        return violations
    violations.extend(_configuration_violations(root))
    try:
        # .gitignore cannot protect an existing index entry: include tracked ignored files.
        rc, output = _git(root, ("ls-files", "--cached", "--others", "--exclude-standard", "-z"))
        if rc != 0:
            return violations + ["Git file inventory failed (details omitted)"]
        for item in output.split(b"\0"):
            if item:
                relative = Path(os.fsdecode(item))
                if _forbidden_repository_path(relative):
                    violations.append(f"local data is tracked or not ignored: {str(relative)!r}")
        probes = (*IGNORE_PROBES, ".env.example")
        rc, output = _git(
            root, ("check-ignore", "--no-index", "--stdin", "-z"),
            b"\0".join(p.encode() for p in probes) + b"\0",
        )
        if rc not in (0, 1):
            return violations + ["Git ignore check failed (details omitted)"]
        ignored = set(output.split(b"\0"))
        for probe in IGNORE_PROBES:
            if probe.encode() not in ignored:
                violations.append(f"Git ignore protection missing for: {probe}")
        if b".env.example" in ignored:
            violations.append(".env.example must remain available for a sanitized example")
    except (OSError, subprocess.TimeoutExpired, RuntimeError):
        violations.append("Git hygiene check unavailable or timed out (details omitted)")
    return violations


def main() -> int:
    violations = collect_violations()
    for violation in violations:
        print(f"FAIL: {violation}")
    if violations:
        return 1
    print("M0_SAFETY_CHECK_OK (repository hygiene only; run Ruff and tests separately)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
