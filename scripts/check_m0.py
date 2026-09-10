"""Read-only repository safety gate for the M0 foundation."""

from __future__ import annotations

from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]
IGNORED_DIRECTORIES = {
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    ".ruff_cache",
    "runtime",
    "state",
    ".cache",
    "tmp",
    "logs",
}
REQUIRED_FILES = (
    "AGENTS.md",
    ".gitignore",
    ".python-version",
    "README.md",
    "pyproject.toml",
    "docs/audit/INITIAL_SECURITY_AUDIT.md",
    "docs/operations/HOST_FIREWALL_HARDENING_PLAN.md",
    "docs/operations/NEXT_STEPS.md",
    "tests/test_m0_safety.py",
)
UNSAFE_SOURCE_PATTERNS = {
    "shell" + "=True": "shell string execution is not allowed in project subprocesses",
    "os." + "system(": "os.system is not allowed in project subprocesses",
    "ev" + "al(": "eval is not allowed in project code",
    "ex" + "ec(": "exec is not allowed in project code",
}


def _project_files() -> list[Path]:
    files: list[Path] = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in IGNORED_DIRECTORIES for part in path.relative_to(ROOT).parts):
            continue
        files.append(path)
    return files


def _forbidden_local_file(path: Path) -> bool:
    name = path.name
    if name == ".env" or (name.startswith(".env.") and name != ".env.example"):
        return True
    return path.suffix.lower() in {".db", ".sqlite", ".sqlite3"}


def collect_violations() -> list[str]:
    violations: list[str] = []
    files = _project_files()
    file_set = {path.relative_to(ROOT).as_posix() for path in files}

    for required in REQUIRED_FILES:
        if required not in file_set:
            violations.append(f"missing required M0 file: {required}")

    gitignore = (ROOT / ".gitignore").read_text(encoding="utf-8")
    for entry in (".venv/", ".env", "!.env.example", "*.sqlite3"):
        if entry not in gitignore:
            violations.append(f".gitignore is missing safety entry: {entry}")

    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    for entry in (
        'requires-python = ">=3.10"',
        "dependencies = []",
        "[dependency-groups]",
        '"ruff",',
        "package = false",
    ):
        if entry not in pyproject:
            violations.append(f"pyproject.toml is missing M0 metadata: {entry}")

    python_version = (ROOT / ".python-version").read_text(encoding="utf-8").strip()
    if python_version != "3.10":
        violations.append(f".python-version must pin the workstation baseline 3.10, got {python_version!r}")

    for path in files:
        relative = path.relative_to(ROOT)
        if _forbidden_local_file(path):
            violations.append(f"sensitive runtime file is present in project tree: {relative}")
        if path.suffix in {".py", ".sh"}:
            text = path.read_text(encoding="utf-8", errors="replace")
            for pattern, explanation in UNSAFE_SOURCE_PATTERNS.items():
                if pattern in text:
                    violations.append(f"{relative}: {explanation}")

    return violations


def main() -> int:
    violations = collect_violations()
    if violations:
        for violation in violations:
            print(f"FAIL: {violation}")
        return 1
    print("M0_SAFETY_CHECK_OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
