"""Inspect local M2c build artifacts without extracting or printing file contents."""

from pathlib import Path, PurePosixPath
import tarfile
import zipfile

from security_orchestrator.investigation.contracts import require

DIRECTORY = Path(".cache/m2c-review/dist")


def check():
    sources = Path("src/security_orchestrator")
    expected = {
        p.relative_to(sources).as_posix(): p.read_bytes()
        for p in sources.rglob("*")
        if p.is_file() and p.suffix in {".py", ".js", ".html", ".css"}
    }
    for archive_path in sorted(DIRECTORY.glob("security_orchestrator-*")):
        if archive_path.suffix == ".whl":
            with zipfile.ZipFile(archive_path) as archive:
                contents = {
                    name: archive.read(name)
                    for name in archive.namelist()
                    if not name.endswith("/")
                }
            prefix = "security_orchestrator/"
            metadata = {
                "security_orchestrator-0.1.0.dist-info/" + name
                for name in ("WHEEL", "METADATA", "RECORD", "entry_points.txt")
            }
        else:
            with tarfile.open(archive_path) as archive:
                require(all(member.isfile() or member.isdir() for member in archive.getmembers()))
                contents = {
                    member.name: archive.extractfile(member).read()
                    for member in archive.getmembers()
                    if member.isfile()
                }
            root = "security_orchestrator-0.1.0/"
            prefix = root + "src/security_orchestrator/"
            metadata = {
                root + name
                for name in ("README.md", "PKG-INFO", "pyproject.toml", "pyproject.toml.orig")
            }
        require(set(contents) == {prefix + name for name in expected} | metadata)
        for name, data in contents.items():
            require(".." not in PurePosixPath(name).parts and not name.startswith("/"))
            require(b"/home/portfolio/" not in data and b"/Users/" not in data)
            if name.startswith(prefix):
                require(data == expected[name.removeprefix(prefix)])
        print(
            f"PASS {archive_path.name}: {len(contents)} regular files; exact reviewed source/assets and metadata"
        )
    require(len(list(DIRECTORY.glob("*.whl"))) == 1 and len(list(DIRECTORY.glob("*.tar.gz"))) == 1)


if __name__ == "__main__":
    check()
