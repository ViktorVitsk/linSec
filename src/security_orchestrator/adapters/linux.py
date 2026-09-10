"""Read-only Linux collection with bounded files, fixed argv and minimized records.

No command lines, unit contents, account password fields or remote peer addresses
leave this boundary. Text from operating-system sources is never a command.
"""

import hashlib
import ipaddress
import os
from pathlib import Path
import re
import selectors
import stat
import subprocess
import sys
import time

from ..config import Config
from ..model import Collection, InvalidInput, MAX_ITEMS, SOURCES, encode


class SourceError(Exception):
    pass


COMMANDS = {
    **{
        f"{proto}{family}": (
            "/usr/bin/ss",
            "-H",
            "-O",
            "-n",
            "-e",
            "-p",
            "-l" if proto == "tcp" else "-a",
            f"-{proto[0]}",
            f"-{family}",
        )
        for proto in ("tcp", "udp")
        for family in (4, 6)
    },
    **{
        f"systemd_{scope}": (
            "/usr/bin/systemctl",
            f"--{scope}",
            "--no-pager",
            "--no-legend",
            "--plain",
            "list-unit-files",
            "--type=service",
            "--type=timer",
        )
        for scope in ("system", "user")
    },
    "notify": (
        "/usr/bin/notify-send",
        "--app-name=Security Orchestrator",
        "--expire-time=8000",
        "Security Orchestrator",
        "Есть новые предупреждения. Откройте sec alerts.",
    ),
}


def command(name: str, *, timeout: float = 10, limit: int = 2 * 1024 * 1024) -> str:
    argv = COMMANDS[name]
    # Build a minimal environment. No inherited loader, pager, ss test-input or unit-path overrides.
    env = {
        "PATH": "/usr/bin:/bin",
        "LC_ALL": "C",
        "SYSTEMD_PAGER": "cat",
        "SYSTEMD_COLORS": "0",
        "HOME": str(Path.home()),
        "XDG_RUNTIME_DIR": f"/run/user/{os.getuid()}",
    }
    if name in {"systemd_user", "notify"}:
        env["DBUS_SESSION_BUS_ADDRESS"] = f"unix:path=/run/user/{os.getuid()}/bus"
    try:
        # Only registry argv; no caller strings enter arguments. stderr is bounded with stdout,
        # but is never returned, stored or printed. Stop the owned child on limit/timeout.
        with subprocess.Popen(  # noqa: S603
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            shell=False,
            env=env,
            close_fds=True,
        ) as process:
            output = bytearray()
            total = 0
            stderr_seen = False
            deadline = time.monotonic() + timeout
            try:
                with selectors.DefaultSelector() as selector:
                    selector.register(process.stdout, selectors.EVENT_READ, True)
                    selector.register(process.stderr, selectors.EVENT_READ, False)
                    while selector.get_map():
                        remaining = deadline - time.monotonic()
                        if remaining <= 0:
                            raise SourceError("timeout")
                        for key, _ in selector.select(min(remaining, 0.2)):
                            chunk = os.read(key.fileobj.fileno(), 65536)
                            if not chunk:
                                selector.unregister(key.fileobj)
                                continue
                            total += len(chunk)
                            if total > limit:
                                raise SourceError("limit")
                            if key.data:
                                output.extend(chunk)
                            else:
                                stderr_seen = True
                try:
                    rc = process.wait(timeout=max(0.001, deadline - time.monotonic()))
                except subprocess.TimeoutExpired as error:
                    raise SourceError("timeout") from error
                if rc or stderr_seen:
                    raise SourceError("command_failed")
            finally:
                if process.poll() is None:
                    process.kill()
                    process.wait(timeout=2)
        return output.decode("utf-8", errors="strict")
    except FileNotFoundError as error:
        raise SourceError("missing_command") from error
    except UnicodeError as error:
        raise SourceError("invalid_input") from error
    except OSError as error:
        raise SourceError("access_or_io") from error


def read_regular(path: Path, limit: int = 1024 * 1024) -> tuple[bytes, os.stat_result]:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        before = os.fstat(stream.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise SourceError("invalid_input")
        data = stream.read(limit + 1)
        after = os.fstat(stream.fileno())
        if len(data) > limit:
            raise SourceError("limit")
        if (before.st_mtime_ns, before.st_ctime_ns, before.st_size) != (
            after.st_mtime_ns,
            after.st_ctime_ns,
            after.st_size,
        ):
            raise SourceError("access_or_io")
        return data, after


def fingerprint(path: Path, *, unit_roots: tuple[Path, ...] = ()) -> dict:
    result = {
        "kind": "file",
        "path": str(path),
        "exists": False,
        "sha256": None,
        "mode": None,
        "uid": None,
        "gid": None,
        "link_sha256": None,
    }
    try:
        info = path.lstat()
    except FileNotFoundError:
        return result
    result.update(exists=True, mode=stat.S_IMODE(info.st_mode), uid=info.st_uid, gid=info.st_gid)
    if stat.S_ISLNK(info.st_mode):
        target = os.readlink(path)
        result["link_sha256"] = hashlib.sha256(os.fsencode(target)).hexdigest()
        resolved = path.resolve()
        if unit_roots and resolved != Path("/dev/null"):
            if not any(resolved.is_relative_to(root.resolve()) for root in unit_roots):
                raise SourceError("access_or_io")
            data, info = read_regular(resolved)
            result.update(
                sha256=hashlib.sha256(data).hexdigest(),
                mode=stat.S_IMODE(info.st_mode),
                uid=info.st_uid,
                gid=info.st_gid,
            )
        elif not unit_roots:
            # Persistence links must be explicitly resolved by the owner before collecting target.
            raise SourceError("access_or_io")
    else:
        data, info = read_regular(path)
        result.update(
            sha256=hashlib.sha256(data).hexdigest(),
            mode=stat.S_IMODE(info.st_mode),
            uid=info.st_uid,
            gid=info.st_gid,
        )
    return result


def owner_context(pid: int, fd: int, inode: int) -> dict:
    base = Path("/proc") / str(pid)
    socket_path = base / "fd" / str(fd)
    expected = f"socket:[{inode}]"
    if os.readlink(socket_path) != expected:
        raise SourceError("context_missing")
    exe = os.readlink(base / "exe")
    uid = base.stat().st_uid
    if os.readlink(socket_path) != expected or not exe.startswith("/"):
        raise SourceError("context_missing")
    return {"exe": exe, "uid": uid}


def parse_ss(raw: str, protocol: str, family: int, owner=owner_context) -> dict:
    items = {}
    lines = raw.splitlines()
    if len(lines) > MAX_ITEMS:
        raise SourceError("limit")
    for line in lines:
        fields = line.split(maxsplit=5)
        # A single selected protocol omits the Netid column in ss.
        if fields and fields[0] in {"tcp", "udp"}:
            fields = line.split(maxsplit=6)[1:]
        if len(fields) < 6 or not fields[1].isdigit() or not fields[2].isdigit():
            raise SourceError("invalid_input")
        state, _, _, local, _, details = fields
        if state not in ({"LISTEN"} if protocol == "tcp" else {"UNCONN", "ESTAB"}):
            raise SourceError("invalid_input")
        address, separator, port = local.rpartition(":")
        address = address.strip("[]")
        if not separator or not port.isdecimal() or not 0 <= int(port) <= 65535:
            raise SourceError("invalid_input")
        if int(port) == 0:  # An unbound UDP socket is not a bound endpoint.
            continue
        if address == "*":
            address = "0.0.0.0" if family == 4 else "::"  # noqa: S104 -- observed bind, no server
        try:
            parsed = ipaddress.ip_address(address.split("%", 1)[0])
            if parsed.version != family:
                raise ValueError
        except ValueError as error:
            raise SourceError("invalid_input") from error
        zone = "%" + address.split("%", 1)[1] if "%" in address else ""
        address = str(parsed) + zone
        # Process names may contain strings resembling uid:/ino:. Only parse the numeric
        # details suffix, which follows the last users:(...) closing parenthesis.
        numeric = details.rsplit(")", 1)[-1] if "users:(" in details else details
        inode_match = re.search(r"(?:^|\s)ino:(\d+)(?:\s|$)", numeric)
        uid_match = re.search(r"(?:^|\s)uid:(\d+)(?:\s|$)", numeric)
        if not inode_match:
            raise SourceError("invalid_input")
        inode = int(inode_match[1])
        uid = int(uid_match[1]) if uid_match else 0  # ss omits the zero uid (upstream ss.c).
        owners = []
        pairs = re.findall(r"pid=(\d+),fd=(\d+)", details.split("ino:", 1)[0])
        if len(pairs) > 128:
            raise SourceError("limit")
        complete = bool(pairs)
        for pid, descriptor in pairs:
            try:
                owners.append(owner(int(pid), int(descriptor), inode))
            except (OSError, SourceError):
                complete = False
        owners = sorted({encode(o): o for o in owners}.values(), key=encode)
        data = {
            "kind": "endpoint",
            "protocol": protocol,
            "family": family,
            "bind": address,
            "port": int(port),
            "uid": uid,
            "owners": owners,
            "context_complete": complete,
        }
        key = f"{protocol}{family}:{address}:{port}:uid={uid}"
        if key in items:
            previous = items[key]
            data["owners"] = sorted(
                {encode(o): o for o in previous["owners"] + owners}.values(), key=encode
            )
            data["context_complete"] &= previous["context_complete"]
        items[key] = data
    return items


def parse_accounts(passwd: str, group: str, selected: tuple[str, ...]) -> dict:
    users = {}
    items = {}
    if len(passwd.splitlines()) + len(group.splitlines()) > MAX_ITEMS:
        raise SourceError("limit")
    for line in passwd.splitlines():
        fields = line.split(":")
        if len(fields) != 7 or not fields[0] or not fields[2].isdigit() or not fields[3].isdigit():
            raise SourceError("invalid_input")
        name, uid, gid = fields[0], int(fields[2]), int(fields[3])
        if name in users:
            raise SourceError("invalid_input")
        users[name] = gid
        if uid == 0:
            items["uid0:" + name] = {"kind": "uid0", "name": name, "uid": uid, "gid": gid}
    seen = set()
    for line in group.splitlines():
        fields = line.split(":")
        if len(fields) != 4 or not fields[0] or not fields[2].isdigit() or fields[0] in seen:
            raise SourceError("invalid_input")
        name, gid = fields[0], int(fields[2])
        seen.add(name)
        if name in selected:
            members = set(filter(None, fields[3].split(",")))
            members.update(user for user, primary in users.items() if primary == gid)
            items["group:" + name] = {
                "kind": "group",
                "name": name,
                "gid": gid,
                "members": sorted(members),
            }
    if not users or not seen:
        raise SourceError("invalid_input")
    return items


def unit_paths(scope: str, home: Path) -> tuple[Path, ...]:
    prefixes = ("/etc", "/run", "/usr/local/lib", "/usr/lib", "/lib")
    paths = [Path(p) / "systemd" / scope for p in prefixes]
    runtime = Path(f"/run/user/{os.getuid()}/systemd") if scope == "user" else Path("/run/systemd")
    paths += [runtime / p for p in ("transient", "generator.early", "generator", "generator.late")]
    if scope == "user":
        paths += [
            home / ".config/systemd/user",
            home / ".local/share/systemd/user",
            home / ".config/systemd/user.control",
            runtime / "user.control",
            Path("/etc/xdg/systemd/user"),
            Path("/usr/local/share/systemd/user"),
            Path("/usr/share/systemd/user"),
        ]
    else:
        paths += [Path("/etc/systemd/system.control"), Path("/run/systemd/system.control")]
    # /lib may alias /usr/lib; do not record the same content twice.
    return tuple(dict.fromkeys(path.resolve() for path in paths))


def parse_unit_files(raw: str, scope: str) -> dict:
    result = {}
    for line in raw.splitlines():
        fields = line.split()
        if (
            len(fields) not in {2, 3}
            or not fields[0].endswith((".service", ".timer"))
            or "/" in fields[0]
            or len(fields[0]) > 256
        ):
            raise SourceError("invalid_input")
        name, state = fields[:2]
        states = {
            "enabled",
            "enabled-runtime",
            "linked",
            "linked-runtime",
            "alias",
            "masked",
            "masked-runtime",
            "static",
            "disabled",
            "indirect",
            "generated",
            "transient",
            "bad",
        }
        if state not in states or name in result:
            raise SourceError("invalid_input")
        result[name] = {"kind": "unit", "name": name, "scope": scope, "enablement": state}
        if len(result) > MAX_ITEMS:
            raise SourceError("limit")
    return {"unit:" + k: v for k, v in result.items()}


def collect_units(scope: str, run=command, roots: tuple[Path, ...] | None = None) -> Collection:
    source = "systemd_" + scope
    result = Collection(
        source, scope="standard unit paths; service/timer files, drop-ins, enablement"
    )
    roots = roots if roots is not None else unit_paths(scope, Path.home())
    deadline = time.monotonic() + 20
    count = 0
    try:
        result.items.update(parse_unit_files(run(source), scope))
    except SourceError as error:
        result.status, result.reason = "partial", str(error)
    for root in roots:
        try:
            with os.scandir(root) as entries:
                for entry in entries:
                    count += 1
                    if count > MAX_ITEMS or time.monotonic() > deadline:
                        raise SourceError("limit")
                    path = Path(entry.path)
                    if entry.name.endswith((".service", ".timer")):
                        result.items["file:" + str(path)] = fingerprint(path, unit_roots=roots)
                    elif entry.name.endswith((".d", ".wants", ".requires")):
                        # One level only. Do not follow directory links into arbitrary locations.
                        if entry.is_symlink():
                            raise SourceError("access_or_io")
                        with os.scandir(path) as children:
                            for child in children:
                                count += 1
                                if count > MAX_ITEMS or time.monotonic() > deadline:
                                    raise SourceError("limit")
                                if child.name.endswith((".conf", ".service", ".timer")):
                                    child_path = Path(child.path)
                                    result.items["file:" + str(child_path)] = fingerprint(
                                        child_path, unit_roots=roots
                                    )
        except FileNotFoundError:
            # Missing standard search directories are normal; a disappearing file is partial
            # via fingerprint/read_regular, not evidence that all objects were removed.
            if root.exists():
                result.status, result.reason = "partial", "access_or_io"
        except (OSError, SourceError) as error:
            result.status = "partial"
            result.reason = str(error) if isinstance(error, SourceError) else "access_or_io"
        if count > MAX_ITEMS or time.monotonic() > deadline:
            result.status, result.reason = "partial", "limit"
            break
    return result


def persistence_paths(home: Path) -> dict[str, Path]:
    return {
        "crontab": Path("/etc/crontab"),
        "rc_local": Path("/etc/rc.local"),
        "ld_preload": Path("/etc/ld.so.preload"),
        **{name: home / ("." + name) for name in ("profile", "bashrc", "bash_profile", "zshrc")},
    }


def collect(config: Config, cancelled=lambda: False) -> list[Collection]:
    results = []
    for source in SOURCES:
        if cancelled():
            raise SourceError("cancelled")
        result = Collection(source)
        try:
            if sys.platform != "linux":
                raise SourceError("unsupported_platform")
            if source[:3] in {"tcp", "udp"}:
                result.scope = "current network namespace; available process context"
                result.items = parse_ss(command(source), source[:3], int(source[3]))
                if any(not d["context_complete"] for d in result.items.values()):
                    result.reason = "context_missing"
            elif source.startswith("systemd_"):
                result = collect_units(source.split("_")[1])
            elif source == "accounts":
                result.scope = "local /etc/passwd + /etc/group; groups=" + ",".join(
                    config.privileged_groups
                )
                passwd, _ = read_regular(Path("/etc/passwd"))
                group, _ = read_regular(Path("/etc/group"))
                result.items = parse_accounts(
                    passwd.decode(), group.decode(), config.privileged_groups
                )
            else:
                selected = persistence_paths(Path.home())
                result.scope = "selected files=" + ",".join(config.persistence)
                for name in config.persistence:
                    try:
                        result.items[name] = fingerprint(selected[name])
                    except (OSError, SourceError):
                        result.status, result.reason = "partial", "access_or_io"
            # Configuration participates in scope, preventing silent reuse after selection changes.
            result.scope += "; config=" + config.fingerprint
            result.validate()
        except (SourceError, OSError, UnicodeError, InvalidInput, ValueError):
            error = sys.exception()
            result.items = {}
            result.status = "unavailable"
            result.reason = str(error) if isinstance(error, SourceError) else "invalid_input"
        results.append(result)
    return results
