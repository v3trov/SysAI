from __future__ import annotations

import json
import os
import re
import shutil
import tempfile
from contextlib import contextmanager
from datetime import datetime, timezone
from pathlib import Path

from .config import state_dir
from .context import discover, dynamic_summary
from . import custom_tools
from .runner import run
from .safety import Rejected, parse_command, secret_path
from .storage import Storage


SPECS: dict[str, dict[str, tuple[type, bool]]] = {
    "shell_exec": {"command": (str, True), "timeout": (int, False), "shell": (bool, False), "cwd": (str, False)},
    "read_file": {"path": (str, True)}, "list_directory": {"path": (str, True)}, "file_stat": {"path": (str, True)},
    "write_file": {"path": (str, True), "content": (str, True)},
    "edit_file": {"path": (str, True), "old": (str, True), "new": (str, True)},
    "system_info": {"dynamic": (bool, False)},
    "service_manager": {"action": (str, True), "service": (str, True)},
    "package_manager": {"action": (str, True), "package": (str, False)},
    "network_info": {"action": (str, True)}, "process_manager": {"action": (str, True), "pid": (int, False)},
    "log_reader": {"action": (str, True), "service": (str, False), "lines": (int, False)},
    "docker": {"action": (str, True), "name": (str, False), "image": (str, False), "host_port": (int, False), "container_port": (int, False), "volume_target": (str, False)},
    "mount_manager": {"action": (str, True), "source": (str, False), "target": (str, False)},
    "schedule_task": {"description": (str, True), "schedule": (str, True), "kind": (str, True), "payload": (str, True)},
    "provision_disk": {"device": (str, True), "expected_size_gb": (int, True), "target": (str, True)},
    "archive_create": {"source": (str, True), "destination": (str, True)},
    "create_tool": {"name": (str, True), "description": (str, True), "parameters": (str, True), "source": (str, True), "replace": (bool, False)},
    "inspect_tool": {"name": (str, False)},
}

DESCRIPTIONS = {
    "shell_exec": "General Linux command. Backend parses argv and classifies risk. Set shell=true only for pipelines, redirects or expansion; approval is required. Prefer typed tools where they fit.",
    "read_file": "Read up to 32 KiB from an absolute path; sensitive credential paths are blocked.",
    "list_directory": "List up to 200 names in an absolute directory.",
    "file_stat": "Read size, ownership, mode and mtime of an absolute path.",
    "write_file": "Create a new file only; existing files require edit_file.",
    "edit_file": "Replace one exact occurrence of old with new; backup and config validation are automatic.",
    "system_info": "Read static system discovery; dynamic=true also refreshes uptime, memory, filesystems and block devices.",
    "service_manager": "systemd service status/start/stop/restart/reload/enable/disable/is-active/is-enabled. Network and SSH mutations require destructive approval.",
    "package_manager": "apt update/install/remove/search/query one package. Verify installation with query.",
    "network_info": "Read interfaces, routes, DNS or listening ports; never changes network settings.",
    "process_manager": "Read top CPU, top memory, ports, one PID or open files for one PID.",
    "log_reader": "Read bounded journal, kernel or service logs; lines 1..500.",
    "docker": "Docker info/ps/inspect/logs/images/volumes/pull/run/stop/restart/remove. Run accepts image, container name, optional host_port/container_port and named-volume target such as /app/data.",
    "mount_manager": "Read lsblk/blkid/findmnt or mount/umount an existing target. For formatting use a separate approved operation.",
    "schedule_task": "Create persistent systemd task. Schedule: daily HH:MM, hourly, or every N minutes/hours. kind=static with JSON payload {steps:[{tool:registered_tool_name,arguments:{...}}]} composed from fresh system context; kind=ai with natural-language prompt for a fresh plan on every run.",
    "provision_disk": "Format one provably blank whole disk as ext4, mount under /mnt, and persist by UUID in fstab. Requires exact destructive approval. Never use for an existing filesystem or partition.",
    "archive_create": "Create a timestamped 0600 tar.gz of source under an existing destination directory; returns archive path.",
    "create_tool": "Write or update any Python tool. Source must define run(args) and return a JSON-compatible result. Parameters is a JSON object schema encoded as a string. The tool becomes callable immediately under its chosen name. Generated code uses current OS privileges and requires interactive approval.",
    "inspect_tool": "List generated tools, or give name to read the source and schema of one tool for improvement.",
}

ENUMS = {"service_manager": {"action": ["status", "start", "stop", "restart", "reload", "enable", "disable", "is-active", "is-enabled"]},
         "package_manager": {"action": ["update", "install", "remove", "search", "query"]},
         "network_info": {"action": ["interfaces", "routes", "dns", "ports"]},
         "process_manager": {"action": ["top", "memory", "ports", "pid", "files"]},
         "log_reader": {"action": ["journal", "kernel", "service"]},
         "docker": {"action": ["info", "ps", "inspect", "logs", "images", "volumes", "pull", "run", "stop", "restart", "remove"]},
         "mount_manager": {"action": ["lsblk", "blkid", "findmnt", "mount", "umount"]},
         "schedule_task": {"kind": ["static", "ai"]}}


def validate(name: str, args: object) -> dict:
    if name not in SPECS:
        manifest = custom_tools.get(name)
        if not manifest:
            raise Rejected("Unknown tool")
        return custom_tools.validate_args(manifest["parameters"], args)
    if not isinstance(args, dict):
        raise Rejected("Unknown tool or invalid arguments")
    spec = SPECS[name]
    if set(args) - set(spec) or any(required and key not in args for key, (_, required) in spec.items()):
        raise Rejected("Unknown or missing tool argument")
    for key, value in args.items():
        if type(value) is not spec[key][0]:
            raise Rejected(f"Invalid argument type: {key}")
    return args


def schemas() -> list[dict]:
    mapping = {str: "string", int: "integer", bool: "boolean"}
    builtins = [{"type": "function", "function": {"name": name, "description": DESCRIPTIONS[name], "parameters": {
        "type": "object", "properties": {key: {"type": mapping[kind], **({"enum": ENUMS[name][key]} if key in ENUMS.get(name, {}) else {})} for key, (kind, _) in spec.items()},
        "required": [key for key, (_, required) in spec.items() if required], "additionalProperties": False}}} for name, spec in SPECS.items()]
    generated = [{"type": "function", "function": {"name": name, "description": item["description"], "parameters": item["parameters"]}}
                 for name, item in custom_tools.all_tools().items() if name not in SPECS]
    return builtins + generated


@contextmanager
def resource_lock(target: str):
    directory = state_dir() / "locks"
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    import hashlib
    path = directory / hashlib.sha256(target.encode()).hexdigest()
    with path.open("w") as handle:
        if os.name != "nt":
            import fcntl
            fcntl.flock(handle, fcntl.LOCK_EX)
        yield


def _file(path: str) -> Path:
    candidate = Path(path)
    if not candidate.is_absolute():
        raise Rejected("Absolute path required")
    if candidate.is_symlink():
        raise Rejected("Symbolic links are not writable")
    return candidate


def _backup(path: Path, db: Storage, run_id: str) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    dest = state_dir() / "backups" / f"{stamp}-{path.name}"
    dest.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    shutil.copy2(path, dest)
    db.backup(run_id, str(path), str(dest))
    return dest


def _validate_config(path: Path) -> dict:
    if str(path).startswith("/etc/nginx/"):
        return run(["nginx", "-t"], timeout=20)
    if str(path).startswith("/etc/ssh/"):
        return run(["sshd", "-t"], timeout=20)
    if path.suffix in {".service", ".timer"} and str(path).startswith("/etc/systemd/system/"):
        return run(["systemd-analyze", "verify", str(path)], timeout=20)
    return {"exit_code": 0, "stdout": "No native validator registered", "stderr": ""}


def _write(path: Path, content: str, backup: Path | None) -> dict:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, temp = tempfile.mkstemp(prefix=".sysai-", dir=path.parent)
    try:
        with os.fdopen(fd, "w") as stream:
            stream.write(content)
            stream.flush()
            os.fsync(stream.fileno())
        if path.exists():
            os.chmod(temp, path.stat().st_mode & 0o777)
            if hasattr(os, "chown"):
                os.chown(temp, path.stat().st_uid, path.stat().st_gid)
        else:
            os.chmod(temp, 0o600)
        os.replace(temp, path)
        result = _validate_config(path)
        if result["exit_code"] != 0:
            if backup:
                shutil.copy2(backup, path)
            else:
                path.unlink(missing_ok=True)
            return {"success": False, "validation": result, "rolled_back": True}
        return {"success": True, "validation": result, "backup": str(backup) if backup else None}
    finally:
        if os.path.exists(temp):
            os.unlink(temp)


def execute(name: str, args: dict, db: Storage, run_id: str, timeout: int = 120) -> dict:
    validate(name, args)
    if name not in SPECS:
        return custom_tools.execute(name, args, timeout)
    if name == "create_tool":
        return custom_tools.create(args["name"], args["description"], args["parameters"], args["source"], args.get("replace", False), set(SPECS))
    if name == "inspect_tool":
        return custom_tools.inspect(args.get("name"))
    if name == "shell_exec":
        cwd = args.get("cwd")
        if cwd is not None and (not Path(cwd).is_absolute() or not Path(cwd).is_dir()):
            raise Rejected("cwd must be an existing absolute directory")
        return run(parse_command(args["command"], args.get("shell", False)), min(args.get("timeout", timeout), timeout), cwd=cwd)
    if name in {"read_file", "list_directory", "file_stat"}:
        path = Path(args["path"])
        if not path.is_absolute():
            raise Rejected("Absolute path required")
        if secret_path(str(path)):
            raise Rejected("Sensitive file cannot be sent to model")
        if name == "read_file":
            with path.open("rb") as stream:
                data = stream.read(32769)
            return {"content": data[:32768].decode("utf-8", "replace"), "truncated": len(data) > 32768}
        if name == "list_directory":
            entries = sorted(p.name for p in path.iterdir())
            return {"entries": entries[:200], "truncated": len(entries) > 200}
        stat = path.stat()
        return {"size": stat.st_size, "mode": oct(stat.st_mode & 0o777), "uid": stat.st_uid, "gid": stat.st_gid, "mtime": stat.st_mtime}
    if name in {"write_file", "edit_file"}:
        path = _file(args["path"])
        with resource_lock(str(path)):
            if name == "write_file" and path.exists():
                raise Rejected("write_file creates new files only")
            if name == "edit_file" and not path.is_file():
                raise Rejected("edit_file requires existing regular file")
            before = path.read_text() if path.exists() else ""
            if name == "edit_file":
                if not args["old"] or before.count(args["old"]) != 1:
                    raise Rejected("Old text must occur exactly once")
                content = before.replace(args["old"], args["new"], 1)
            else:
                content = args["content"]
            if len(content.encode()) > 1024 * 1024:
                raise Rejected("File content too large")
            backup = _backup(path, db, run_id) if path.exists() else None
            return _write(path, content, backup)
    if name == "system_info":
        return {"static": discover(), "dynamic": dynamic_summary() if args.get("dynamic") else None}
    if name == "service_manager":
        action, service = args["action"], args["service"]
        if action not in {"status", "start", "stop", "restart", "reload", "enable", "disable", "is-active", "is-enabled"} or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@-]*", service):
            raise Rejected("Invalid service action/name")
        with resource_lock("service:" + service):
            return run(["systemctl", action, service], timeout)
    if name == "package_manager":
        action, package = args["action"], args.get("package", "")
        if action not in {"update", "install", "remove", "search", "query"} or (action != "update" and not re.fullmatch(r"[a-z0-9][a-z0-9+.-]+", package)):
            raise Rejected("Invalid package action/name")
        argv = {"update": ["apt-get", "update"], "install": ["apt-get", "install", "-y", package], "remove": ["apt-get", "remove", "-y", package],
                "search": ["apt-cache", "search", package], "query": ["dpkg-query", "-W", package]}[action]
        with resource_lock("apt"):
            return run(argv, max(timeout, 300) if action in {"update", "install", "remove"} else timeout)
    if name == "network_info":
        commands = {"interfaces": ["ip", "-j", "addr"], "routes": ["ip", "-j", "route"], "dns": ["cat", "/etc/resolv.conf"], "ports": ["ss", "-lntup"]}
        if args["action"] not in commands:
            raise Rejected("Invalid network action")
        return run(commands[args["action"]], timeout)
    if name == "process_manager":
        commands = {"top": ["ps", "aux", "--sort=-%cpu"], "memory": ["ps", "aux", "--sort=-%mem"], "ports": ["ss", "-lntup"]}
        if args["action"] == "pid" and args.get("pid", 0) > 0:
            return run(["ps", "-p", str(args["pid"]), "-o", "pid,comm,%cpu,%mem,stat"], timeout)
        if args["action"] == "files" and args.get("pid", 0) > 0:
            return run(["lsof", "-p", str(args["pid"])], timeout)
        if args["action"] not in commands:
            raise Rejected("Invalid process action")
        return run(commands[args["action"]], timeout)
    if name == "log_reader":
        lines = args.get("lines", 100)
        if not 1 <= lines <= 500 or args["action"] not in {"journal", "kernel", "service"}:
            raise Rejected("Invalid log request")
        argv = ["journalctl", "-n", str(lines), "--no-pager"]
        if args["action"] == "kernel":
            argv.append("-k")
        if args["action"] == "service":
            service = args.get("service", "")
            if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.@-]*", service):
                raise Rejected("Invalid service name")
            argv.extend(["-u", service])
        return run(argv, timeout)
    if name == "docker":
        action = args["action"]
        if action not in {"info", "ps", "inspect", "logs", "images", "volumes", "pull", "run", "stop", "restart", "remove"}:
            raise Rejected("Invalid docker action")
        name_arg, image = args.get("name", ""), args.get("image", "")
        if name_arg and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]*", name_arg) or image and not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_./:@-]*", image):
            raise Rejected("Invalid docker identifier")
        commands = {"info": ["docker", "info"], "ps": ["docker", "ps", "-a"], "images": ["docker", "images"], "volumes": ["docker", "volume", "ls"],
                    "inspect": ["docker", "inspect", "-f", "{{json .State}}", name_arg], "logs": ["docker", "logs", "--tail", "100", name_arg],
                    "pull": ["docker", "pull", image], "run": ["docker", "run", "-d", "--restart", "unless-stopped", "--name", name_arg],
                    "stop": ["docker", "stop", name_arg], "restart": ["docker", "restart", name_arg], "remove": ["docker", "rm", name_arg]}
        if action in {"inspect", "logs", "stop", "restart", "remove", "run"} and not name_arg or action in {"pull", "run"} and not image:
            raise Rejected("Missing docker identifier")
        if action == "run":
            host_port, container_port = args.get("host_port"), args.get("container_port")
            if (host_port is None) != (container_port is None):
                raise Rejected("Both port numbers are required")
            if host_port is not None:
                if not 1 <= host_port <= 65535 or not 1 <= container_port <= 65535:
                    raise Rejected("Invalid port")
                commands["run"].extend(["-p", f"{host_port}:{container_port}"])
            volume_target = args.get("volume_target")
            if volume_target:
                if not re.fullmatch(r"/[A-Za-z0-9_./-]+", volume_target) or ".." in volume_target.split("/") or volume_target == "/":
                    raise Rejected("Invalid volume target")
                commands["run"].extend(["-v", f"sysai-{name_arg}:{volume_target}"])
            commands["run"].append(image)
        with resource_lock("docker:" + (name_arg or image)):
            return run(commands[action], timeout)
    if name == "mount_manager":
        action = args["action"]
        if action in {"lsblk", "blkid", "findmnt"}:
            return run({"lsblk": ["lsblk", "-J", "-o", "NAME,PATH,SIZE,TYPE,FSTYPE,UUID,MOUNTPOINTS"], "blkid": ["blkid"], "findmnt": ["findmnt", "-J"]}[action], timeout)
        if action not in {"mount", "umount"} or not args.get("target", "").startswith("/"):
            raise Rejected("Invalid mount operation")
        target = args["target"]
        if action == "mount" and not args.get("source", "").startswith("/dev/"):
            raise Rejected("Mount source must be block device")
        with resource_lock("mount:" + target):
            return run(["mount", args["source"], target] if action == "mount" else ["umount", target], timeout)
    if name == "schedule_task":
        from .scheduler import create_task
        return create_task(db, args["description"], args["schedule"], args["kind"], args["payload"])
    if name == "provision_disk":
        from .disks import provision
        return provision(args["device"], args["expected_size_gb"], args["target"], db, run_id)
    if name == "archive_create":
        source, destination = Path(args["source"]), Path(args["destination"])
        if not source.is_absolute() or source == Path("/") or not source.exists() or not destination.is_absolute() or not destination.is_dir():
            raise Rejected("Archive source and existing destination directory must be absolute")
        with resource_lock("archive:" + str(destination)):
            stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
            archive = destination / f"{source.name}-{stamp}.tar.gz"
            fd = os.open(archive, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            os.close(fd)
            outcome = run(["tar", "-czf", str(archive), "-C", str(source.parent), "--", source.name], timeout=600)
            if outcome["exit_code"] != 0:
                archive.unlink(missing_ok=True)
            else:
                db.backup(run_id, str(source), str(archive))
            outcome["path"] = str(archive)
            return outcome
    raise Rejected("Unknown tool")
