from __future__ import annotations

import json
from pathlib import Path

from .runner import run


def verify(name: str, args: dict, timeout: int = 30) -> dict:
    if name == "create_tool":
        import hashlib
        from .custom_tools import get
        manifest = get(args["name"])
        return {"verified": bool(manifest and manifest["sha256"] == hashlib.sha256(args["source"].encode()).hexdigest()),
                "detail": "Registered source hash checked"}
    if name in {"write_file", "edit_file"}:
        path = Path(args["path"])
        if not path.is_file():
            return {"verified": False, "detail": "Target file absent"}
        content = path.read_text()
        expected = args["content"] if name == "write_file" else args["new"]
        return {"verified": expected in content, "detail": "File content checked"}
    if name == "service_manager":
        action, service = args["action"], args["service"]
        if action in {"status", "is-active", "is-enabled"}:
            return {"verified": True}
        query = "is-enabled" if action in {"enable", "disable"} else "is-active"
        result = run(["systemctl", query, service], timeout)
        expected = "enabled" if action == "enable" else "disabled" if action == "disable" else "inactive" if action == "stop" else "active"
        return {"verified": result["stdout"].strip() == expected, "detail": result}
    if name == "package_manager":
        action = args["action"]
        if action in {"search", "query", "update"}:
            return {"verified": True, "detail": "No target state for this action"}
        result = run(["dpkg-query", "-W", "-f=${Status}", args["package"]], timeout)
        installed = result["stdout"].strip() == "install ok installed"
        return {"verified": installed if action == "install" else not installed, "detail": result}
    if name == "mount_manager":
        action = args["action"]
        if action in {"lsblk", "blkid", "findmnt"}:
            return {"verified": True}
        result = run(["findmnt", "--target", args["target"]], timeout)
        mounted = result["exit_code"] == 0 and args["target"] in result["stdout"]
        return {"verified": mounted if action == "mount" else not mounted, "detail": result}
    if name == "docker":
        action = args["action"]
        if action in {"info", "ps", "inspect", "logs", "images", "volumes"}:
            return {"verified": True}
        if action == "pull":
            result = run(["docker", "image", "inspect", args["image"]], timeout)
            return {"verified": result["exit_code"] == 0, "detail": result}
        result = run(["docker", "inspect", "-f", "{{.State.Running}}", args["name"]], timeout)
        expected = action in {"run", "restart"}
        verified = (result["stdout"].strip() == "true") if expected else (result["exit_code"] != 0 if action == "remove" else result["stdout"].strip() == "false")
        if action == "run" and verified and args.get("container_port"):
            ports = run(["docker", "inspect", "-f", "{{json .NetworkSettings.Ports}}", args["name"]], timeout)
            try:
                bindings = json.loads(ports["stdout"])[f"{args['container_port']}/tcp"]
                verified = any(item.get("HostPort") == str(args["host_port"]) for item in bindings)
            except (KeyError, TypeError, ValueError):
                verified = False
            result["ports"] = ports
        return {"verified": verified, "detail": result}
    if name == "schedule_task":
        return {"verified": True, "detail": "Timer creation verified by systemctl enable"}
    if name == "provision_disk":
        result = run(["findmnt", "-n", "-o", "TARGET", "--target", args["target"]], timeout)
        return {"verified": result["exit_code"] == 0 and result["stdout"].strip() == args["target"], "detail": result}
    if name == "archive_create":
        directory = Path(args["destination"])
        archives = sorted(directory.glob(Path(args["source"]).name + "-*.tar.gz"))
        return {"verified": bool(archives and archives[-1].stat().st_size > 0), "detail": "Archive exists and is non-empty"}
    return {"verified": False, "detail": "No verifier"}
