from __future__ import annotations

import os
import posixpath
import re
import shlex
import hashlib
from dataclasses import dataclass
from pathlib import Path
from .redact import redact


class Rejected(ValueError):
    """An unsafe or invalid tool request."""


READ_COMMANDS = {"df", "du", "free", "lsblk", "blkid", "findmnt", "ps", "uptime", "uname", "id", "whoami", "lspci", "lsusb", "sensors", "stat", "ls", "apt-cache", "dpkg-query", "ping", "wc", "date", "which", "type"}
SHELL_META = re.compile(r"[;&|><`$(){}\n\r\\]")
PROTECTED = ("/", "/boot", "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/var", "/home", "/root")
NETWORK_PATHS = ("/etc/ssh", "/etc/network", "/etc/netplan", "/etc/systemd/network", "/etc/NetworkManager", "/etc/nftables.conf", "/etc/iptables")
SECRET_PATHS = ("/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/environment", "/etc/ssl/private", "/etc/letsencrypt", "/root/.ssh", "/etc/ssh/ssh_host", "/var/lib/sysai")


def secret_path(path: str) -> bool:
    resolved = posixpath.normpath(path) if os.name == "nt" else os.path.realpath(path)
    parts = resolved.split("/")
    return (any(resolved == prefix or resolved.startswith(prefix + "/") or resolved.startswith(prefix + "_") for prefix in SECRET_PATHS)
            or any(part in {".ssh", ".aws", ".gnupg", "environ"} for part in parts)
            or resolved.endswith((".pem", ".key", ".env")))


def parse_command(command: str, shell: bool = False) -> list[str]:
    if not command or len(command) > 4096 or "\x00" in command:
        raise Rejected("Invalid command length or content")
    if shell:
        return ["bash", "-o", "pipefail", "-c", command]
    if SHELL_META.search(command):
        raise Rejected("Set shell=true for shell syntax")
    try:
        argv = shlex.split(command)
    except ValueError as exc:
        raise Rejected("Invalid command quoting") from exc
    if not argv or argv[0].startswith("-"):
        raise Rejected("Invalid executable")
    return argv


def parse_diagnostic(command: str) -> list[str]:
    return parse_command(command)


def classify_command(command: str, shell: bool = False) -> Decision:
    argv = parse_command(command, shell)
    if shell:
        if re.search(r"\b(?:mkfs(?:\.[a-z0-9]+)?|wipefs|dd|shred|sfdisk|sgdisk|blkdiscard|iptables|nft|netplan|rm)\b|\|\s*(?:sudo\s+)?(?:ba)?sh\b", command):
            return Decision(3, command, "Destructive shell expression")
        redirects = re.findall(r">{1,2}\s*(/[^\s;&|]+)", command)
        if any(network_path(path) or protected_path(path) for path in redirects):
            return Decision(3, command, "Protected shell redirection")
        return Decision(2, command, "Shell expression; review entire command")
    name = os.path.basename(argv[0])
    rest = argv[1:]
    if name == "sudo":
        return Decision(3, command, "Privileged command; review all arguments")
    if name in {"mkfs", "mkfs.ext4", "mkfs.xfs", "mkfs.btrfs", "wipefs", "dd", "shred", "fdisk", "sfdisk", "sgdisk", "parted", "cryptsetup", "blkdiscard", "lvremove", "vgremove", "reboot", "poweroff", "shutdown", "halt"}:
        return Decision(3, command, "Destructive or disruptive operation")
    if name == "find":
        return Decision(3 if any(x in rest for x in ("-delete", "-exec", "-execdir", "-ok", "-fprint", "-fprintf")) else 0, command, "Find filesystem entries")
    if name == "rsync" and any(x.startswith("--delete") for x in rest):
        return Decision(3, command, "Rsync deletion")
    if name in {"zfs", "zpool", "btrfs"} and any(x in rest for x in ("destroy", "delete", "remove")):
        return Decision(3, command, "Filesystem destruction")
    if name in {"bash", "sh", "python", "python3", "perl", "ruby"}:
        return Decision(3, command, "Arbitrary program")
    if name == "rm":
        targets = [x for x in rest if not x.startswith("-")]
        protected = any(x.startswith("/") and (protected_path(x) or any(x == p or x.startswith(p + "/") for p in PROTECTED if p != "/")) for x in targets)
        return Decision(3 if protected else 2, command, "Remove files")
    if name in {"chmod", "chown", "chgrp"}:
        recursive = any(x in {"-R", "--recursive"} or x.startswith("-R") for x in rest)
        protected = any(x.startswith("/") and (protected_path(x) or recursive and any(x.startswith(p + "/") for p in PROTECTED if p != "/")) for x in rest)
        return Decision(3 if protected else 2, command, "Change ownership or permissions")
    if name in {"iptables", "ip6tables", "nft", "ufw", "firewall-cmd", "netplan", "nmcli", "ifup", "ifdown", "route"}:
        return Decision(3, command, "Network change may interrupt SSH; automatic rollback unavailable")
    if name == "ip":
        if any(x in rest for x in ("add", "del", "delete", "replace", "flush", "set")):
            return Decision(3, command, "Network change may interrupt SSH; automatic rollback unavailable")
        readable = {"addr", "address", "link", "route", "neigh", "rule"}
        return Decision(0 if not rest or any(x in readable for x in rest) and not any(x in rest for x in ("exec", "monitor")) else 2, command, "Network diagnostic")
    if name == "systemctl":
        action = next((x for x in rest if not x.startswith("-")), "")
        if action in {"reboot", "poweroff", "halt", "rescue", "emergency"}:
            return Decision(3, command, "System state change")
        if action in {"status", "is-active", "is-enabled", "list-units", "show", "list-timers"} or "--failed" in rest:
            return Decision(0, command, "Service diagnostic")
        if any(any(word in x.lower() for word in ("ssh", "network", "firewall")) for x in rest):
            return Decision(3, command, "Service change may interrupt SSH; automatic rollback unavailable")
        return Decision(1 if action in {"start", "stop", "restart", "reload", "enable", "disable"} else 2, command, "Service change")
    if name in {"apt", "apt-get"}:
        action = next((x for x in rest if not x.startswith("-")), "")
        if any(x in rest for x in ("openssh-server", "network-manager", "netplan.io", "ufw", "nftables", "iptables")):
            return Decision(3, command, "Package may affect remote access")
        return Decision(1 if action in {"install", "update", "upgrade"} else 2 if action in {"remove", "purge", "autoremove", "full-upgrade", "dist-upgrade"} else 0 if action in {"search", "show", "list"} else 2, command, "Package operation")
    if name == "docker":
        action = next((x for x in rest if not x.startswith("-")), "")
        return Decision(0 if action in {"ps", "info", "inspect", "logs", "images", "stats", "version"} else 1 if action in {"pull", "start", "stop", "restart"} else 2, command, "Docker operation")
    if name == "journalctl":
        return Decision(2 if any(x.startswith(("--vacuum", "--rotate", "--flush", "--sync", "--relinquish", "--setup-keys")) for x in rest) else 0, command, "Journal operation")
    if name == "dmesg":
        return Decision(2 if any(x in rest for x in ("-C", "-c", "--clear", "--read-clear")) else 0, command, "Kernel log")
    if name == "ss":
        return Decision(2 if "-K" in rest else 0, command, "Socket inspection")
    if name == "ethtool":
        return Decision(0 if len(rest) == 1 or len(rest) == 2 and rest[0] in {"-i", "-S", "-k", "-a"} else 3, command, "Network adapter operation")
    if name == "smartctl":
        return Decision(0 if len(rest) == 2 and rest[0] in {"-a", "-H", "-i", "-x"} else 2, command, "SMART operation")
    if name == "iw":
        return Decision(0 if not any(x in rest for x in ("connect", "disconnect", "set", "del", "add")) else 3, command, "Wi-Fi operation")
    if name in {"cat", "head", "tail"} and any(secret_path(x) for x in rest if x.startswith("/")):
        raise Rejected("Sensitive file cannot be sent to model")
    if name in {"cat", "head", "tail"}:
        return Decision(0 if all(x.startswith("/") or x.startswith("-") for x in rest) else 2, command, "Read file")
    if name == "getent":
        return Decision(2 if "shadow" in rest or "gshadow" in rest else 0, command, "Identity lookup")
    if name in READ_COMMANDS or name in {"rfkill", "hostname"} and not rest:
        return Decision(0, command, "Diagnostic command")
    if name in {"mkdir", "touch", "cp", "mv", "tee"}:
        return Decision(3 if any(network_path(x) for x in rest if x.startswith("/")) else 2 if any(x.startswith(("/etc/", "/boot/", "/usr/")) for x in rest) else 1, command, "File change")
    return Decision(2, command, "Unrecognized Linux command; explicit review required")


def protected_path(path: str) -> bool:
    resolved = posixpath.normpath(path) if os.name == "nt" else os.path.realpath(path)
    return resolved in PROTECTED


def network_path(path: str) -> bool:
    resolved = posixpath.normpath(path) if os.name == "nt" else os.path.realpath(path)
    return any(resolved == prefix or resolved.startswith(prefix + "/") for prefix in NETWORK_PATHS)


@dataclass(frozen=True)
class Decision:
    level: int
    target: str
    description: str


def classify(tool: str, args: dict) -> Decision:
    if tool == "shell_exec":
        return classify_command(args["command"], args.get("shell", False))
    if tool in {"read_file", "list_directory", "file_stat", "system_info", "network_info", "process_manager", "log_reader"}:
        return Decision(0, str(args), "Диагностика")
    if tool == "service_manager":
        action = args["action"]
        service = args["service"].removesuffix(".service")
        level = 0 if action in {"status", "is-active", "is-enabled"} else 3 if service in {"ssh", "sshd", "NetworkManager", "systemd-networkd", "networking"} else 1
        description = f"systemctl {action}" + ("; SSH may disconnect; automatic rollback unavailable" if level == 3 else "")
        return Decision(level, args["service"], description)
    if tool == "package_manager":
        action = args["action"]
        critical = {"openssh-server", "network-manager", "systemd-networkd", "netplan.io", "ufw", "nftables", "iptables"}
        level = 0 if action in {"search", "query"} else 3 if args.get("package", "") in critical else 2 if action == "remove" else 1
        return Decision(level, args.get("package", "package index"), f"apt {action}")
    if tool == "mount_manager":
        action = args["action"]
        if action not in {"lsblk", "blkid", "findmnt"} and protected_path(args.get("target", "")):
            raise Rejected("Protected mount target")
        return Decision(0 if action in {"lsblk", "blkid", "findmnt"} else 2, args.get("target", ""), f"mount {action}")
    if tool == "docker":
        action = args["action"]
        return Decision(0 if action in {"info", "ps", "inspect", "logs", "images", "volumes"} else 2 if action in {"remove", "run"} else 1, args.get("name", args.get("image", "docker")), f"docker {action}")
    if tool in {"write_file", "edit_file"}:
        path = args["path"]
        if secret_path(path):
            raise Rejected("Sensitive file cannot be sent to model")
        if protected_path(path):
            raise Rejected("Protected directory cannot be overwritten")
        level = 3 if network_path(path) else 2 if path.startswith(("/etc/", "/boot/")) else 1
        return Decision(level, path, f"File {tool}" + ("; SSH may disconnect; automatic rollback unavailable" if level == 3 else ""))
    if tool == "schedule_task":
        target = args["description"]
        if args["kind"] == "static":
            from .scheduler import validate_plan
            plan = validate_plan(args["payload"])
            target += "; steps=" + ", ".join(step["tool"] + " " + str(step["arguments"]) for step in plan["steps"])
        return Decision(2, target, "Create persistent systemd task")
    if tool == "provision_disk":
        return Decision(3, args["device"], f"Format whole disk and mount at {args['target']}")
    if tool == "archive_create":
        return Decision(1, args["destination"], f"Archive {args['source']}")
    raise Rejected("Unknown tool")


def approve(decision: Decision, *, dry_run: bool, interactive: bool) -> bool:
    if dry_run or decision.level < 2:
        return True
    if not interactive:
        return False
    print(f"Риск {decision.level}: {decision.description}; объект: {redact(decision.target)}")
    target_token = decision.target if len(decision.target) <= 80 else hashlib.sha256(decision.target.encode()).hexdigest()[:12]
    expected = f"ПОДТВЕРЖДАЮ {target_token}"
    return input(f"Введите точно '{redact(expected)}': ").strip() == expected
