from __future__ import annotations

import os
import platform
import re
import shutil
import socket
from datetime import datetime, timezone
from pathlib import Path

from .runner import run


def discover() -> dict:
    release = {}
    path = Path("/etc/os-release")
    if path.exists():
        for line in path.read_text(errors="replace").splitlines():
            if "=" in line:
                key, value = line.split("=", 1)
                release[key] = value.strip('"')
    model = Path("/proc/device-tree/model")
    cpu = ""
    cpuinfo = Path("/proc/cpuinfo")
    if cpuinfo.exists():
        for line in cpuinfo.read_text(errors="replace").splitlines():
            if line.lower().startswith(("model name", "hardware", "processor")) and ":" in line:
                cpu = line.split(":", 1)[1].strip()[:160]
                if cpu:
                    break
    ram_kib = None
    meminfo = Path("/proc/meminfo")
    if meminfo.exists():
        match = re.search(r"MemTotal:\s+(\d+) kB", meminfo.read_text(errors="replace"))
        ram_kib = int(match.group(1)) if match else None
    net_dir = Path("/sys/class/net")
    interfaces = sorted(p.name for p in net_dir.iterdir()) if net_dir.exists() else []
    systemd = Path("/run/systemd/system").exists()
    network_manager = None
    if systemd:
        for service in ("NetworkManager", "systemd-networkd"):
            if run(["systemctl", "is-active", service], timeout=3)["stdout"].strip() == "active":
                network_manager = service
                break
    virt = run(["systemd-detect-virt"], timeout=3) if shutil.which("systemd-detect-virt") else None
    return {"timestamp": datetime.now(timezone.utc).isoformat(), "hostname": socket.gethostname(),
            "os": {"name": release.get("PRETTY_NAME", platform.system()), "version": release.get("VERSION_ID", "")},
            "architecture": platform.machine(), "kernel": platform.release(), "user": {"uid": os.geteuid() if hasattr(os, "geteuid") else -1, "name": os.environ.get("USER", ""), "sudo_installed": bool(shutil.which("sudo"))},
            "ssh_session": bool(os.environ.get("SSH_CONNECTION") or os.environ.get("SSH_TTY")),
            "cpu": cpu, "ram_kib": ram_kib, "interfaces": interfaces,
            "systemd": systemd, "package_manager": "apt-get" if shutil.which("apt-get") else None,
            "network_manager": network_manager, "virtualization": virt["stdout"].strip() if virt and virt["exit_code"] == 0 else None,
            "docker": bool(shutil.which("docker")), "board_model": model.read_bytes().replace(b"\0", b"").decode("utf-8", "replace")[:200] if model.exists() else None}


def dynamic_summary() -> dict:
    return {name: run(args, timeout=10, max_bytes=8000) for name, args in {
        "uptime": ["uptime"], "memory": ["free", "-h"], "filesystems": ["df", "-h"],
        "blocks": ["lsblk", "-o", "NAME,SIZE,TYPE,FSTYPE,MOUNTPOINTS"],
        "addresses": ["ip", "-j", "addr"], "routes": ["ip", "-j", "route"],
        "failed_services": ["systemctl", "--failed", "--no-pager"],
    }.items()}
