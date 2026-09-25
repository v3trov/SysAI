from __future__ import annotations

import json
import os
import re
import shutil
import stat
import tempfile
from pathlib import Path

from .runner import run
from .safety import Rejected
from .storage import Storage
from .tools import resource_lock


def _node(device: str) -> dict:
    result = run(["lsblk", "-J", "-b", "-o", "PATH,SIZE,TYPE,FSTYPE,MOUNTPOINTS", device], timeout=15)
    if result["exit_code"] != 0 or result["truncated"]:
        raise Rejected("Cannot inspect block device")
    try:
        nodes = json.loads(result["stdout"])["blockdevices"]
        if len(nodes) != 1 or nodes[0]["path"] != device:
            raise ValueError
        return nodes[0]
    except (KeyError, IndexError, TypeError, ValueError, json.JSONDecodeError):
        raise Rejected("Unexpected lsblk response") from None


def preflight(device: str, expected_size_gb: int) -> dict:
    if not re.fullmatch(r"/dev/(?:sd[a-z]+|vd[a-z]+|xvd[a-z]+|nvme\d+n\d+|mmcblk\d+)", device):
        raise Rejected("Only a whole local block device can be provisioned")
    if not 1 <= expected_size_gb <= 1000000:
        raise Rejected("Invalid expected size")
    try:
        mode = os.stat(device).st_mode
    except OSError:
        raise Rejected("Block device is unavailable") from None
    if not stat.S_ISBLK(mode):
        raise Rejected("Target is not a block device")
    node = _node(device)
    if node.get("type") != "disk" or node.get("children") or node.get("fstype") or any(node.get("mountpoints") or []):
        raise Rejected("Device has partitions, filesystem or mounts")
    size = node.get("size")
    if type(size) is not int or abs(size / 1_000_000_000 - expected_size_gb) > expected_size_gb * 0.15:
        raise Rejected("Device size differs from expected size")
    signatures = run(["wipefs", "-n", device], timeout=15)
    if signatures["exit_code"] != 0 or signatures["stdout"].strip():
        raise Rejected("Device contains a signature or cannot be checked")
    blkid = run(["blkid", "-p", device], timeout=15)
    if blkid["exit_code"] != 2:
        raise Rejected("blkid found data or could not inspect device")
    return {"device": device, "size_bytes": size, "blank": True}


def provision(device: str, expected_size_gb: int, target: str, db: Storage, run_id: str) -> dict:
    if not hasattr(os, "geteuid") or os.geteuid() != 0:
        raise Rejected("Disk provisioning requires root")
    mountpoint = Path(target)
    if not re.fullmatch(r"/mnt/[A-Za-z0-9_./-]+", target) or ".." in mountpoint.parts or mountpoint.is_symlink() or not str(mountpoint.resolve(strict=False)).startswith("/mnt/"):
        raise Rejected("Mount point must be a direct path under /mnt")
    if mountpoint.exists() and (not mountpoint.is_dir() or any(mountpoint.iterdir())):
        raise Rejected("Mount point must be absent or empty")
    with resource_lock("disk:" + device), resource_lock("/etc/fstab"):
        before = preflight(device, expected_size_gb)
        mounted = run(["findmnt", "-rn", "-S", device], timeout=15)
        if mounted["exit_code"] == 0:
            raise Rejected("Device is mounted")
        fstab = Path("/etc/fstab")
        original = fstab.read_text()
        if any(target in line.split()[:2] for line in original.splitlines() if line.strip() and not line.lstrip().startswith("#")):
            raise Rejected("fstab already contains this mount point")
        if fstab.is_symlink():
            raise Rejected("Symlinked fstab is unsupported")
        probe_fd, probe_path = tempfile.mkstemp(prefix=".sysai-probe-", dir=fstab.parent)
        os.close(probe_fd)
        os.unlink(probe_path)
        backup_dir = Path("/var/lib/sysai/backups")
        backup_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
        backup = backup_dir / ("fstab-" + run_id)
        shutil.copy2(fstab, backup)
        db.backup(run_id, str(fstab), str(backup))
        mountpoint.mkdir(parents=True, exist_ok=True)
        formatted = run(["mkfs.ext4", "-F", "-q", device], timeout=600)
        if formatted["exit_code"] != 0:
            return {"success": False, "stage": "format", "detail": formatted}
        uuid_result = run(["blkid", "-s", "UUID", "-o", "value", device], timeout=15)
        uuid = uuid_result["stdout"].strip()
        if uuid_result["exit_code"] != 0 or not re.fullmatch(r"[A-Fa-f0-9-]{16,64}", uuid):
            return {"success": False, "stage": "uuid", "detail": uuid_result}
        if any(uuid in line for line in original.splitlines() if line.strip() and not line.lstrip().startswith("#")):
            return {"success": False, "stage": "fstab_conflict", "device_formatted": True, "uuid": uuid}
        line = f"UUID={uuid} {target} ext4 defaults,nofail 0 2\n"
        temporary = fstab.with_name(".fstab.sysai-" + run_id)
        try:
            mount_result = run(["mount", device, target], timeout=30)
            if mount_result["exit_code"] != 0:
                raise Rejected("Mount failed")
            final = run(["findmnt", "-n", "-o", "UUID", "--target", target], timeout=15)
            if final["exit_code"] != 0 or final["stdout"].strip() != uuid:
                raise Rejected("Mounted UUID differs from expected UUID")
            temporary.write_text(original.rstrip("\n") + "\n" + line)
            os.chmod(temporary, fstab.stat().st_mode & 0o777)
            os.chown(temporary, fstab.stat().st_uid, fstab.stat().st_gid)
            os.replace(temporary, fstab)
            validation = run(["findmnt", "--verify", "--tab-file", str(fstab)], timeout=30)
            if validation["exit_code"] != 0:
                raise Rejected("fstab validation failed")
            return {"success": True, "device": device, "size_bytes": before["size_bytes"], "uuid": uuid, "target": target, "fstab_backup": str(backup)}
        except Exception as exc:
            run(["umount", target], timeout=30)
            shutil.copy2(backup, fstab)
            return {"success": False, "stage": "mount_or_fstab", "error": str(exc), "fstab_rolled_back": True, "device_formatted": True, "uuid": uuid}
        finally:
            temporary.unlink(missing_ok=True)
