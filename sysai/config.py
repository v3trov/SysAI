from __future__ import annotations

import json
import os
import tempfile
from dataclasses import dataclass
from pathlib import Path


def state_dir() -> Path:
    root = hasattr(os, "geteuid") and os.geteuid() == 0
    return Path(os.environ.get("SYSAI_STATE_DIR", "/var/lib/sysai" if root else str(Path.home() / ".local/share/sysai")))


def config_dir() -> Path:
    root = hasattr(os, "geteuid") and os.geteuid() == 0
    return Path(os.environ.get("SYSAI_CONFIG_DIR", "/etc/sysai" if root else str(Path.home() / ".config/sysai")))


@dataclass(frozen=True)
class Config:
    model: str = "deepseek-flash"
    base_url: str = "https://api.deepseek.com"
    max_iterations: int = 30
    tool_timeout: int = 120
    mode: str = "normal"

    @classmethod
    def load(cls) -> Config:
        path = config_dir() / "config.json"
        data = json.loads(path.read_text()) if path.exists() else {}
        if not isinstance(data, dict) or set(data) - set(cls.__dataclass_fields__):
            raise ValueError("Invalid config keys")
        for key, kind in {"model": str, "base_url": str, "max_iterations": int, "tool_timeout": int, "mode": str}.items():
            if key in data and type(data[key]) is not kind:
                raise ValueError(f"Invalid config type: {key}")
        result = cls(**data)
        if result.mode not in {"normal", "expert"} or not 1 <= result.max_iterations <= 100 or not 1 <= result.tool_timeout <= 900:
            raise ValueError("Invalid config values")
        if not result.base_url.startswith("https://"):
            raise ValueError("API URL must use HTTPS")
        return result


def api_key() -> str:
    key = os.environ.get("DEEPSEEK_API_KEY")
    if key:
        return key
    path = config_dir() / "deepseek.key"
    if not path.exists():
        raise RuntimeError("Run `sysai setup` or set DEEPSEEK_API_KEY")
    if os.name != "nt" and path.stat().st_mode & 0o077:
        raise RuntimeError("API key file permissions must be 0600")
    return path.read_text().strip()


def save_key(key: str) -> None:
    directory = config_dir()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    path = directory / "deepseek.key"
    fd, temporary = tempfile.mkstemp(prefix=".deepseek-", dir=directory)
    try:
        os.chmod(temporary, 0o600)
        with os.fdopen(fd, "w") as stream:
            stream.write(key.strip() + "\n")
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)
