from __future__ import annotations

import subprocess
import time
from typing import Sequence


def run(argv: Sequence[str], timeout: int = 30, max_bytes: int = 32768, cwd: str | None = None) -> dict:
    start = time.monotonic()
    try:
        completed = subprocess.run(list(argv), capture_output=True, timeout=timeout, check=False, cwd=cwd)
        out, err = completed.stdout, completed.stderr
        return {"exit_code": completed.returncode, "stdout": out[:max_bytes].decode("utf-8", "replace"),
                "stderr": err[:max_bytes].decode("utf-8", "replace"), "truncated": len(out) > max_bytes or len(err) > max_bytes,
                "duration_ms": int((time.monotonic() - start) * 1000)}
    except subprocess.TimeoutExpired:
        return {"exit_code": None, "stdout": "", "stderr": "Timed out", "truncated": False,
                "duration_ms": int((time.monotonic() - start) * 1000)}
    except FileNotFoundError:
        return {"exit_code": None, "stdout": "", "stderr": f"Command unavailable: {argv[0]}", "truncated": False,
                "duration_ms": int((time.monotonic() - start) * 1000)}
