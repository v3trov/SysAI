"""Persistent tools written by the agent itself.

Each tool is a Python module with ``run(args)``. Modules run in a separate
process, but they have the invoking user's OS privileges; this is isolation
for timeouts and failures, not a security sandbox.
"""

from __future__ import annotations

import ast
import hashlib
import json
import os
import re
import subprocess
import sys
import tempfile
from pathlib import Path

from .config import state_dir
from .safety import Rejected


NAME = re.compile(r"[a-z][a-z0-9_]{1,63}\Z")
RUNNER = """import asyncio, contextlib, inspect, json, runpy, sys
with contextlib.redirect_stdout(sys.stderr):
    function = runpy.run_path(sys.argv[1])["run"]
    result = function(json.load(sys.stdin))
    if inspect.isawaitable(result):
        result = asyncio.run(result)
print(json.dumps({"result": result}, ensure_ascii=False, default=str))
"""


def tool_dir() -> Path:
    return state_dir() / "tools"


def _valid_schema(schema: object) -> dict:
    if not isinstance(schema, dict) or schema.get("type") != "object":
        raise Rejected("Tool parameters must be a JSON object schema")
    properties = schema.get("properties", {})
    required = schema.get("required", [])
    if not isinstance(properties, dict) or not all(isinstance(key, str) and isinstance(value, dict) for key, value in properties.items()):
        raise Rejected("Invalid tool parameter properties")
    if not isinstance(required, list) or not all(isinstance(key, str) and key in properties for key in required):
        raise Rejected("Invalid required parameters")
    return schema


def _validate_value(schema: dict, value: object, key: str) -> None:
    kinds = {"string": str, "integer": int, "number": (int, float), "boolean": bool, "object": dict, "array": list}
    kind = schema.get("type")
    if kind in kinds:
        if kind in {"integer", "number"} and type(value) is bool or not isinstance(value, kinds[kind]):
            raise Rejected(f"Invalid tool argument type: {key}")
    if "enum" in schema and value not in schema["enum"]:
        raise Rejected(f"Invalid tool argument value: {key}")
    if kind == "object":
        properties = schema.get("properties", {})
        for required in schema.get("required", []):
            if required not in value:
                raise Rejected(f"Missing tool argument: {key}.{required}")
        if schema.get("additionalProperties", True) is False and set(value) - set(properties):
            raise Rejected(f"Unknown tool argument: {key}")
        for child, item in value.items():
            if child in properties:
                _validate_value(properties[child], item, f"{key}.{child}")
    if kind == "array" and isinstance(schema.get("items"), dict):
        for index, item in enumerate(value):
            _validate_value(schema["items"], item, f"{key}[{index}]")


def validate_args(schema: dict, args: object) -> dict:
    if not isinstance(args, dict):
        raise Rejected("Tool arguments must be an object")
    _validate_value(schema, args, "arguments")
    return args


def get(name: str) -> dict | None:
    if not NAME.fullmatch(name):
        return None
    path = tool_dir() / f"{name}.json"
    if not path.is_file():
        return None
    try:
        manifest = json.loads(path.read_text())
        _valid_schema(manifest["parameters"])
        if manifest["name"] != name or not re.fullmatch(re.escape(name) + r"-[0-9a-f]{16}\.py", manifest["file"]):
            return None
        source_path = tool_dir() / manifest["file"]
        if not source_path.is_file() or hashlib.sha256(source_path.read_bytes()).hexdigest() != manifest["sha256"]:
            return None
        return manifest
    except (OSError, ValueError, KeyError, TypeError, Rejected):
        return None


def all_tools() -> dict[str, dict]:
    directory = tool_dir()
    if not directory.exists():
        return {}
    return {path.stem: manifest for path in sorted(directory.glob("*.json")) if (manifest := get(path.stem)) is not None}


def _atomic_write(path: Path, data: str) -> None:
    fd, temporary = tempfile.mkstemp(prefix=".sysai-tool-", dir=path.parent)
    try:
        os.chmod(temporary, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
            stream.write(data)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)


def create(name: str, description: str, parameters: str, source: str, replace: bool, reserved: set[str]) -> dict:
    if not NAME.fullmatch(name) or name in reserved:
        raise Rejected("Invalid or reserved tool name")
    if not description.strip() or len(description) > 2000 or not source.strip() or len(source.encode()) > 128 * 1024:
        raise Rejected("Invalid tool description or source size")
    try:
        schema = _valid_schema(json.loads(parameters))
        tree = ast.parse(source, filename=f"{name}.py")
        compile(tree, f"{name}.py", "exec")
    except (SyntaxError, ValueError, TypeError) as exc:
        raise Rejected(f"Invalid tool definition: {exc}") from None
    if not any(isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == "run" for node in tree.body):
        raise Rejected("Tool source must define run(args)")
    directory = tool_dir()
    directory.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(directory, 0o700)
    previous = get(name)
    if previous and not replace:
        raise Rejected("Tool already exists; set replace=true to update it")
    digest = hashlib.sha256(source.encode()).hexdigest()
    filename = f"{name}-{digest[:16]}.py"
    _atomic_write(directory / filename, source)
    manifest = {"name": name, "description": description, "parameters": schema, "file": filename, "sha256": digest}
    _atomic_write(directory / f"{name}.json", json.dumps(manifest, ensure_ascii=False))
    return {"success": True, "name": name, "sha256": digest, "replaced": bool(previous)}


def inspect(name: str | None = None) -> dict:
    if name is None:
        return {"tools": [{"name": item["name"], "description": item["description"], "sha256": item["sha256"]} for item in all_tools().values()]}
    manifest = get(name)
    if not manifest:
        raise Rejected("Tool not found")
    return {"name": name, "description": manifest["description"], "parameters": manifest["parameters"],
            "source": (tool_dir() / manifest["file"]).read_text(), "sha256": manifest["sha256"]}


def execute(name: str, args: dict, timeout: int) -> dict:
    manifest = get(name)
    if not manifest:
        raise Rejected("Tool not found")
    validate_args(manifest["parameters"], args)
    environment = os.environ.copy()
    environment.pop("DEEPSEEK_API_KEY", None)
    try:
        completed = subprocess.run([sys.executable, "-I", "-c", RUNNER, str(tool_dir() / manifest["file"])],
                                   input=json.dumps(args).encode(), capture_output=True, timeout=timeout, env=environment)
    except subprocess.TimeoutExpired:
        return {"exit_code": None, "error": "Custom tool timed out"}
    stdout = completed.stdout[:32768].decode("utf-8", "replace")
    stderr = completed.stderr[:8192].decode("utf-8", "replace")
    try:
        parsed = json.loads(stdout)
        result = parsed["result"] if isinstance(parsed, dict) and "result" in parsed else {"stdout": stdout}
    except json.JSONDecodeError:
        result = {"stdout": stdout}
    return {"exit_code": completed.returncode, "result": result, "stderr": stderr,
            "truncated": len(completed.stdout) > 32768 or len(completed.stderr) > 8192}
