from __future__ import annotations

import argparse
import getpass
import json
import os
import shutil
import sys
from pathlib import Path

from . import __version__
from .agent import Agent
from .config import Config, config_dir, save_key, state_dir
from .context import discover, dynamic_summary
from .llm import DeepSeekProvider, LLMError
from .scheduler import task_run
from .storage import Storage


def _agent(config: Config, db: Storage, args, *, interactive: bool = True) -> Agent:
    return Agent(DeepSeekProvider(config), config, db, dry_run=args.dry_run, interactive=interactive, debug=args.debug)


def _ask(agent: Agent, question: str) -> int:
    result = agent.ask(question)
    print(result.message)
    print(f"[{result.run_id}: {result.status}]")
    return 0 if result.status in {"success", "planned"} else 1


def _task_ai(agent: Agent, request: str) -> dict:
    result = agent.ask(request)
    return {"run_id": result.run_id, "message": result.message, "exit_code": 0 if result.status == "success" else 1}


def _tty_prompt(message: str) -> str:
    if os.name == "nt":
        return input(message)
    with open("/dev/tty", "r+") as terminal:
        terminal.write(message)
        terminal.flush()
        return terminal.readline().strip()


def setup_wizard() -> int:
    info = discover()
    print(f"SysAI setup | {info['os']['name']} | {info['architecture']}")
    print("Диагностические результаты и часть сведений о системе будут отправляться в DeepSeek API для анализа.")
    consent = _tty_prompt("Разрешить отправку этих данных в DeepSeek? Введите YES: ")
    if consent != "YES":
        print("Настройка отменена. Ключ не запрашивался и не сохранялся.")
        return 1
    key = getpass.getpass("DeepSeek API key (ввод скрыт): ").strip()
    if not key:
        raise ValueError("Empty API key")
    print("Проверяю API без отправки сведений о сервере...")
    response = DeepSeekProvider(Config.load(), key=key).complete([{"role": "user", "content": "Reply OK"}], [])
    if not response.get("content"):
        raise LLMError("API returned an empty response; key not saved")
    save_key(key)
    print(f"API: OK. Ключ сохранён в {config_dir() / 'deepseek.key'} (0600).")
    print("Готово. Запустите: sysai")
    return 0


def _tasks(db: Storage, parts: list[str], agent: Agent) -> int:
    if not parts:
        rows = db.db.execute("SELECT id,enabled,kind,schedule,description FROM scheduled_tasks ORDER BY id").fetchall()
        for row in rows:
            print(f"{row['id']:4} {'active' if row['enabled'] else 'disabled':8} {row['kind']:6} {row['schedule']:22} {row['description']}")
        return 0
    if len(parts) < 2 or not parts[1].isdigit():
        raise ValueError("Usage: sysai task show|run|enable|disable|delete|logs ID")
    action, task_id = parts[0], int(parts[1])
    row = db.db.execute("SELECT * FROM scheduled_tasks WHERE id=?", (task_id,)).fetchone()
    if not row:
        raise ValueError("Task not found")
    if action == "show":
        print(json.dumps(dict(row), ensure_ascii=False, indent=2))
    elif action == "logs":
        for item in db.db.execute("SELECT * FROM task_runs WHERE task_id=? ORDER BY id DESC LIMIT 20", (task_id,)):
            print(json.dumps(dict(item), ensure_ascii=False))
    elif action == "run":
        print(json.dumps(task_run(db, task_id, lambda request: _task_ai(agent, request)), ensure_ascii=False))
    elif action in {"enable", "disable"}:
        from .runner import run
        result = run(["systemctl", action, "--now", f"sysai-task-{task_id}.timer"])
        if result["exit_code"] != 0:
            raise RuntimeError(result["stderr"])
        db.db.execute("UPDATE scheduled_tasks SET enabled=? WHERE id=?", (int(action == "enable"), task_id))
        db.db.commit()
    elif action == "delete":
        from .runner import run
        timer = f"sysai-task-{task_id}.timer"
        run(["systemctl", "disable", "--now", timer])
        for suffix in ("timer", "service"):
            (Path("/etc/systemd/system") / f"sysai-task-{task_id}.{suffix}").unlink(missing_ok=True)
        run(["systemctl", "daemon-reload"])
        db.db.execute("DELETE FROM scheduled_tasks WHERE id=?", (task_id,))
        db.db.commit()
    else:
        raise ValueError("Unknown task action")
    return 0


def main(argv: list[str] | None = None) -> int:
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(errors="replace")
    parser = argparse.ArgumentParser(prog="sysai")
    parser.add_argument("--dry-run", action="store_true")
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("command", nargs="*")
    args = parser.parse_args(argv)
    parts = args.command
    command = parts[0] if parts else ""
    if command == "version":
        print(__version__)
        return 0
    if command == "setup":
        return setup_wizard()
    if command == "info":
        print(json.dumps({"static": discover(), "dynamic": dynamic_summary()}, ensure_ascii=False, indent=2))
        return 0
    if command == "config":
        print(json.dumps(Config.load().__dict__, ensure_ascii=False, indent=2))
        print("Config directory:", config_dir())
        return 0
    if command == "doctor":
        print(json.dumps({"python": sys.version.split()[0], "sysai": __version__, "state_dir": str(state_dir()),
                          "config_dir": str(config_dir()), "tools": {x: bool(shutil.which(x)) for x in ("systemctl", "apt-get", "docker", "ip", "lsblk")}}, indent=2))
        return 0
    if command == "update":
        if hasattr(os, "geteuid") and os.geteuid() != 0:
            raise RuntimeError("Run update as root: sudo sysai update")
        if len(parts) > 2:
            raise ValueError("Usage: sysai update [local-source-or-wheel]")
        source = str(Path(parts[1]).resolve()) if len(parts) == 2 else "https://github.com/v3trov/SysAI/archive/refs/heads/main.tar.gz"
        if len(parts) == 2 and not Path(source).exists():
            raise ValueError("Update source does not exist")
        executable = shutil.which("sysai")
        venv = Path(executable).resolve().parent.parent if executable else None
        pip = venv / "bin/pip" if venv else None
        if not pip or not pip.exists():
            raise RuntimeError("Update requires a virtualenv installation; reinstall from the new release")
        from .runner import run
        result = run([str(pip), "install", "--upgrade", source], timeout=300)
        print(result["stdout"] or result["stderr"])
        return 0 if result["exit_code"] == 0 else 1
    if command == "uninstall":
        if not (hasattr(os, "geteuid") and os.geteuid() == 0):
            raise RuntimeError("Run uninstall as root")
        link = Path("/usr/local/bin/sysai")
        if not link.is_symlink() or os.readlink(link) != "/opt/sysai/venv/bin/sysai":
            raise RuntimeError("Expected SysAI symlink not found; no files removed")
        link.unlink()
        shutil.rmtree("/opt/sysai/venv")
        print("Program removed. Configuration, history and backups retained.")
        return 0
    config = Config.load()
    db = Storage()
    agent = _agent(config, db, args, interactive=command != "task-run")
    if command == "history":
        for row in db.db.execute("SELECT id,started,status,request FROM runs ORDER BY started DESC LIMIT 30"):
            print(f"{row['id']} {row['started']} {row['status']} {row['request']}")
        return 0
    if command == "tasks":
        return _tasks(db, [], agent)
    if command == "task":
        return _tasks(db, parts[1:], agent)
    if command == "task-run":
        if len(parts) != 2 or not parts[1].isdigit():
            raise ValueError("Usage: sysai task-run ID")
        print(json.dumps(task_run(db, int(parts[1]), lambda request: _task_ai(agent, request)), ensure_ascii=False))
        return 0
    if command == "ask":
        if len(parts) < 2:
            raise ValueError("Usage: sysai ask QUESTION")
        return _ask(agent, " ".join(parts[1:]))
    if parts:
        return _ask(agent, " ".join(parts))
    info = discover()
    print(f"SysAI {__version__}\nHost: {info['hostname']}\nOS: {info['os']['name']}\nKernel: {info['kernel']}\nArch: {info['architecture']}")
    while True:
        try:
            question = input("sysai> ").strip()
        except (EOFError, KeyboardInterrupt):
            print()
            return 0
        if question.lower() in {"exit", "quit", "выход"}:
            return 0
        if question:
            _ask(agent, question)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (ValueError, RuntimeError, LLMError) as exc:
        print(f"SysAI: {exc}", file=sys.stderr)
        raise SystemExit(1) from None
