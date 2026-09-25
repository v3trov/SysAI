from __future__ import annotations

import json
import re
import shutil
from pathlib import Path

from .runner import run
from .redact import redact
from .storage import Storage, now


def parse_schedule(text: str) -> str:
    daily = re.search(r"(?:каждый день|ежедневно|daily).*?(\d{1,2}):(\d{2})", text, re.I)
    if daily:
        hour, minute = map(int, daily.groups())
        if hour > 23 or minute > 59:
            raise ValueError("Invalid time")
        return f"*-*-* {hour:02d}:{minute:02d}:00"
    interval = re.search(r"(?:каждые|every)\s+(\d+)\s*(минут|minutes?|час|hours?)", text, re.I)
    if interval:
        count = int(interval.group(1))
        unit = interval.group(2).lower()
        if not 1 <= count <= 1440:
            raise ValueError("Invalid interval")
        if unit.startswith(("мин", "min")):
            if 60 % count:
                raise ValueError("Minute interval must divide 60")
            return f"*-*-* *:00/{count}:00"
        if 24 % count:
            raise ValueError("Hour interval must divide 24")
        return f"*-*-* 00/{count}:00:00"
    hourly = re.search(r"(?:раз в час|каждый час|hourly)", text, re.I)
    if hourly:
        return "hourly"
    raise ValueError("Supported schedules: daily HH:MM, hourly, every N minutes/hours")


def unit_text(task_id: int, schedule: str, executable: str = "/usr/local/bin/sysai") -> tuple[str, str]:
    service = f"[Unit]\nDescription=SysAI task {task_id}\n[Service]\nType=oneshot\nExecStart={executable} task-run {task_id}\n"
    timer = f"[Unit]\nDescription=SysAI timer {task_id}\n[Timer]\nOnCalendar={schedule}\nPersistent=true\nUnit=sysai-task-{task_id}.service\n[Install]\nWantedBy=timers.target\n"
    return service, timer


def install_units(task_id: int, schedule: str) -> dict:
    if not Path("/run/systemd/system").exists():
        raise RuntimeError("systemd is unavailable")
    executable = shutil.which("sysai")
    if not executable or " " in executable:
        raise RuntimeError("sysai executable path unavailable")
    service, timer = unit_text(task_id, schedule, executable)
    directory = Path("/etc/systemd/system")
    service_path = directory / f"sysai-task-{task_id}.service"
    timer_path = directory / f"sysai-task-{task_id}.timer"
    service_path.write_text(service)
    timer_path.write_text(timer)
    for argv in (["systemd-analyze", "verify", str(service_path), str(timer_path)], ["systemctl", "daemon-reload"], ["systemctl", "enable", "--now", timer_path.name]):
        outcome = run(argv, timeout=30)
        if outcome["exit_code"] != 0:
            timer_path.unlink(missing_ok=True)
            service_path.unlink(missing_ok=True)
            run(["systemctl", "daemon-reload"], timeout=30)
            raise RuntimeError(outcome["stderr"] or "Failed to enable timer")
    return {"service": str(service_path), "timer": str(timer_path)}


def validate_plan(payload: str) -> dict:
    from .safety import classify
    from .tools import validate
    spec = json.loads(payload)
    if not isinstance(spec, dict) or set(spec) != {"steps"} or not isinstance(spec["steps"], list) or not 1 <= len(spec["steps"]) <= 20:
        raise ValueError("Static payload requires 1..20 steps")
    pending_shell = False
    for step in spec["steps"]:
        if not isinstance(step, dict) or set(step) != {"tool", "arguments"} or step["tool"] in {"schedule_task", "provision_disk"}:
            raise ValueError("Invalid scheduled step")
        validate(step["tool"], step["arguments"])
        level = classify(step["tool"], step["arguments"]).level
        if level >= 3:
            raise ValueError("Deletion and formatting cannot run unattended")
        if pending_shell and level > 0:
            raise ValueError("Mutating shell step needs a read-only verification step")
        pending_shell = step["tool"] == "shell_exec" and level > 0
    if pending_shell:
        raise ValueError("Static plan ends without verification")
    return spec


def create_task(db: Storage, description: str, schedule_text: str, kind: str, payload: str) -> dict:
    if kind not in {"static", "ai"}:
        raise ValueError("Invalid task kind")
    if kind == "static":
        spec = validate_plan(payload)
        payload = json.dumps(spec)
    schedule = parse_schedule(schedule_text)
    cursor = db.db.execute("INSERT INTO scheduled_tasks (description,kind,schedule,payload) VALUES (?,?,?,?)", (redact(description[:500]), kind, schedule, redact(payload[:2000])))
    task_id = cursor.lastrowid
    db.db.commit()
    try:
        units = install_units(task_id, schedule)
        return {"id": task_id, "schedule": schedule, **units}
    except Exception:
        db.db.execute("DELETE FROM scheduled_tasks WHERE id=?", (task_id,))
        db.db.commit()
        raise


def task_run(db: Storage, task_id: int, ai_runner) -> dict:
    row = db.db.execute("SELECT * FROM scheduled_tasks WHERE id=? AND enabled=1", (task_id,)).fetchone()
    if row is None:
        raise ValueError("Task does not exist or is disabled")
    try:
        if row["kind"] == "ai":
            result = ai_runner(row["payload"])
        else:
            from .safety import classify
            from .tools import execute, resource_lock, validate
            from .verify import verify
            spec = json.loads(row["payload"])
            observations = []
            pending_shell = False
            for step in spec["steps"]:
                name, arguments = step["tool"], step["arguments"]
                validate(name, arguments)
                decision = classify(name, arguments)
                if name in {"schedule_task", "provision_disk"} or decision.level > 1 or pending_shell and decision.level > 0:
                    raise ValueError("Scheduled step became unsafe")
                if decision.level > 0:
                    with resource_lock("global-mutation"):
                        output = execute(name, arguments, db, f"task_{task_id}")
                else:
                    output = execute(name, arguments, db, f"task_{task_id}")
                if output.get("exit_code", 0) != 0 or output.get("success", True) is False:
                    observations.append({"tool": name, "result": output})
                    result = {"exit_code": 1, "steps": observations}
                    break
                if name == "shell_exec" and decision.level > 0:
                    pending_shell = True
                elif decision.level == 0 and pending_shell:
                    pending_shell = False
                elif decision.level > 0:
                    check = verify(name, arguments)
                    output["verification"] = check
                    if not check["verified"]:
                        observations.append({"tool": name, "result": output})
                        result = {"exit_code": 1, "steps": observations}
                        break
                observations.append({"tool": name, "result": output})
            else:
                result = {"exit_code": 1 if pending_shell else 0, "steps": observations}
        status = "success" if result.get("exit_code", 0) == 0 else "failed"
    except Exception as exc:
        result, status = {"error": str(exc)}, "failed"
    db.db.execute("INSERT INTO task_runs (task_id,timestamp,status,result) VALUES (?,?,?,?)", (task_id, now(), status, json.dumps(result)[:35000]))
    db.db.commit()
    return result
