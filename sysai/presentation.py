"""Readable interactive terminal output, with plain text for pipes and logs."""

from __future__ import annotations

import re
import sys
from contextlib import contextmanager

from .redact import redact

try:
    from rich.console import Console
    from rich.markdown import Markdown
    from rich.panel import Panel
    from rich.rule import Rule
    from rich.syntax import Syntax
    from rich.text import Text
except ImportError:  # Source checkouts can still run without optional UI assets.
    Console = None


LABELS = {
    "system_info": "Система", "network_info": "Сеть", "process_manager": "Процессы",
    "log_reader": "Журналы", "service_manager": "Службы", "package_manager": "Пакеты",
    "read_file": "Чтение файла", "list_directory": "Каталог", "file_stat": "Свойства файла",
    "shell_exec": "Команда", "write_file": "Создание файла", "edit_file": "Изменение файла",
    "docker": "Docker", "mount_manager": "Диски", "schedule_task": "Расписание",
    "create_tool": "Новый инструмент", "inspect_tool": "Инструменты",
}

ESCAPE_SEQUENCE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07]*(?:\x07|\x1b\\))")


def safe_terminal_text(value: str) -> str:
    value = ESCAPE_SEQUENCE.sub("", value)
    return "".join(char for char in value if char in "\n\t" or ord(char) >= 32)


class TerminalUI:
    def __init__(self, *, debug: bool = False):
        self.debug = debug
        self.console = Console(highlight=False) if Console is not None else None
        self.interactive = bool(self.console and self.console.is_terminal and sys.stdout.isatty())
        self._status = None
        self._steps = 0

    def banner(self, version: str, info: dict) -> None:
        host = info.get("hostname", "unknown")
        os_name = info.get("os", {}).get("name", "Linux")
        kernel = info.get("kernel", "")
        arch = info.get("architecture", "")
        if not self.interactive:
            print(f"SysAI {version} | {host} | {os_name} | {kernel} | {arch}")
            return
        self.console.print(Rule(f"[bold cyan]SysAI {version}[/]", style="cyan"))
        self.console.print(Text(f"{host}  ·  {os_name}  ·  {kernel}  ·  {arch}", style="dim"))
        self.console.print()

    def prompt(self) -> str:
        if self.interactive:
            return self.console.input("[bold cyan]sysai[/] [dim]›[/] ")
        return input("sysai> ")

    def _start(self) -> None:
        if self.interactive and not self.debug and self._status is None:
            self._status = self.console.status("Анализирую запрос…", spinner="dots", spinner_style="cyan")
            self._status.start()

    def pause(self) -> None:
        if self._status is not None:
            self._status.stop()
            self._status = None

    def resume(self) -> None:
        self._start()

    @contextmanager
    def activity(self):
        self._steps = 0
        self._start()
        try:
            yield
        finally:
            self.pause()

    def progress(self, name: str, args: dict) -> None:
        self._steps += 1
        if not self.interactive or self.debug:
            return
        label = LABELS.get(name, name.replace("_", " "))
        target = args.get("action") or args.get("path") or args.get("command") or args.get("name") or ""
        target = safe_terminal_text(redact(str(target))).replace("\n", " ")[:64]
        self._start()
        self._status.update(Text(f"Шаг {self._steps}  ·  {label}" + (f"  ·  {target}" if target else "")))

    def code(self, name: str, source: str) -> None:
        self.pause()
        if self.interactive:
            self.console.print(Panel(Syntax(safe_terminal_text(redact(source)), "python", line_numbers=True, word_wrap=True),
                                     title=f"Код инструмента: {name}", border_style="yellow"))
        else:
            print(f"Код нового инструмента {name}:\n{safe_terminal_text(redact(source))}")

    def result(self, run_id: str, status: str, message: str) -> None:
        self.pause()
        message = safe_terminal_text(message)
        titles = {"success": ("Ответ", "cyan"), "planned": ("План", "yellow"),
                  "incomplete": ("Требует проверки", "yellow"), "failed": ("Ошибка", "red")}
        title, color = titles.get(status, ("Результат", "cyan"))
        if not self.interactive:
            print(message)
            print(f"[{run_id}: {status}]")
            return
        self.console.print(Panel(Markdown(message, code_theme="monokai"), title=title,
                                 title_align="left", border_style=color, padding=(1, 2)))
        self.console.print(Text(f"{run_id} · {status}", style="dim"))
        self.console.print()
