import json
import io
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch
from contextlib import redirect_stdout

from sysai.agent import Agent, _parse_response
from sysai.config import Config
from sysai.custom_tools import get as get_custom_tool, tool_dir
from sysai.cli import setup_wizard
from sysai.context import discover
from sysai.disks import preflight
from sysai.llm import MockLLMProvider, DeepSeekProvider, LLMError
from sysai.presentation import Console, TerminalUI, safe_terminal_text
from sysai.redact import redact
from sysai.runner import run
from sysai.safety import Rejected, approve, classify, parse_command, protected_path, secret_path
from sysai.scheduler import parse_schedule, task_run, unit_text, validate_plan
from sysai.storage import Storage
from sysai.tools import execute, schemas, validate


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        os.environ["SYSAI_STATE_DIR"] = self.temp.name
        self.db = Storage(Path(self.temp.name) / "test.db")
        self.addCleanup(self.db.db.close)

    def test_dangerous_commands_require_confirmation(self):
        for command in ("rm -rf /", "rm -rf /etc", "mkfs.ext4 /dev/sda1", "wipefs -a /dev/sda", "dd if=/dev/zero of=/dev/sda", "iptables -F", "nft flush ruleset", "ip route del default"):
            with self.subTest(command=command):
                decision = classify("shell_exec", {"command": command})
                self.assertEqual(decision.level, 3)
                self.assertFalse(approve(decision, dry_run=False, interactive=False))
        with self.assertRaises(Rejected):
            parse_command("df; rm -rf /")
        self.assertEqual(classify("shell_exec", {"command": "df; rm -rf /", "shell": True}).level, 3)
        self.assertEqual(classify("shell_exec", {"command": "echo hi > /etc/ssh/sshd_config", "shell": True}).level, 3)

    def test_diagnostic(self):
        self.assertEqual(parse_command("ip route"), ["ip", "route"])
        self.assertEqual(classify("shell_exec", {"command": "df -h"}).level, 0)
        self.assertEqual(classify("shell_exec", {"command": "custom-admin-command --check"}).level, 2)
        self.assertEqual(classify("service_manager", {"action": "restart", "service": "sshd.service"}).level, 2)
        self.assertEqual(classify("package_manager", {"action": "install", "package": "htop"}).level, 1)
        self.assertEqual(classify("package_manager", {"action": "install", "package": "openssh-server"}).level, 2)
        disk = classify("provision_disk", {"device": "/dev/sdb", "expected_size_gb": 500, "target": "/mnt/storage"})
        self.assertEqual(disk.level, 3)
        self.assertFalse(approve(disk, dry_run=False, interactive=False))
        for command in ("nft list ruleset", "python3 -V", "tracepath example.com"):
            self.assertEqual(classify("shell_exec", {"command": command}).level, 0)
        self.assertEqual(classify("shell_exec", {"command": "python3 /tmp/check_ui.py"}).level, 2)
        self.assertEqual(classify("shell_exec", {"command": "rm /tmp/some-file"}).level, 3)
        self.assertEqual(classify("docker", {"action": "remove", "name": "some-container"}).level, 3)
        self.assertEqual(classify("package_manager", {"action": "remove", "package": "htop"}).level, 3)
        with patch("builtins.input", side_effect=AssertionError("No approval prompt expected")):
            self.assertTrue(approve(classify("shell_exec", {"command": "python3 /tmp/check_ui.py"}), dry_run=False, interactive=True))

    def test_protected(self):
        for path in ("/", "/etc", "/boot", "/root"):
            self.assertTrue(protected_path(path))
        self.assertFalse(protected_path("/tmp/sysai-test"))
        self.assertTrue(secret_path("/home/user/.ssh/id_rsa"))
        self.assertTrue(secret_path("/etc/ssl/private/server.key"))

    def test_schema(self):
        with self.assertRaises(Rejected):
            validate("shell_exec", {"command": "df", "unexpected": 1})
        with self.assertRaises(Rejected):
            validate("missing", {})
        with self.assertRaises(Rejected):
            _parse_response({"tool_calls": [{"type": "function", "function": {"name": "shell_exec", "arguments": "{"}}]})
        self.assertIn("Unknown or missing", _parse_response({"tool_calls": [{"id": "bad", "type": "function", "function": {"name": "shell_exec", "arguments": '{"command":"df","extra":1}'}}]})[1][0][3])
        self.assertEqual(validate("shell_exec", {"command": "df", "shell": "false"})["shell"], False)
        self.assertEqual(validate("shell_exec", {"command": "df", "shell": "TRUE"})["shell"], True)

    def test_deepseek_parser_rejects_truncated_response(self):
        class Response:
            def __enter__(self):
                return self
            def __exit__(self, *unused):
                return False
            def read(self, unused):
                return json.dumps({"choices": [{"finish_reason": "length", "message": {"content": "partial"}}]}).encode()
        with patch("sysai.llm.api_key", return_value="test-key"), patch("sysai.llm.urllib.request.urlopen", return_value=Response()):
            with self.assertRaises(LLMError):
                DeepSeekProvider(Config()).complete([{"role": "user", "content": "test"}], [])

    def test_runner_and_timeout(self):
        result = run([sys.executable, "-c", "print('ok')"], timeout=2)
        self.assertEqual(result["exit_code"], 0)
        self.assertIn("ok", result["stdout"])
        timeout = run([sys.executable, "-c", "import time; time.sleep(2)"], timeout=1)
        self.assertIsNone(timeout["exit_code"])

    def test_secret_redaction(self):
        self.assertNotIn("secret123", redact("Authorization: Bearer secret123"))
        self.assertNotIn("secret123", redact("password=secret123"))

    def test_setup_keeps_key_out_of_output_and_tests_before_save(self):
        os.environ["SYSAI_CONFIG_DIR"] = self.temp.name
        self.addCleanup(os.environ.pop, "SYSAI_CONFIG_DIR", None)
        output = io.StringIO()
        with patch("sysai.cli._tty_prompt", return_value="YES"), patch("sysai.cli.getpass.getpass", return_value="test-secret"), patch("sysai.cli.DeepSeekProvider.complete", return_value={"content": "OK"}), redirect_stdout(output):
            self.assertEqual(setup_wizard(), 0)
        self.assertNotIn("test-secret", output.getvalue())
        self.assertEqual((Path(self.temp.name) / "deepseek.key").read_text().strip(), "test-secret")

    def test_file_backup(self):
        file = Path(self.temp.name) / "config.txt"
        file.write_text("old")
        self.db.start("run1", "test")
        result = execute("edit_file", {"path": str(file), "old": "old", "new": "new"}, self.db, "run1")
        self.assertTrue(result["success"])
        self.assertEqual(file.read_text(), "new")
        self.assertEqual(Path(result["backup"]).read_text(), "old")

    def test_file_rollback_on_validation_failure(self):
        file = Path(self.temp.name) / "config.txt"
        file.write_text("old")
        self.db.start("run2", "test")
        with patch("sysai.tools._validate_config", return_value={"exit_code": 1, "stderr": "invalid"}):
            result = execute("edit_file", {"path": str(file), "old": "old", "new": "new"}, self.db, "run2")
        self.assertFalse(result["success"])
        self.assertTrue(result["rolled_back"])
        self.assertEqual(file.read_text(), "old")

    def test_docker_run_builds_bounded_args(self):
        args = {"action": "run", "name": "uptime-kuma", "image": "example/uptime-kuma:1", "host_port": 3001, "container_port": 3001, "volume_target": "/app/data"}
        with patch("sysai.tools.run", return_value={"exit_code": 0}) as mocked:
            execute("docker", args, self.db, "run1")
        argv = mocked.call_args.args[0]
        self.assertEqual(argv[0:3], ["docker", "run", "-d"])
        self.assertIn("3001:3001", argv)
        self.assertIn("sysai-uptime-kuma:/app/data", argv)

    def test_disk_preflight_rejects_existing_signature(self):
        lsblk = {"exit_code": 0, "truncated": False, "stdout": json.dumps({"blockdevices": [{"path": "/dev/sdb", "size": 500_000_000_000, "type": "disk", "fstype": None, "mountpoints": [None]}]})}
        with patch("sysai.disks.os.stat") as mocked_stat, patch("sysai.disks.run", side_effect=[lsblk, {"exit_code": 0, "stdout": "ext4 signature"}]):
            mocked_stat.return_value.st_mode = 0o060000
            with self.assertRaises(Rejected):
                preflight("/dev/sdb", 500)

    def test_disk_preflight_rejects_wrong_size(self):
        lsblk = {"exit_code": 0, "truncated": False, "stdout": json.dumps({"blockdevices": [{"path": "/dev/sdb", "size": 100_000_000_000, "type": "disk", "fstype": None, "mountpoints": [None]}]})}
        with patch("sysai.disks.os.stat") as mocked_stat, patch("sysai.disks.run", return_value=lsblk):
            mocked_stat.return_value.st_mode = 0o060000
            with self.assertRaises(Rejected):
                preflight("/dev/sdb", 500)

    def test_disk_preflight_accepts_only_blank_matching_disk(self):
        lsblk = {"exit_code": 0, "truncated": False, "stdout": json.dumps({"blockdevices": [{"path": "/dev/sdb", "size": 500_000_000_000, "type": "disk", "fstype": None, "mountpoints": [None]}]})}
        with patch("sysai.disks.os.stat") as mocked_stat, patch("sysai.disks.run", side_effect=[lsblk, {"exit_code": 0, "stdout": ""}, {"exit_code": 2, "stdout": ""}]):
            mocked_stat.return_value.st_mode = 0o060000
            self.assertTrue(preflight("/dev/sdb", 500)["blank"])

    def test_schedule(self):
        self.assertEqual(parse_schedule("Каждый день в 04:00"), "*-*-* 04:00:00")
        self.assertEqual(parse_schedule("Каждые 30 минут"), "*-*-* *:00/30:00")
        self.assertIn("OnCalendar=", unit_text(1, "daily")[1])

    def test_model_composed_static_plan(self):
        plan = {"steps": [{"tool": "shell_exec", "arguments": {"command": "df -h"}},
                          {"tool": "system_info", "arguments": {"dynamic": True}}]}
        self.assertEqual(len(validate_plan(json.dumps(plan))["steps"]), 2)
        self.db.db.execute("INSERT INTO scheduled_tasks (description,kind,schedule,payload) VALUES (?,?,?,?)", ("Check system", "static", "hourly", json.dumps(plan)))
        self.db.db.commit()
        with patch("sysai.tools.execute", return_value={"exit_code": 0, "stdout": "ok"}) as executor:
            result = task_run(self.db, 1, lambda unused: {})
        self.assertEqual(result["exit_code"], 0)
        self.assertEqual(executor.call_count, 2)
        dangerous = {"steps": [{"tool": "shell_exec", "arguments": {"command": "mkfs.ext4 /dev/sdb"}}]}
        with self.assertRaises(ValueError):
            validate_plan(json.dumps(dangerous))
        unverified = {"steps": [{"tool": "shell_exec", "arguments": {"command": "mkdir /tmp/sysai-test"}}]}
        with self.assertRaises(ValueError):
            validate_plan(json.dumps(unverified))

    def test_config_and_context(self):
        self.assertEqual(Config().mode, "normal")
        self.assertIn("hostname", discover())

    def test_agent_loop(self):
        replies = [
            {"tool_calls": [{"id": "a", "type": "function", "function": {"name": "system_info", "arguments": "{}"}}]},
            {"content": "Система проверена."},
        ]
        agent = Agent(MockLLMProvider(replies), Config(), self.db, interactive=False)
        result = agent.ask("Проверь состояние сервера")
        self.assertEqual(result.status, "success", result.message)
        self.assertIn("проверена", result.message)

    def test_agent_handles_multiple_tool_calls_in_one_reply(self):
        class RecordingProvider(MockLLMProvider):
            def complete(self, messages, tools):
                self.last_messages = list(messages)
                return super().complete(messages, tools)

        calls = [{"id": "first", "type": "function", "function": {"name": "system_info", "arguments": "{}"}},
                 {"id": "second", "type": "function", "function": {"name": "system_info", "arguments": '{"dynamic":true}'}}]
        provider = RecordingProvider([{"content": None, "tool_calls": calls}, {"content": "Проверка завершена."}])
        agent = Agent(provider, Config(), self.db, interactive=False)
        with patch("sysai.agent.execute", return_value={"exit_code": 0, "stdout": "ok"}) as executor:
            result = agent.ask("Проверь систему")
        self.assertEqual(result.status, "success")
        self.assertEqual(executor.call_count, 2)
        assistant = next(item for item in provider.last_messages if item["role"] == "assistant" and "tool_calls" in item)
        replies = [item for item in provider.last_messages if item["role"] == "tool"]
        self.assertEqual([call["id"] for call in assistant["tool_calls"]], ["first", "second"])
        self.assertEqual([reply["tool_call_id"] for reply in replies], ["first", "second"])

    def test_invalid_batch_is_rejected_before_any_tool_runs(self):
        calls = [{"id": "first", "type": "function", "function": {"name": "system_info", "arguments": "{}"}},
                 {"id": "second", "type": "function", "function": {"name": "missing", "arguments": "{}"}}]
        agent = Agent(MockLLMProvider([{"tool_calls": calls}, {"content": "Исправлю параметры."}]), Config(), self.db, interactive=False)
        with patch("sysai.agent.execute") as executor:
            result = agent.ask("Проверь систему")
        self.assertEqual(result.status, "success")
        executor.assert_not_called()

    def test_rejected_shell_syntax_is_returned_for_model_retry(self):
        class RecordingProvider(MockLLMProvider):
            def complete(self, messages, tools):
                self.last_messages = list(messages)
                return super().complete(messages, tools)

        bad = {"id": "bad", "type": "function", "function": {"name": "shell_exec", "arguments": '{"command":"df -h | tail -1"}'}}
        good = {"id": "good", "type": "function", "function": {"name": "shell_exec", "arguments": '{"command":"df -h"}'}}
        provider = RecordingProvider([{"tool_calls": [bad]}, {"tool_calls": [good]}, {"content": "Исправил вызов."}])
        agent = Agent(provider, Config(), self.db, interactive=False)
        with patch("sysai.agent.execute", return_value={"exit_code": 0, "stdout": "ok"}) as executor:
            result = agent.ask("Проверь диск")
        self.assertEqual(result.status, "success")
        executor.assert_called_once()
        replies = [item for item in provider.last_messages if item["role"] == "tool"]
        self.assertIn("Set shell=true", replies[0]["content"])
        self.assertEqual([item["tool_call_id"] for item in replies], ["bad", "good"])

    def test_string_boolean_tool_argument_does_not_abort_request(self):
        call = {"id": "check", "type": "function", "function": {"name": "shell_exec", "arguments": '{"command":"df -h","shell":"false"}'}}
        agent = Agent(MockLLMProvider([{"tool_calls": [call]}, {"content": "Диск проверен."}]), Config(), self.db, interactive=False)
        with patch("sysai.agent.execute", return_value={"exit_code": 0, "stdout": "ok"}) as executor:
            result = agent.ask("Проверь диск")
        self.assertEqual(result.status, "success")
        self.assertIs(executor.call_args.args[1]["shell"], False)

    def test_plain_output_has_no_terminal_escapes(self):
        output = io.StringIO()
        ui = TerminalUI()
        ui.interactive = False
        with redirect_stdout(output):
            ui.result("run_test", "success", "## Система\n\n- **SSH:** работает")
        self.assertIn("## Система", output.getvalue())
        self.assertNotIn("\x1b", output.getvalue())
        self.assertEqual(safe_terminal_text("ok\x1b[31mred\x1b[0m"), "okred")

    @unittest.skipIf(Console is None, "Rich is not installed in this test interpreter")
    def test_interactive_output_renders_markdown_panel(self):
        output = io.StringIO()
        ui = TerminalUI()
        ui.console = Console(file=output, force_terminal=True, color_system=None, width=72)
        ui.interactive = True
        ui.result("run_test", "success", "## Система\n\n- **SSH:** работает")
        rendered = output.getvalue()
        self.assertTrue("┌" in rendered or "╭" in rendered)
        self.assertIn("SSH", rendered)
        self.assertNotIn("**SSH**", rendered)

    def test_tool_execution_rejection_is_returned_for_model_retry(self):
        calls = [{"id": "bad", "type": "function", "function": {"name": "read_file", "arguments": '{"path":"/missing"}'}}]
        agent = Agent(MockLLMProvider([{"tool_calls": calls}, {"content": "Файл недоступен."}]), Config(), self.db, interactive=False)
        with patch("sysai.agent.execute", side_effect=Rejected("File unavailable")):
            result = agent.ask("Прочитай файл")
        self.assertEqual(result.status, "success")
        self.assertIn("Файл недоступен", result.message)

    def test_missing_file_is_returned_to_model(self):
        calls = [{"id": "missing", "type": "function", "function": {"name": "read_file", "arguments": '{"path":"/tmp/sysai-nonexistent-test-file"}'}}]
        agent = Agent(MockLLMProvider([{"tool_calls": calls}, {"content": "Файла нет; продолжаю проверку другим способом."}]), Config(), self.db, interactive=False)
        result = agent.ask("Проверь файл")
        self.assertEqual(result.status, "success")
        self.assertIn("Файла нет", result.message)

    def test_agent_creates_and_uses_new_python_tool(self):
        parameters = json.dumps({"type": "object", "properties": {"a": {"type": "integer"}, "b": {"type": "integer"}},
                                 "required": ["a", "b"], "additionalProperties": False})
        source = "def run(args):\n    return {'sum': args['a'] + args['b']}\n"
        create_args = {"name": "add_numbers", "description": "Add two integers", "parameters": parameters, "source": source}
        calls = [
            {"tool_calls": [{"id": "create", "type": "function", "function": {"name": "create_tool", "arguments": json.dumps(create_args)}}]},
            {"tool_calls": [{"id": "use", "type": "function", "function": {"name": "add_numbers", "arguments": '{"a":2,"b":3}'}}]},
            {"tool_calls": [{"id": "check", "type": "function", "function": {"name": "system_info", "arguments": "{}"}}]},
            {"content": "Сумма равна 5."},
        ]

        class RecordingProvider(MockLLMProvider):
            def complete(self, messages, tools):
                self.available.append({tool["function"]["name"] for tool in tools})
                return super().complete(messages, tools)

        provider = RecordingProvider(calls)
        provider.available = []
        agent = Agent(provider, Config(), self.db, interactive=True)
        with patch("sysai.agent.approve", return_value=True), patch("sysai.agent.discover", return_value={}), \
             patch("sysai.agent.execute", wraps=execute) as executor, redirect_stdout(io.StringIO()):
            result = agent.ask("Создай инструмент сложения и используй")
        self.assertEqual(result.status, "success", result.message)
        self.assertNotIn("add_numbers", provider.available[0])
        self.assertIn("add_numbers", provider.available[1])
        self.assertEqual(executor.call_count, 3)
        self.assertEqual(classify("add_numbers", {"a": 2, "b": 3}).level, 2)
        with self.assertRaises(Rejected):
            validate("add_numbers", {"a": 2, "b": "3"})
        self.assertIn("add_numbers", {tool["function"]["name"] for tool in schemas()})
        self.assertIn("sum", execute("add_numbers", {"a": 2, "b": 3}, self.db, "test")["result"])
        upgraded = dict(create_args, source="def run(args):\n    return {'sum': 2 * (args['a'] + args['b'])}\n", replace=True)
        self.assertTrue(execute("create_tool", upgraded, self.db, "test")["replaced"])
        self.assertEqual(execute("add_numbers", {"a": 2, "b": 3}, self.db, "test")["result"]["sum"], 10)
        version = get_custom_tool("add_numbers")
        (tool_dir() / version["file"]).write_text("def run(args):\n    return {'sum': 999}\n")
        self.assertNotIn("add_numbers", {tool["function"]["name"] for tool in schemas()})

    def test_dry_run_does_not_mutate(self):
        file = Path(self.temp.name) / "planned.txt"
        replies = [
            {"tool_calls": [{"id": "a", "type": "function", "function": {"name": "write_file", "arguments": json.dumps({"path": str(file), "content": "data"})}}]},
            {"content": "План готов."},
        ]
        agent = Agent(MockLLMProvider(replies), Config(), self.db, dry_run=True, interactive=False)
        result = agent.ask("Создай файл")
        self.assertEqual(result.status, "planned")
        self.assertFalse(file.exists())


if __name__ == "__main__":
    unittest.main()
