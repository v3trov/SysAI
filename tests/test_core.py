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
from sysai.cli import setup_wizard
from sysai.context import discover
from sysai.disks import preflight
from sysai.llm import MockLLMProvider, DeepSeekProvider, LLMError
from sysai.redact import redact
from sysai.runner import run
from sysai.safety import Rejected, approve, classify, parse_command, protected_path, secret_path
from sysai.scheduler import parse_schedule, task_run, unit_text, validate_plan
from sysai.storage import Storage
from sysai.tools import execute, validate


class CoreTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        os.environ["SYSAI_STATE_DIR"] = self.temp.name
        self.db = Storage(Path(self.temp.name) / "test.db")
        self.addCleanup(self.db.db.close)

    def test_dangerous_commands_require_confirmation(self):
        for command in ("rm -rf /", "rm -rf /etc", "mkfs.ext4 /dev/sda1", "wipefs -a /dev/sda", "dd if=/dev/zero of=/dev/sda", "iptables -F", "nft flush ruleset", "ip route del default", "ethtool -K eth0 gro off"):
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
        self.assertEqual(classify("service_manager", {"action": "restart", "service": "sshd.service"}).level, 3)
        self.assertEqual(classify("package_manager", {"action": "install", "package": "htop"}).level, 1)
        self.assertEqual(classify("package_manager", {"action": "install", "package": "openssh-server"}).level, 3)
        disk = classify("provision_disk", {"device": "/dev/sdb", "expected_size_gb": 500, "target": "/mnt/storage"})
        self.assertEqual(disk.level, 3)
        self.assertFalse(approve(disk, dry_run=False, interactive=False))

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
        with self.assertRaises(Rejected):
            _parse_response({"tool_calls": [{"type": "function", "function": {"name": "shell_exec", "arguments": '{"command":"df","extra":1}'}}]})

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
