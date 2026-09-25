# SysAI

SysAI is a local terminal agent for Debian, Ubuntu and Armbian administration over SSH. It uses DeepSeek tool calling, a guarded tool registry, live diagnostics, and backend verification.

Interactive answers use stable progress lines and formatted Markdown panels for headings, lists, code and tables. The prompt uses the terminal's native input and echo. Redirected output remains plain text without terminal control codes. Set `NO_COLOR=1` if you prefer a monochrome terminal.

## Supported systems and installation

Python 3.10+, systemd and apt are expected for full functionality. The code is architecture independent and targets amd64, arm64 and armhf. Install directly from this repository:

```bash
curl -fsSL https://raw.githubusercontent.com/v3trov/SysAI/main/install.sh | sudo sh
```

The installer shows five steps: system check, dependencies, source download, isolated installation, and private API setup. It downloads the repository archive over HTTPS, creates `/opt/sysai/venv` without modifying system Python, and places the command in `/usr/local/bin`. The setup wizard uses the terminal directly even when the installer is piped through `sh`. If installation completed but API setup was interrupted, run `sudo sysai setup`; there is no need to reinstall. To inspect the script before running it:

```bash
curl -fsSLo sysai-install.sh https://raw.githubusercontent.com/v3trov/SysAI/main/install.sh
less sysai-install.sh
sudo sh sysai-install.sh
```

## DeepSeek API and configuration

The default model is `deepseek-flash` at `https://api.deepseek.com`. During setup, SysAI explains which diagnostics are sent to DeepSeek, asks for explicit consent, accepts the API key through hidden terminal input, tests the key without sending server details, then stores it with mode 0600. The key never appears in a URL, command argument, shell history, or installation log. Run `sudo sysai setup` later if setup was skipped. The root key lives in `/etc/sysai/deepseek.key`; a regular user's setup uses `~/.config/sysai/deepseek.key`. System timers run as root. `DEEPSEEK_API_KEY` takes precedence. Optional `config.json` in the same directory:

```json
{"model":"deepseek-flash","base_url":"https://api.deepseek.com","max_iterations":30,"tool_timeout":120,"mode":"normal"}
```

DeepSeek's current [Chat Completions tool calling documentation](https://api-docs.deepseek.com/guides/tool_calls/) describes the API used here. The [change log](https://api-docs.deepseek.com/updates/) lists current model names.

## Use

```bash
sysai
sysai "Проверь состояние сервера"
sysai ask "Почему Docker не запускается?"
sysai --dry-run "Установи htop"
sysai --debug info
sysai info
sysai doctor
sysai history
```

The agent may take up to 30 model steps per request. Diagnostics and ordinary actions run without confirmation. Recognized deletion, formatting and disk destruction require the exact target-specific phrase at the terminal. `--dry-run` allows live diagnostics and records proposed mutations without executing them.

SysAI can write its own Python tools through `create_tool`. It supplies a name, description, JSON parameter schema and Python source defining `run(args)`, then can call the new tool in the same conversation. It can inspect and replace its tools later; they persist in `/var/lib/sysai/tools` for root and survive package updates. There is no fixed catalog of task-specific scripts. Generated tools have the invoking user's OS privileges and run automatically. Their source is displayed in the terminal when registered. They run in separate processes with timeouts, not a security sandbox.

Docker runs support a container name, image, optional TCP port mapping, and an optional named volume. The backend checks that the container is running and that a requested port binding exists.

## Safety and limits

The shell tool accepts general Linux commands. Simple commands run as argv. Pipelines, redirects and expansion require `shell=true`. The backend classifies known read operations, mutations and recognized destructive actions. Tool calls are validated before execution. Output is bounded and redacted before being sent to DeepSeek or stored. Config edits are backed up; native validation is used for nginx and systemd units. SQLite history lives in `/var/lib/sysai` for root or `~/.local/share/sysai` for other users. Resource locks serialize typed mutations.

Network and SSH changes can use the general command and file tools automatically. They lack automatic timed rollback, so console or out-of-band recovery should be available. The `provision_disk` tool handles only a whole blank disk with no partitions, signatures or mounts: it checks size, requires exact destructive approval, formats ext4, writes a backed-up UUID entry to `fstab`, and verifies the mount. Other storage workflows can use general Linux commands; recognized destructive commands require approval. The disk path has unit tests but has not been exercised on a spare physical disk; use a disposable VM before production use.

**Deletion protection is best effort.** Recognized remove, wipe and formatting commands require confirmation, but arbitrary shell commands and generated Python tools running as root can delete or overwrite data through code the classifier does not recognize. SysAI cannot guarantee that no data is deleted in this unrestricted mode. Keep recoverable backups or snapshots for valuable systems.

## Scheduled tasks

The `schedule_task` tool can create systemd timers for `daily HH:MM`, hourly, and fixed minute/hour intervals. The model creates a static task by composing registered tool calls into a validated JSON plan, or creates an AI task with a prompt that receives fresh system context on every run. There is no list of predefined backup or report scenarios. High-risk steps cannot run unattended. Results are stored in SQLite.

```bash
sysai tasks
sysai task show 1
sysai task run 1
sysai task logs 1
sysai task enable 1
sysai task disable 1
sysai task delete 1
```

Tasks run without an interactive approver, so high-risk actions are denied.

## Updating and uninstalling

Run `sudo sysai update` to reinstall the latest source from this GitHub repository, or `sudo sysai update /path/to/local/source` for a local build. Config, history and backups are outside the virtualenv and are retained. `sudo sysai uninstall` removes the executable and virtualenv while retaining state.

## Development and testing

```bash
python -m unittest discover -s tests -v
python -m compileall -q sysai
```

Tests use a mock LLM and require no DeepSeek key. See [architecture](docs/ARCHITECTURE.md) for trust boundaries and data flow.
