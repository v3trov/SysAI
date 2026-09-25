# SysAI architecture

The terminal owns the conversation. The controller sends a small, fresh system summary and registered JSON tool schemas to DeepSeek. A model response is either a registered tool call or a final answer. The controller validates the response, asks the independent safety engine for a decision, executes a bounded tool, redacts the observation, and repeats. Every mutation requires a subsequent read-only verification call before a successful final answer is accepted.

The trust boundaries are: untrusted user and machine output → model input; untrusted model output → strict protocol parser → registered tool → safety engine → Linux. The shell tool accepts general Linux commands. A simple command executes as argv without a shell. Pipelines, redirection and expansion require `shell=true` and explicit approval. Unknown commands default to high risk; known destructive commands and protected targets require destructive approval. Typed tools remain available where useful. Neither prompts nor model claims grant permission.

Risk 0 runs automatically. Risk 1 is announced. Risk 2 needs an exact interactive approval. Risk 3 needs an exact object-specific approval, even in expert mode. Dry run records the proposed action without changing state. Scheduled runs cannot provide interactive approval and therefore reject risk 2/3. Per-resource file locks serialize changes. File edits use a backup, atomic replacement, a native config validation where available, and rollback on validation failure. Network and SSH changes require destructive approval and warn that timed rollback is unavailable.

SQLite stores run, call, task, task-run, and backup metadata; it is never considered authoritative for live system state. Systemd timers start separate `sysai task-run` processes. Static tasks run a model-composed, validated sequence of registered tools. AI tasks use the same controller and safety checks as interactive work.

No process runs persistently. The project uses Python's standard library to keep installation small on amd64, arm64 and armhf Debian-family systems.
