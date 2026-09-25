# SysAI architecture

The terminal owns the conversation. The controller sends a small, fresh system summary and registered JSON tool schemas to DeepSeek. A model response is either a registered tool call or a final answer. The controller validates the response, asks the independent safety engine for a decision, executes a bounded tool, redacts the observation, and repeats. Every mutation requires a subsequent read-only verification call before a successful final answer is accepted.

The trust boundaries are: untrusted user and machine output → model input; untrusted model output → strict protocol parser → registered tool → safety engine → Linux. The shell tool accepts general Linux commands. A simple command executes as argv without a shell. Pipelines, redirection and expansion require `shell=true`. Recognized deletion and formatting commands require approval. Typed tools remain available where useful. Arbitrary root code can bypass textual detection, so no deletion guarantee is possible.

Risk 0 runs automatically. Risk 1 and 2 are announced and run automatically. Risk 3 needs an exact object-specific approval. Dry run records the proposed action without changing state. Scheduled runs cannot provide interactive approval and therefore reject risk 3. Per-resource file locks serialize changes. File edits use a backup, atomic replacement, a native config validation where available, and rollback on validation failure. Network and SSH changes run automatically; timed rollback is unavailable.

SQLite stores run, call, task, task-run, and backup metadata; it is never considered authoritative for live system state. Systemd timers start separate `sysai task-run` processes. Static tasks run a model-composed, validated sequence of registered tools. AI tasks use the same controller and safety checks as interactive work.

No process runs persistently. The project uses Python's standard library to keep installation small on amd64, arm64 and armhf Debian-family systems.

Model-authored tools are stored as versioned Python source plus a manifest under the state directory. The source defines `run(args)` and the manifest supplies a JSON parameter schema. The controller exposes new schemas on the next model step without restarting, validates arguments, checks the source hash, and runs each tool in a timed child process. Registration and invocation run automatically. Source is shown when registered. A child process provides failure and timeout separation but does not limit what root code can access.
