import re

PATTERNS = [
    (re.compile(r"(?i)(authorization\s*:\s*bearer\s+)\S+"), r"\1[REDACTED]"),
    (re.compile(r'(?i)((?:"|\')?(?:password|passwd|token|api[_-]?key|secret|cookie)(?:"|\')?\s*[:=]\s*)("[^"]*"|\'[^\']*\')'), r"\1[REDACTED]"),
    (re.compile(r"(?i)((?:password|passwd|token|api[_-]?key|secret)\s*[=:]\s*)\S+"), r"\1[REDACTED]"),
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----[\s\S]*?-----END [A-Z ]*PRIVATE KEY-----"), "[REDACTED PRIVATE KEY]"),
    (re.compile(r"(?i)(cookie\s*:\s*)[^\r\n]+"), r"\1[REDACTED]"),
]


def redact(value: str) -> str:
    for pattern, replacement in PATTERNS:
        value = pattern.sub(replacement, value)
    return value
