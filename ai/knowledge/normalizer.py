import hashlib
import json
import re
from typing import Any


_SECRET_PATTERNS = [
    re.compile(r"(?i)(authorization\s*[:=]\s*)(?:bearer\s+)?[^\s,;]+"),
    re.compile(
        r"(?i)(\b(?:access[_-]?token|refresh[_-]?token|api[_-]?key|"
        r"client[_-]?secret|password|passwd|secret)\b\s*[:=]\s*)"
        r"[^\s,;]+"
    ),
    re.compile(r"(?i)(\b(?:cookie|set-cookie)\s*[:=]\s*)[^\r\n]+"),
]

_SENSITIVE_KEY_NAMES = {
    "authorization",
    "cookie",
    "setcookie",
    "xapikey",
    "apikey",
    "accesstoken",
    "refreshtoken",
    "clientsecret",
    "password",
    "passwd",
    "secret",
}


def _normalized_key(key: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


def sanitize_text(value: Any) -> str:
    """Convert a value to text and redact common credential/header formats."""
    text = str(value)
    for pattern in _SECRET_PATTERNS:
        text = pattern.sub(lambda match: match.group(1) + "[REDACTED]", text)
    return text


def sanitize_value(value: Any) -> Any:
    """Recursively sanitize strings and redact sensitive mapping keys."""
    if isinstance(value, str):
        return sanitize_text(value)
    if isinstance(value, dict):
        cleaned = {}
        for key, item in value.items():
            key_text = str(key)
            if _normalized_key(key) in _SENSITIVE_KEY_NAMES:
                cleaned[key_text] = "[REDACTED]"
            else:
                cleaned[key_text] = sanitize_value(item)
        return cleaned
    if isinstance(value, (list, tuple)):
        return [sanitize_value(item) for item in value]
    return value


def stable_document_id(document_type: str, source: str, source_reference: str) -> str:
    canonical = json.dumps(
        [document_type, source, source_reference],
        ensure_ascii=True,
        separators=(",", ":"),
    )
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:24]
    return f"{document_type}:{digest}"


def to_plain_dict(value: Any) -> dict[str, Any]:
    if hasattr(value, "model_dump"):
        result = value.model_dump(mode="json")
    elif isinstance(value, dict):
        result = value
    else:
        raise TypeError("Expected a Pydantic model or dictionary.")
    if not isinstance(result, dict):
        raise TypeError("Expected a dictionary-shaped assessment record.")
    return result
