"""Helpers for masking secrets in text destined for logs or API responses."""

from __future__ import annotations

import re
from typing import Iterable, Optional
from urllib.parse import urlsplit, urlunsplit

REDACTED = "***"

# user:pass@ userinfo embedded in any URL (proxy URLs, remote server URLs)
URL_USERINFO_RE = re.compile(r"(?<=://)[^/@]+@")

# secret-bearing query parameters in URLs that end up in free text
SENSITIVE_QUERY_PARAM_RE = re.compile(r"(?i)\b(password|passwd|pwd|token|api_key|apikey|secret|auth)=([^&#\s\"']+)")


def redact_text(text: Optional[str], secrets: Iterable[str] = ()) -> Optional[str]:
    """
    Mask URL userinfo, secret-bearing query parameters, and any known secret
    strings inside a free-text value before it is logged or serialized.
    """
    if not isinstance(text, str) or not text:
        return text
    text = URL_USERINFO_RE.sub(f"{REDACTED}@", text)
    text = SENSITIVE_QUERY_PARAM_RE.sub(rf"\1={REDACTED}", text)
    # longest first so substrings don't survive partial replacement
    for secret in sorted({s for s in secrets if isinstance(s, str) and s}, key=len, reverse=True):
        text = text.replace(secret, REDACTED)
    return text


def safe_display_url(url: str) -> str:
    """Rebuild a URL from its scheme/host/port/path only, so userinfo can never be logged."""
    parts = urlsplit(url)
    netloc = parts.hostname or ""
    if parts.port:
        netloc += f":{parts.port}"
    return urlunsplit((parts.scheme, netloc, parts.path, "", ""))
