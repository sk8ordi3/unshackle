from __future__ import annotations

import logging
import time
from typing import Any, Callable, Optional

import requests

from unshackle.core.cacher import Cacher

CACHE_KEY = "ip_info_v2"
CACHE_TTL = 86400  # 24 hours
PROVIDER_STATE_KEY = "ip_provider_state"
RATE_LIMIT_COOLDOWN = 300  # 5 minutes
REQUEST_TIMEOUT = 10

Fetcher = Callable[[requests.Session], Optional[dict]]


class _RateLimited(Exception):
    """Raised by a provider fetcher when the upstream returns 429."""


def _empty() -> dict:
    return {
        "ip": "",
        "country": "",
        "country_code": "",
        "region": "",
        "city": "",
        "org": "",
        "asn": "",
        "as_name": "",
        "continent_code": "",
    }


def _parse_ipinfo_lite(data: dict) -> Optional[dict]:
    code = (data.get("country_code") or "").strip()
    if not code:
        return None
    asn = (data.get("asn") or "").strip()
    as_name = (data.get("as_name") or "").strip()
    org = f"{asn} {as_name}".strip() if (asn or as_name) else ""
    out = _empty()
    out.update(
        {
            "ip": data.get("ip") or "",
            "country": code.lower(),
            "country_code": code.upper(),
            "org": org,
            "asn": asn,
            "as_name": as_name,
            "continent_code": (data.get("continent_code") or "").upper(),
        }
    )
    return out


def _parse_ipinfo(data: dict) -> Optional[dict]:
    code = (data.get("country") or "").strip()
    if not code:
        return None
    out = _empty()
    out.update(
        {
            "ip": data.get("ip") or "",
            "country": code.lower(),
            "country_code": code.upper(),
            "region": data.get("region") or "",
            "city": data.get("city") or "",
            "org": data.get("org") or "",
        }
    )
    return out


def _parse_ip_api_in(data: dict) -> Optional[dict]:
    code = (data.get("country_code") or "").strip()
    if not code:
        return None
    asn = (data.get("asn") or "").strip()
    org_name = (data.get("organization") or "").strip()
    org = f"{asn} {org_name}".strip() if (asn or org_name) else ""
    out = _empty()
    out.update(
        {
            "ip": data.get("ip") or "",
            "country": code.lower(),
            "country_code": code.upper(),
            "region": data.get("region") or "",
            "city": data.get("city") or "",
            "org": org,
            "asn": asn,
            "as_name": org_name,
            "continent_code": (data.get("continent_code") or "").upper(),
        }
    )
    return out


def _check(response: requests.Response) -> Optional[dict]:
    """Raise _RateLimited on 429, return parsed JSON on 200, else None."""
    if response.status_code == 429:
        raise _RateLimited()
    if response.status_code != 200:
        return None
    try:
        return response.json()
    except ValueError:
        return None


def _fetch_ipinfo_lite(token: str) -> Fetcher:
    headers = {"Authorization": f"Bearer {token}"}

    def fetch(session: requests.Session) -> Optional[dict]:
        payload = _check(session.get("https://api.ipinfo.io/lite/me", headers=headers, timeout=REQUEST_TIMEOUT))
        return _parse_ipinfo_lite(payload) if payload else None

    return fetch


def _fetch_ipinfo(session: requests.Session) -> Optional[dict]:
    payload = _check(session.get("https://ipinfo.io/json", timeout=REQUEST_TIMEOUT))
    return _parse_ipinfo(payload) if payload else None


def _fetch_ip_api_in(session: requests.Session) -> Optional[dict]:
    """ip-api.in has no /me endpoint — resolve IP via ipify first, then look it up."""
    ip_resp = session.get("https://api.ipify.org", timeout=REQUEST_TIMEOUT)
    if ip_resp.status_code == 429:
        raise _RateLimited()
    if ip_resp.status_code != 200:
        return None
    ip = (ip_resp.text or "").strip()
    if not ip:
        return None
    payload = _check(session.get(f"https://ip-api.in/api/v1/ip/{ip}", timeout=REQUEST_TIMEOUT))
    if not payload or not payload.get("success"):
        return None
    return _parse_ip_api_in(payload.get("data") or {})


def _build_providers() -> list[tuple[str, Fetcher]]:
    """Return ordered (name, fetcher) pairs. Token read at call time."""
    from unshackle.core.config import config

    providers: list[tuple[str, Fetcher]] = []
    token = (getattr(config, "ipinfo_api_key", "") or "").strip()
    if token:
        providers.append(("ipinfo_lite", _fetch_ipinfo_lite(token)))
    providers.append(("ipinfo", _fetch_ipinfo))
    providers.append(("ip_api_in", _fetch_ip_api_in))
    return providers


def get_ip_info(
    session: Optional[requests.Session] = None,
    *,
    cached: bool = False,
) -> Optional[dict]:
    """
    Look up IP/geolocation info via ipinfo.io (Lite when `ipinfo_api_key` configured)
    with fallback to ip-api.in.

    Returns a normalized dict with keys: `ip`, `country` (lowercase ISO2),
    `country_code` (uppercase ISO2), `region`, `city`, `org`, `asn`, `as_name`,
    `continent_code`, and `_provider`. Returns None if every provider fails.

    Args:
        session: Optional requests session. If a proxied session is passed, the
            returned info reflects the proxy's exit IP. Auth headers for ipinfo
            are sent per-request; never mutated onto session.headers.
        cached: When True, read/write a 24h Cacher-backed entry. Use only for
            local IP lookups — never with a proxied session.
    """
    log = logging.getLogger("ip_info")

    if cached:
        cache = Cacher("global").get(CACHE_KEY)
        if cache and not cache.expired and cache.data:
            return cache.data
    else:
        cache = None

    state_cache = Cacher("global").get(PROVIDER_STATE_KEY)
    state: dict[str, Any] = (
        state_cache.data if state_cache and not state_cache.expired and isinstance(state_cache.data, dict) else {}
    )

    providers = _build_providers()
    now = time.time()

    def _cooldown_key(item: tuple[str, Fetcher]) -> int:
        info = state.get(item[0]) or {}
        return 1 if (now - info.get("rate_limited_at", 0)) < RATE_LIMIT_COOLDOWN else 0

    providers.sort(key=_cooldown_key)

    sess = session or requests.Session()

    for name, fetcher in providers:
        log.debug(f"Trying IP provider: {name}")
        try:
            normalized = fetcher(sess)
        except _RateLimited:
            log.warning(f"Provider {name} returned 429 (rate limited), trying next provider")
            entry = state.setdefault(name, {})
            entry["rate_limited_at"] = now
            entry["rate_limit_count"] = entry.get("rate_limit_count", 0) + 1
            state_cache.set(state, expiration=RATE_LIMIT_COOLDOWN)
            continue
        except Exception as e:
            log.debug(f"Provider {name} failed with exception: {e}")
            continue

        if not normalized:
            log.debug(f"Provider {name} returned no usable data")
            continue

        normalized["_provider"] = name
        log.debug(f"Successfully got IP info from provider: {name}")

        if name in state and state[name].pop("rate_limited_at", None) is not None:
            state_cache.set(state, expiration=RATE_LIMIT_COOLDOWN)

        if cached and cache is not None:
            cache.set(normalized, expiration=CACHE_TTL)

        return normalized

    log.warning("All IP geolocation providers failed")
    return None
