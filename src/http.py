from __future__ import annotations

import time
import random
from typing import Optional, Dict, Any

import requests


class HttpError(RuntimeError):
    """Backwards-compatible error type for existing modules."""
    pass


def _sleep_backoff(attempt: int, base: float = 1.0, cap: float = 20.0) -> None:
    # exponential backoff + jitter
    t = min(cap, base * (2 ** attempt))
    t = t * (0.7 + random.random() * 0.6)
    time.sleep(t)


def http_get_json(
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, str]] = None,
    timeout: int = 25,
    max_retries: int = 4,
    retry_on_status: Optional[set[int]] = None,
) -> Any:
    """
    Compatibility wrapper expected by existing modules:
      from .http import http_get_json, HttpError

    - Retries on {429, 500, 502, 503, 504} by default
    - Retries on network errors
    - Returns parsed JSON
    """
    if retry_on_status is None:
        retry_on_status = {429, 500, 502, 503, 504}

    last_err: Optional[Exception] = None

    for attempt in range(max_retries + 1):
        try:
            r = requests.get(url, headers=headers, params=params, timeout=timeout)

            if r.status_code in retry_on_status:
                last_err = HttpError(f"GET {url} retryable status={r.status_code} body={r.text[:300]}")
                if attempt < max_retries:
                    ra = r.headers.get("Retry-After")
                    if ra:
                        try:
                            time.sleep(min(60, int(ra)))
                        except Exception:
                            _sleep_backoff(attempt)
                    else:
                        _sleep_backoff(attempt)
                    continue

            if r.status_code >= 400:
                raise HttpError(f"GET {url} failed status={r.status_code} body={r.text[:500]}")

            try:
                return r.json()
            except Exception as e:
                raise HttpError(f"GET {url} json parse failed: {e} body={r.text[:300]}")

        except (requests.RequestException, HttpError) as e:
            last_err = e
            if attempt < max_retries:
                _sleep_backoff(attempt)
                continue
            break

    raise HttpError(str(last_err))


# ---- Optional: keep the newer generic API too (for future modules) ----

def request_json(
    method: str,
    url: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    params: Optional[Dict[str, str]] = None,
    json: Optional[Any] = None,
    data: Optional[bytes] = None,
    timeout: int = 25,
    max_retries: int = 4,
    retry_on_status: Optional[set[int]] = None,
) -> Any:
    """
    Generic JSON request helper (used by newer modules).
    """
    if retry_on_status is None:
        retry_on_status = {429, 500, 502, 503, 504}

    last_err: Optional[Exception] = None

    for attempt in range(max_retries + 1):
        try:
            r = requests.request(
                method=method.upper(),
                url=url,
                headers=headers,
                params=params,
                json=json,
                data=data,
                timeout=timeout,
            )

            if r.status_code in retry_on_status:
                last_err = HttpError(f"{method} {url} retryable status={r.status_code} body={r.text[:300]}")
                if attempt < max_retries:
                    ra = r.headers.get("Retry-After")
                    if ra:
                        try:
                            time.sleep(min(60, int(ra)))
                        except Exception:
                            _sleep_backoff(attempt)
                    else:
                        _sleep_backoff(attempt)
                    continue

            if r.status_code >= 400:
                raise HttpError(f"{method} {url} failed status={r.status_code} body={r.text[:500]}")

            try:
                return r.json()
            except Exception as e:
                raise HttpError(f"{method} {url} json parse failed: {e} body={r.text[:300]}")

        except (requests.RequestException, HttpError) as e:
            last_err = e
            if attempt < max_retries:
                _sleep_backoff(attempt)
                continue
            break

    raise HttpError(str(last_err))
