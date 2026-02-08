from __future__ import annotations

import os
import time
import logging
from typing import Optional, Dict

import requests

log = logging.getLogger("argus.http")

DEFAULT_UA = os.getenv("ARGUS_HTTP_USER_AGENT", "Argus-AI-Threat-Intelligence/1.0")
DEFAULT_TIMEOUT = float(os.getenv("ARGUS_HTTP_TIMEOUT", "35"))
DEFAULT_MAX_BYTES = int(os.getenv("ARGUS_HTTP_MAX_BYTES", str(4 * 1024 * 1024)))  # 4MB
DEFAULT_RETRIES = int(os.getenv("ARGUS_HTTP_RETRIES", "2"))
DEFAULT_BACKOFF = float(os.getenv("ARGUS_HTTP_BACKOFF", "0.8"))


def _merge_headers(headers: Optional[Dict[str, str]] = None) -> Dict[str, str]:
    h = {
        "User-Agent": DEFAULT_UA,
        "Accept-Encoding": "gzip, deflate",
        "Accept": "*/*",
    }
    if headers:
        for k, v in headers.items():
            if v is None:
                continue
            h[k] = v
    return h


def http_head(
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    headers: Optional[Dict[str, str]] = None,
    allow_redirects: bool = True,
) -> requests.Response:
    """
    HEAD 요청(리다이렉트 허용).
    - patch_intel에서 Content-Type 판단에 사용
    - 실패 시 예외를 던질 수 있음(호출부에서 처리)
    """
    h = _merge_headers(headers)
    r = requests.head(url, headers=h, timeout=timeout, allow_redirects=allow_redirects)
    r.raise_for_status()
    return r


def http_get(
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    headers: Optional[Dict[str, str]] = None,
    max_bytes: int = DEFAULT_MAX_BYTES,
    retries: int = DEFAULT_RETRIES,
    backoff: float = DEFAULT_BACKOFF,
    allow_redirects: bool = True,
) -> bytes:
    """
    안전한 GET:
    - gzip/deflate 지원
    - streaming으로 내려받으며 max_bytes 초과 시 차단(운영 안정성/DoS 방지)
    - 5xx/네트워크 오류에 대해 제한된 재시도(비용 0 + 안정성)
    """
    h = _merge_headers(headers)

    last_err: Optional[Exception] = None
    for attempt in range(retries + 1):
        try:
            with requests.get(
                url,
                headers=h,
                timeout=timeout,
                stream=True,
                allow_redirects=allow_redirects,
            ) as r:
                r.raise_for_status()

                # Content-Length가 과도하면 미리 차단
                cl = r.headers.get("Content-Length")
                if cl:
                    try:
                        if int(cl) > max_bytes:
                            raise ValueError(f"Response too large (Content-Length={cl} > max_bytes={max_bytes})")
                    except ValueError:
                        # Content-Length가 숫자가 아니거나 parse 실패면 그냥 streaming으로 제한
                        pass

                buf = bytearray()
                for chunk in r.iter_content(chunk_size=64 * 1024):
                    if not chunk:
                        continue
                    buf.extend(chunk)
                    if len(buf) > max_bytes:
                        raise ValueError(f"Response exceeded max_bytes={max_bytes} while downloading {url}")

                return bytes(buf)

        except Exception as e:
            last_err = e
            # 재시도 대상: 네트워크/5xx 계열이 대부분(raise_for_status 포함)
            if attempt < retries:
                sleep_s = backoff * (2 ** attempt)
                log.info("GET retry %d/%d for %s (sleep %.2fs) reason=%s", attempt + 1, retries, url, sleep_s, e)
                time.sleep(sleep_s)
                continue
            break

    # 최종 실패
    raise RuntimeError(f"http_get failed for {url}: {last_err}")
