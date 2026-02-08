from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import requests

log = logging.getLogger("argus.vulncheck")


@dataclass
class VulnCheckFinding:
    cve_id: str
    kind: str               # "weaponized" | "exploit" | "poc" | "advisory" | "other"
    title: str
    summary: str
    evidence: str           # LLM 입력용(정규화 텍스트)
    source: str             # "VulnCheck"
    raw: dict


def _clip(s: str, n: int) -> str:
    s = (s or "").strip()
    if len(s) <= n:
        return s
    return s[:n] + "…(truncated)"


def _headers(api_key: str) -> dict:
    # 가능한 인증 헤더를 동시에 제공(환경/스키마 차이에 대한 내성)
    return {
        "Authorization": f"Bearer {api_key}",
        "X-Api-Key": api_key,
        "Accept": "application/json",
        "User-Agent": "Argus-AI-Threat-Intelligence/1.0",
    }


def fetch_vulncheck_findings(cfg, cve_id: str, timeout: int = 35) -> List[VulnCheckFinding]:
    api_key = getattr(cfg, "VULNCHECK_API_KEY", None)
    if not api_key:
        return []

    cve_id = cve_id.upper().strip()
    base = getattr(cfg, "VULNCHECK_BASE_URL", "https://api.vulncheck.com/v3").rstrip("/")

    # best-effort endpoint. 환경별로 다를 수 있으므로 실패 시 빈 리스트.
    url = f"{base}/cves/{cve_id}"

    try:
        r = requests.get(url, headers=_headers(api_key), timeout=timeout)
        if r.status_code >= 400:
            log.info("VulnCheck fetch failed %s %s", r.status_code, r.text[:200])
            return []
        j = r.json()
    except Exception as e:
        log.info("VulnCheck request error: %s", e)
        return []

    raw = j if isinstance(j, dict) else {"data": j}

    title = str(raw.get("title") or raw.get("cve") or cve_id)
    summary = str(raw.get("summary") or raw.get("description") or "")

    weaponized = bool(raw.get("weaponized") or raw.get("isWeaponized") or raw.get("exploited") or False)
    kind = "weaponized" if weaponized else "other"

    # 룰 생성에 도움이 되는 "근거 중심 텍스트"로 변환
    lines: List[str] = []
    lines.append(f"- Source: VulnCheck")
    lines.append(f"- CVE: {cve_id}")
    lines.append(f"- Weaponized/Exploited flag (best-effort): {weaponized}")
    if summary:
        lines.append(f"- Summary: {_clip(summary, 1800)}")

    # 흔히 등장 가능한 필드 후보들을 최대한 텍스트화
    # URL만 나열하는 것이 아니라, title/type를 함께 붙여서 “언어적 근거”를 강화
    for key in ["exploits", "pocs", "references", "links", "sources", "timeline"]:
        val = raw.get(key)
        if isinstance(val, list) and val:
            lines.append(f"- {key}:")
            for it in val[:25]:
                if isinstance(it, str):
                    lines.append(f"  - {it}")
                elif isinstance(it, dict):
                    t = it.get("title") or it.get("name") or it.get("type") or "item"
                    u = it.get("url") or it.get("link") or ""
                    s = it.get("summary") or it.get("description") or ""
                    chunk = f"  - {t} {u}".strip()
                    lines.append(chunk)
                    if s:
                        lines.append(f"    - note: {_clip(str(s), 400)}")
            break

    evidence = "\n".join(lines).strip()

    return [
        VulnCheckFinding(
            cve_id=cve_id,
            kind=kind,
            title=title,
            summary=_clip(summary, 2200),
            evidence=evidence,
            source="VulnCheck",
            raw=raw,
        )
    ]
