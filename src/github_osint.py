from __future__ import annotations

import base64
import logging
from dataclasses import dataclass
from typing import List, Optional

import requests

from .http import http_get

log = logging.getLogger("argus.github_osint")


@dataclass
class GitHubFinding:
    cve_id: str
    kind: str        # "repo" | "code"
    title: str
    summary: str
    evidence: str    # LLM 입력용 정규화 텍스트
    raw_url: str     # HTML URL(참고용)
    api_url: str = ""  # GitHub API URL (code item일 때 유용)


def _clip(s: str, n: int) -> str:
    s = (s or "").strip()
    if len(s) <= n:
        return s
    return s[:n] + "…(truncated)"


def _headers(token: str) -> dict:
    return {
        "Authorization": f"Bearer {token}",
        "Accept": "application/vnd.github+json",
        "User-Agent": "Argus-AI-Threat-Intelligence/1.0",
    }


def search_repos_by_cve(cfg, cve_id: str, max_items: int = 5) -> List[GitHubFinding]:
    token = getattr(cfg, "GH_TOKEN", None)
    if not token:
        return []

    cve_id = cve_id.upper().strip()
    q = f'"{cve_id}" exploit OR poc OR proof-of-concept OR yara OR sigma OR snort OR suricata'
    url = "https://api.github.com/search/repositories"

    try:
        r = requests.get(url, headers=_headers(token), params={"q": q, "sort": "updated", "order": "desc"}, timeout=25)
        if r.status_code >= 400:
            log.info("GitHub repo search failed %s %s", r.status_code, r.text[:200])
            return []
        j = r.json()
    except Exception as e:
        log.info("GitHub repo search error: %s", e)
        return []

    items = j.get("items") or []
    out: List[GitHubFinding] = []

    for it in items[:max_items]:
        full = it.get("full_name") or it.get("name") or "repo"
        desc = it.get("description") or ""
        html = it.get("html_url") or ""
        evidence = "\n".join(
            [
                f"- Repository: {full}",
                f"- Description: {_clip(desc, 600)}",
                f"- Stars: {it.get('stargazers_count')}",
                f"- Updated: {it.get('updated_at')}",
                f"- Topics: {', '.join(it.get('topics') or [])}",
                f"- URL: {html}",
            ]
        ).strip()

        out.append(
            GitHubFinding(
                cve_id=cve_id,
                kind="repo",
                title=str(full),
                summary=_clip(desc, 900),
                evidence=evidence,
                raw_url=html,
                api_url=it.get("url") or "",
            )
        )

    return out


def search_code_by_cve(cfg, cve_id: str, max_items: int = 5) -> List[GitHubFinding]:
    """
    GitHub code search:
    - 결과에 포함된 api_url(= item.url)을 저장
    - 이후 enrich_code_findings_with_snippets()에서 실제 파일 내용 일부를 텍스트로 가져올 수 있게 함
    """
    token = getattr(cfg, "GH_TOKEN", None)
    if not token:
        return []

    cve_id = cve_id.upper().strip()
    q = f'"{cve_id}" (path:rules OR extension:rules OR extension:yml OR extension:yaml OR extension:yar OR extension:yara OR extension:lua)'
    url = "https://api.github.com/search/code"

    try:
        r = requests.get(url, headers=_headers(token), params={"q": q, "sort": "indexed", "order": "desc"}, timeout=25)
        if r.status_code >= 400:
            log.info("GitHub code search failed %s %s", r.status_code, r.text[:200])
            return []
        j = r.json()
    except Exception as e:
        log.info("GitHub code search error: %s", e)
        return []

    items = j.get("items") or []
    out: List[GitHubFinding] = []

    for it in items[:max_items]:
        name = it.get("name") or "file"
        path = it.get("path") or ""
        repo = (it.get("repository") or {}).get("full_name") or "repo"
        html = it.get("html_url") or ""
        api_url = it.get("url") or ""  # 중요: GitHub API file endpoint

        evidence = "\n".join(
            [
                f"- Repository: {repo}",
                f"- File: {path}",
                f"- Name: {name}",
                f"- URL: {html}",
                f"- API: {api_url}",
            ]
        ).strip()

        out.append(
            GitHubFinding(
                cve_id=cve_id,
                kind="code",
                title=f"{repo}/{path}",
                summary=f"{repo}/{path}",
                evidence=evidence,
                raw_url=html,
                api_url=api_url,
            )
        )

    return out


def _fetch_file_text_via_api(token: str, api_url: str, max_chars: int = 3500) -> str:
    """
    GitHub 'contents' 계열 API 응답(JSON)을 처리:
    - download_url이 있으면 그걸 다운로드(바이트 제한은 http_get에 의해 보장)
    - content(base64)이 있으면 decode
    """
    if not api_url:
        return ""

    try:
        r = requests.get(api_url, headers=_headers(token), timeout=25)
        if r.status_code >= 400:
            return f"(GitHub API fetch failed: {r.status_code})"
        j = r.json()
    except Exception as e:
        return f"(GitHub API error: {e})"

    # download_url 우선
    dl = j.get("download_url") if isinstance(j, dict) else None
    if isinstance(dl, str) and dl:
        try:
            raw = http_get(dl, timeout=25, max_bytes=512 * 1024)  # 512KB 제한
            try:
                txt = raw.decode("utf-8")
            except Exception:
                txt = raw.decode("utf-8", errors="replace")
            txt = txt.strip()
            if len(txt) > max_chars:
                txt = txt[:max_chars] + "\n...(truncated)"
            return txt
        except Exception as e:
            return f"(download_url fetch failed: {e})"

    # base64 content
    content = j.get("content") if isinstance(j, dict) else None
    enc = j.get("encoding") if isinstance(j, dict) else None
    if isinstance(content, str) and enc == "base64":
        try:
            raw = base64.b64decode(content.encode("utf-8"))
            try:
                txt = raw.decode("utf-8")
            except Exception:
                txt = raw.decode("utf-8", errors="replace")
            txt = txt.strip()
            if len(txt) > max_chars:
                txt = txt[:max_chars] + "\n...(truncated)"
            return txt
        except Exception as e:
            return f"(base64 decode failed: {e})"

    return "(No downloadable content in API response)"


def enrich_code_findings_with_snippets(
    cfg,
    findings: List[GitHubFinding],
    *,
    max_fetch: int = 2,
    snippet_max_chars: int = 3500,
) -> List[GitHubFinding]:
    """
    비용 0 / 레이트 제한 고려:
    - code findings 상위 max_fetch개에 대해서만 실제 파일 내용 일부를 가져와 evidence에 포함
    - LLM 웹검색 불가 전제에서 룰 정밀 타격에 직접 도움이 됨
    """
    token = getattr(cfg, "GH_TOKEN", None)
    if not token:
        return findings

    updated: List[GitHubFinding] = []
    fetched = 0
    for f in findings:
        if f.kind != "code" or fetched >= max_fetch:
            updated.append(f)
            continue

        snippet = _fetch_file_text_via_api(token, f.api_url, max_chars=snippet_max_chars)
        ev = f.evidence + "\n\n" + "File snippet (normalized, partial):\n" + "```\n" + snippet + "\n```"
        updated.append(
            GitHubFinding(
                cve_id=f.cve_id,
                kind=f.kind,
                title=f.title,
                summary=f.summary,
                evidence=ev,
                raw_url=f.raw_url,
                api_url=f.api_url,
            )
        )
        fetched += 1

    # 나머지 그대로
    if fetched < len(findings):
        for f in findings:
            if f.kind != "code":
                continue
    return updated


def build_github_section_text(findings: List[GitHubFinding]) -> str:
    if not findings:
        return "## GitHub OSINT (Discovery)\n- No GitHub findings in this run (or GH_TOKEN not set).\n"

    lines: List[str] = []
    lines.append("## GitHub OSINT (Discovery)")
    for f in findings[:10]:
        lines.append(f"- Kind: {f.kind} / Title: {f.title}")
        if f.summary:
            lines.append(f"  - Summary: {f.summary}")
        lines.append("  - Evidence:")
        for ln in f.evidence.splitlines():
            lines.append("    " + ln)
        lines.append("")
    return "\n".join(lines).strip() + "\n"
