from __future__ import annotations

import logging
import re
from dataclasses import dataclass
from typing import List

from bs4 import BeautifulSoup

from .http import http_get, http_head
from .pdf_text import extract_text_from_pdf_bytes

log = logging.getLogger("argus.patch_intel")


@dataclass
class PatchFinding:
    kind: str           # "vendor_advisory" | "release_note" | "patch" | "workaround" | "other"
    title: str
    url: str
    extracted_text: str


def _html_to_text(html: bytes, max_chars: int = 6500) -> str:
    try:
        soup = BeautifulSoup(html, "lxml")
        for tag in soup(["script", "style", "noscript"]):
            tag.decompose()
        text = soup.get_text(separator="\n")
        text = re.sub(r"\n{3,}", "\n\n", text)
        text = re.sub(r"[ \t]{2,}", " ", text)
        text = text.strip()
        if len(text) > max_chars:
            text = text[:max_chars] + "\n...(truncated)"
        return text
    except Exception:
        return ""


def _classify_url(url: str) -> str:
    u = (url or "").lower()

    if any(k in u for k in ["security", "advisory", "bulletin", "alert", "/cve", "psirt"]):
        return "vendor_advisory"
    if any(k in u for k in ["kb", "knowledgebase", "support", "documentation", "docs"]):
        return "vendor_advisory"
    if any(k in u for k in ["release", "releases", "changelog", "notes", "version", "upgrade"]):
        return "release_note"
    if any(k in u for k in ["patch", "download", "fix", "hotfix"]):
        return "patch"
    if any(k in u for k in ["workaround", "mitigation", "hardening"]):
        return "workaround"
    return "other"


def _priority_score(url: str) -> int:
    u = (url or "").lower()
    kind = _classify_url(url)

    if kind == "vendor_advisory":
        score = 0
    elif kind == "release_note":
        score = 10
    elif kind == "patch":
        score = 15
    elif kind == "workaround":
        score = 20
    else:
        score = 40

    # PDF는 이제 추출 가능하지만, 여전히 실패율이 있을 수 있어 약간의 패널티만 부여
    if u.endswith(".pdf"):
        score += 10

    if u.endswith((".zip", ".exe", ".msi", ".tar.gz")):
        score += 40

    if "psirt" in u:
        score -= 5
    if "security" in u:
        score -= 3
    if "cve" in u:
        score -= 2

    return max(score, 0)


def _is_pdf(url: str, content_type: str) -> bool:
    u = (url or "").lower()
    ct = (content_type or "").lower()
    return ("application/pdf" in ct) or u.endswith(".pdf")


def fetch_patch_findings_from_references(
    references: List[str],
    *,
    max_pages: int = 4,
    per_page_text_limit: int = 6500,
) -> List[PatchFinding]:
    """
    공식 패치/권고를 '가능하면 무조건' 확보하기 위한 수집기(PDF 추출 포함).
    - max_pages 제한 유지(운영 안정성)
    """
    out: List[PatchFinding] = []
    if not references:
        return out

    ranked = sorted(list(dict.fromkeys(references)), key=_priority_score)

    for url in ranked[:max_pages]:
        try:
            ctype = ""
            try:
                h = http_head(url, timeout=15)
                ctype = (h.headers.get("Content-Type") or "").lower()
            except Exception:
                ctype = ""

            if _is_pdf(url, ctype):
                # ✅ PDF 다운로드 후 텍스트 추출 (텍스트 레이어만)
                try:
                    pdf_bytes = http_get(url, timeout=45, max_bytes=6 * 1024 * 1024, headers={"Accept": "application/pdf"})
                    res = extract_text_from_pdf_bytes(pdf_bytes, max_pages=8, max_chars=7000)

                    if res.ok:
                        out.append(
                            PatchFinding(
                                kind=_classify_url(url),
                                title=f"PDF extracted ({res.pages} pages, text-layer)",
                                url=url,
                                extracted_text=res.text,
                            )
                        )
                    else:
                        out.append(
                            PatchFinding(
                                kind=_classify_url(url),
                                title="PDF detected but text extraction failed/empty",
                                url=url,
                                extracted_text=f"PDF detected. Text extraction result: {res.reason}",
                            )
                        )
                except Exception as e:
                    out.append(
                        PatchFinding(
                            kind=_classify_url(url),
                            title="PDF detected but download/extraction failed",
                            url=url,
                            extracted_text=f"PDF detected. Download/extraction failed: {e}",
                        )
                    )
                continue

            # HTML/TEXT 처리
            raw = http_get(
                url,
                timeout=40,
                max_bytes=4 * 1024 * 1024,
                headers={"Accept": "text/html,application/xhtml+xml,text/plain;q=0.9,*/*;q=0.8"},
            )
            text = _html_to_text(raw, max_chars=per_page_text_limit)
            if not text:
                continue

            kind = _classify_url(url)
            title = text.splitlines()[0][:200] if text.splitlines() else url
            out.append(PatchFinding(kind=kind, title=title, url=url, extracted_text=text))

        except Exception as e:
            log.info("patch page fetch failed: %s (%s)", url, e)
            continue

    return out


def build_patch_section_md(findings: List[PatchFinding]) -> str:
    lines: List[str] = []
    lines.append("## 7) Vendor Patch / Advisory (Best-effort)")
    if not findings:
        lines.append("- No patch/advisory text could be extracted from references in this run.")
        lines.append("- NOTE: Some vendor pages require JS rendering or authentication.")
        return "\n".join(lines).strip() + "\n"

    for i, f in enumerate(findings, 1):
        lines.append(f"### 7.{i} {f.kind} :: {f.title}")
        lines.append(f"- URL: {f.url}")
        lines.append("")
        lines.append("Extracted (normalized) text:")
        lines.append("```")
        lines.append(f.extracted_text)
        lines.append("```")
        lines.append("")
    return "\n".join(lines).strip() + "\n"
