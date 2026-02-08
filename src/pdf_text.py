from __future__ import annotations

import logging
from dataclasses import dataclass
from typing import Optional

from pypdf import PdfReader

log = logging.getLogger("argus.pdf_text")


@dataclass
class PDFExtractResult:
    ok: bool
    text: str
    pages: int
    reason: str


def extract_text_from_pdf_bytes(
    pdf_bytes: bytes,
    *,
    max_pages: int = 8,
    max_chars: int = 7000,
) -> PDFExtractResult:
    """
    비용 0 + GitHub Actions 환경 안정성을 최우선으로 하는 PDF 텍스트 추출기.
    - OCR 없음: 텍스트 레이어가 있는 PDF만 추출 가능
    - max_pages로 처리 비용 제한
    - max_chars로 Evidence Bundle 폭발 방지
    """
    if not pdf_bytes:
        return PDFExtractResult(ok=False, text="", pages=0, reason="empty_pdf_bytes")

    try:
        reader = PdfReader(io_bytes(pdf_bytes))
    except Exception as e:
        return PDFExtractResult(ok=False, text="", pages=0, reason=f"pdf_open_failed: {e}")

    total_pages = len(reader.pages)
    n = min(total_pages, max_pages)

    chunks = []
    extracted_any = False

    for i in range(n):
        try:
            page = reader.pages[i]
            t = page.extract_text() or ""
            t = t.strip()
            if t:
                extracted_any = True
                # 페이지 구분을 명확히 남김(감사/재현성)
                chunks.append(f"[Page {i+1}]\n{t}\n")
        except Exception:
            continue

    if not extracted_any:
        # 스캔 이미지 기반일 확률이 높음
        return PDFExtractResult(
            ok=False,
            text="",
            pages=n,
            reason="no_text_layer_detected_or_extraction_empty (likely scanned PDF; OCR disabled)",
        )

    full = "\n".join(chunks).strip()
    if len(full) > max_chars:
        full = full[:max_chars] + "\n...(truncated)"

    return PDFExtractResult(ok=True, text=full, pages=n, reason="ok")


def io_bytes(b: bytes):
    # pypdf가 file-like object를 받으므로 최소 래퍼 제공
    import io
    return io.BytesIO(b)
