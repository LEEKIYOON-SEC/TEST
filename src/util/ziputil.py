from __future__ import annotations

import io
import zipfile
from typing import Iterator, Tuple


def iter_zip_text_files(zip_bytes: bytes) -> Iterator[Tuple[str, str]]:
    """
    ZIP(blob)에서 텍스트 파일을 순회하며 (path, text) yield.
    - SigmaHQ, Yara-Rules 같은 repo zip에 사용
    - decode 실패는 errors="replace"로 진행(누락 방지)
    """
    with zipfile.ZipFile(io.BytesIO(zip_bytes), "r") as z:
        for info in z.infolist():
            if info.is_dir():
                continue
            path = info.filename
            with z.open(info, "r") as f:
                raw = f.read()
            try:
                text = raw.decode("utf-8")
            except Exception:
                text = raw.decode("utf-8", errors="replace")
            yield path, text


def write_zip(files: list[tuple[str, bytes]]) -> bytes:
    """
    메모리 상에서 ZIP 생성.
    files: [(path_in_zip, content_bytes), ...]
    """
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", compression=zipfile.ZIP_DEFLATED) as z:
        for path, content in files:
            z.writestr(path, content)
    return buf.getvalue()
