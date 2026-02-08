from __future__ import annotations

import re
from typing import Iterable, List, Set

_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,7}\b", re.IGNORECASE)


def extract_cve_ids(text: str) -> List[str]:
    """
    텍스트에서 등장하는 CVE ID들을 추출(중복 제거, 정렬).
    """
    found = _CVE_RE.findall(text or "")
    norm: Set[str] = set()
    for c in found:
        norm.add(c.upper())
    return sorted(norm)


def contains_cve_id(text: str, cve_id: str) -> bool:
    """
    특정 CVE가 텍스트에 '정확하게' 포함되는지 확인.
    - 단순 substring보다 false positive 줄이기 위해 경계 포함 정규식 검사
    """
    if not text or not cve_id:
        return False
    target = cve_id.upper()
    if target not in text.upper():
        return False
    return bool(re.search(rf"\b{re.escape(target)}\b", text, flags=re.IGNORECASE))


def stable_join(lines: Iterable[str], sep: str = "\n") -> str:
    """
    해시/지문 생성 시 줄바꿈/공백 차이를 줄이기 위한 정규화용.
    """
    return sep.join([(l or "").rstrip() for l in lines])


def sha256_hex(data: bytes) -> str:
    import hashlib
    return hashlib.sha256(data).hexdigest()
