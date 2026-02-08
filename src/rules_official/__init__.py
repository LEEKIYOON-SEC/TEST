from __future__ import annotations

from typing import List, Dict, Any

from .et_open import fetch_et_open_rule_hits
from .sigma_hq import fetch_sigma_hq_hits


def fetch_official_rules_phase1(cfg, cve_id: str) -> List[Dict[str, Any]]:
    """
    공식/공개 룰 1차 수집(누락 방지 우선):
      - ET Open (suricata + snort2)
      - SigmaHQ (sigma)

    반환 포맷(표준):
      {
        "source": "ET_OPEN" | "SIGMAHQ" | ...,
        "engine": "suricata" | "snort2" | "sigma" | ...,
        "rule_path": "...",          # 룰 파일 경로(원본 아카이브 내부 or repo zip 내부)
        "rule_text": "...",          # 룰 파일 전체 텍스트(복붙 목적)
        "reference": "url :: path",  # 취득 근거
        "cve_ids": ["CVE-...."],     # 매칭된 CVE 목록(현재는 대상 1개)
      }
    """
    hits: List[Dict[str, Any]] = []
    hits.extend(fetch_et_open_rule_hits(cfg, cve_id))
    hits.extend(fetch_sigma_hq_hits(cfg, cve_id))

    # 이 단계에서는 "공식 룰은 전부 보내야" 원칙 때문에
    # 여기서 임의 필터링/축약을 하지 않는다.
    return hits
