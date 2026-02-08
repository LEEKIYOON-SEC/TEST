from __future__ import annotations

from typing import List, Dict, Any

from .et_open import fetch_et_open_rule_hits
from .sigma_hq import fetch_sigma_hq_hits
from .yara_rules import fetch_yara_rules_hits
from .snort_community import fetch_snort_community_hits


def fetch_official_rules(cfg, cve_id: str) -> List[Dict[str, Any]]:
    """
    공식/공개 룰 수집(누락 방지 최우선):
      - ET Open (suricata + snort2)
      - SigmaHQ (sigma)
      - Yara-Rules (yara)
      - Snort Community (snort2) [옵션 URL이 있을 때]

    반환 포맷(표준):
      {
        "source": "ET_OPEN" | "SIGMAHQ" | "YARA_RULES" | "SNORT_COMMUNITY",
        "engine": "suricata" | "snort2" | "sigma" | "yara",
        "rule_path": "...",
        "rule_text": "...",
        "reference": "url :: path",
        "cve_ids": ["CVE-...."],
      }
    """
    hits: List[Dict[str, Any]] = []
    hits.extend(fetch_et_open_rule_hits(cfg, cve_id))
    hits.extend(fetch_sigma_hq_hits(cfg, cve_id))
    hits.extend(fetch_yara_rules_hits(cfg, cve_id))
    hits.extend(fetch_snort_community_hits(cfg, cve_id))

    # "검증된 공개룰은 전부 보내야" 원칙 때문에
    # 여기서는 축약/필터링 금지(라우팅/검증은 rules_bundle에서 처리)
    return hits
