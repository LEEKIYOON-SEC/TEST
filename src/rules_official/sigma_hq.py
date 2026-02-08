from __future__ import annotations

import logging
from typing import Dict, Any, List

from ..http import http_get
from ..util.ziputil import iter_zip_text_files
from ..util.textutil import contains_cve_id

log = logging.getLogger("argus.rules.sigma_hq")

SIGMA_HQ_ZIP = "https://github.com/SigmaHQ/sigma/archive/refs/heads/master.zip"


def fetch_sigma_hq_hits(cfg, cve_id: str) -> List[Dict[str, Any]]:
    """
    SigmaHQ repo ZIP을 다운로드하여 CVE-ID가 포함된 룰(yml/yaml)을 전부 수집.
    - Sigma는 "무조건 제공" 정책이므로, 공식 Sigma 룰이 있으면 전부 제공 후보가 된다.
    """
    cve_id = cve_id.upper().strip()
    hits: List[Dict[str, Any]] = []

    try:
        blob = http_get(SIGMA_HQ_ZIP, timeout=180)
        scanned = 0
        for path, text in iter_zip_text_files(blob):
            if not path.endswith((".yml", ".yaml")):
                continue
            scanned += 1
            if contains_cve_id(text, cve_id):
                hits.append(
                    {
                        "source": "SIGMAHQ",
                        "engine": "sigma",
                        "rule_path": path,
                        "rule_text": text.strip() + "\n",
                        "reference": f"{SIGMA_HQ_ZIP} :: {path}",
                        "cve_ids": [cve_id],
                    }
                )
        log.info("SigmaHQ scanned=%d hits=%d", scanned, len(hits))
    except Exception as e:
        log.warning("SigmaHQ fetch/scan failed: %s", e)

    return hits
