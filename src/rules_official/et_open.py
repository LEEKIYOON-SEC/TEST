from __future__ import annotations

import io
import tarfile
import logging
from dataclasses import dataclass
from typing import Dict, List, Any

from ..http import http_get
from ..util.textutil import contains_cve_id

log = logging.getLogger("argus.rules.et_open")


def _extract_tar_gz_rules(archive_bytes: bytes) -> Dict[str, str]:
    """
    tar.gz에서 *.rules 파일들을 추출해 {path: text} 반환.
    - decode 실패는 replace(누락 방지)
    """
    out: Dict[str, str] = {}
    with tarfile.open(fileobj=io.BytesIO(archive_bytes), mode="r:gz") as tf:
        for member in tf.getmembers():
            if not member.isfile():
                continue
            name = member.name
            if not name.endswith(".rules"):
                continue
            f = tf.extractfile(member)
            if not f:
                continue
            raw = f.read()
            try:
                text = raw.decode("utf-8")
            except Exception:
                text = raw.decode("utf-8", errors="replace")
            out[name] = text
    return out


def _find_hits_in_ruleset(
    *,
    source_name: str,
    engine: str,
    base_url: str,
    rules: Dict[str, str],
    cve_id: str,
) -> List[Dict[str, Any]]:
    hits: List[Dict[str, Any]] = []
    for path, text in rules.items():
        if contains_cve_id(text, cve_id):
            # "검증된 공개룰은 전부 보내야" → 파일 전체를 그대로 제공(복붙 목적)
            hits.append(
                {
                    "source": source_name,
                    "engine": engine,
                    "rule_path": path,
                    "rule_text": text.strip() + "\n",
                    "reference": f"{base_url} :: {path}",
                    "cve_ids": [cve_id],
                }
            )
    return hits


def fetch_et_open_rule_hits(cfg, cve_id: str) -> List[Dict[str, Any]]:
    """
    ET Open 룰셋:
      - Suricata 룰 tar.gz
      - Snort2 룰 tar.gz
    둘 다 내려받아 CVE-ID 포함된 룰 파일을 "전부" 수집.

    cfg:
      - ET_OPEN_SURICATA_URL
      - ET_OPEN_SNORT_URL
    """
    cve_id = cve_id.upper().strip()
    hits: List[Dict[str, Any]] = []

    # 1) Suricata 룰셋
    try:
        suri_url = cfg.ET_OPEN_SURICATA_URL
        blob = http_get(suri_url, timeout=120)
        files = _extract_tar_gz_rules(blob)
        hits.extend(
            _find_hits_in_ruleset(
                source_name="ET_OPEN",
                engine="suricata",
                base_url=suri_url,
                rules=files,
                cve_id=cve_id,
            )
        )
        log.info("ET Open suricata scanned=%d hits=%d", len(files), sum(1 for h in hits if h["engine"] == "suricata"))
    except Exception as e:
        log.warning("ET Open suricata fetch/scan failed: %s", e)

    # 2) Snort2 룰셋
    try:
        snort_url = cfg.ET_OPEN_SNORT_URL
        blob = http_get(snort_url, timeout=120)
        files = _extract_tar_gz_rules(blob)
        hits.extend(
            _find_hits_in_ruleset(
                source_name="ET_OPEN",
                engine="snort2",
                base_url=snort_url,
                rules=files,
                cve_id=cve_id,
            )
        )
        log.info("ET Open snort2 scanned=%d hits=%d", len(files), sum(1 for h in hits if h["engine"] == "snort2"))
    except Exception as e:
        log.warning("ET Open snort2 fetch/scan failed: %s", e)

    return hits
