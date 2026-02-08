# src/rules_official/__init__.py
from __future__ import annotations

from typing import List, Dict, Any

__all__ = ["fetch_official_rules"]


def fetch_official_rules(cfg, cve_id: str) -> List[Dict[str, Any]]:
    """
    Official/Public rules aggregator.
    main.py expects:
      from .rules_official import fetch_official_rules
    so this symbol MUST exist at package top-level.
    """
    hits: List[Dict[str, Any]] = []

    def _safe_extend(src):
        if not src:
            return
        if isinstance(src, list):
            for x in src:
                if isinstance(x, dict):
                    hits.append(x)

    def _norm(engine: str) -> str:
        e = (engine or "").strip().lower()
        if e in ("suricata", "suri"):
            return "suricata"
        if e in ("snort", "snort2"):
            return "snort2"
        if e in ("snort3",):
            return "snort3"
        if e in ("sigma",):
            return "sigma"
        if e in ("yara",):
            return "yara"
        return e or "unknown"

    def _dedup(items: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        seen = set()
        out = []
        for h in items:
            h["engine"] = _norm(h.get("engine"))
            key = (
                h.get("engine"),
                (h.get("source") or "").strip(),
                (h.get("rule_path") or "").strip(),
                (h.get("reference") or "").strip(),
            )
            if key in seen:
                continue
            seen.add(key)
            out.append(h)
        return out

    # lazy imports: missing/failed modules must not break whole pipeline
    try:
        from .et_open import fetch_et_open_rule_hits
        _safe_extend(fetch_et_open_rule_hits(cfg, cve_id))
    except Exception:
        pass

    try:
        from .snort_community import fetch_snort_community_rule_hits
        _safe_extend(fetch_snort_community_rule_hits(cfg, cve_id))
    except Exception:
        pass

    return _dedup(hits)
