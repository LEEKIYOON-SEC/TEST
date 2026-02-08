from __future__ import annotations

from typing import List, Dict, Any


def _safe_extend(dst: List[Dict[str, Any]], src: Any) -> None:
    if not src:
        return
    if isinstance(src, list):
        for x in src:
            if isinstance(x, dict):
                dst.append(x)


def _normalize_engine(engine: str) -> str:
    e = (engine or "").strip().lower()
    # canonical names used across Argus
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


def _dedup_hits(hits: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    seen = set()
    out: List[Dict[str, Any]] = []
    for h in hits:
        engine = _normalize_engine(h.get("engine"))
        source = (h.get("source") or "").strip()
        rule_path = (h.get("rule_path") or "").strip()
        reference = (h.get("reference") or "").strip()

        key = (engine, source, rule_path, reference)
        if key in seen:
            continue
        seen.add(key)

        h["engine"] = engine
        out.append(h)
    return out


def fetch_official_rules(cfg, cve_id: str) -> List[Dict[str, Any]]:
    """
    공식/공개 룰 수집 오케스트레이터.
    - 비용 0 원칙: 공개 룰셋(ET Open, Snort Community 등) + GitHub Search 보강
    - 구현 안정성: 모듈이 일부 누락/실패해도 전체 파이프라인이 죽지 않게 best-effort로 동작

    반환 포맷 (list of dict):
      {
        "engine": "suricata" | "snort2" | "snort3" | "sigma" | "yara",
        "source": "et_open" | "snort_community" | "github_trusted" | ...,
        "rule_path": "path/inside/source/or/repo",
        "rule_text": "raw rule text",
        "reference": "URL or identifier",
      }
    """
    hits: List[Dict[str, Any]] = []

    # 1) ET Open (1차: 룰셋 기반, 2차: 검색 보강은 하위 모듈이 담당하거나 추후 통합)
    try:
        from .et_open import fetch_et_open_rule_hits  # lazy import
        _safe_extend(hits, fetch_et_open_rule_hits(cfg, cve_id))
    except Exception:
        # ET Open 실패해도 계속
        pass

    # 2) Snort Community (가능하면 포함)
    try:
        from .snort_community import fetch_snort_community_rule_hits  # lazy import
        _safe_extend(hits, fetch_snort_community_rule_hits(cfg, cve_id))
    except Exception:
        pass

    # 3) (옵션) Trusted GitHub repos / Search 보강
    # - 프로젝트 내에 trusted github 룰 후보 로직이 이미 있다면, 여기서 합칠 수도 있음.
    # - 지금은 main.py가 별도로 github_rule_candidates 를 합치고 있으므로 중복을 피하기 위해 기본은 OFF.
    # - 원하면 이후 세트에서 이 레이어를 여기로 흡수(단일 책임) 가능합니다.

    return _dedup_hits(hits)
