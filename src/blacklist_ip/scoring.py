# src/blacklist_ip/scoring.py
from dataclasses import dataclass
from typing import Any, Dict, List, Optional


def clamp(x: int, lo: int = 0, hi: int = 100) -> int:
    return max(lo, min(hi, x))


def risk_bucket(score: int, critical: int, high: int, medium: int) -> str:
    if score >= critical:
        return "Critical"
    if score >= high:
        return "High"
    if score >= medium:
        return "Medium"
    return "Low"


def compute_source_bonus(sources_count: int, step: int, cap: int) -> int:
    """
    다중 소스(여러 피드에 동시에 등장)일수록 신뢰도/중요도가 높을 가능성이 있어
    보수적으로 가산.
    """
    if sources_count <= 1:
        return 0
    return min(cap, step * (sources_count - 1))


def adjust_from_abuseipdb(abuse: Dict[str, Any]) -> int:
    """
    AbuseIPDB 핵심: abuseConfidenceScore(0~100), totalReports 등을 활용.

    정책(기본안):
      - 90~100: +20
      - 70~89 : +12
      - 40~69 : +6
      - 10~39 : +0
      - 0~9   : -10  (피드 false positive 가능성 완화)

    totalReports < 3이면 신뢰도 낮다고 보고 보정치를 절반으로 감소.
    """
    c = abuse.get("abuseConfidenceScore")
    reports = abuse.get("totalReports")

    try:
        c = int(c)
    except Exception:
        return 0

    if 90 <= c <= 100:
        adj = 20
    elif 70 <= c <= 89:
        adj = 12
    elif 40 <= c <= 69:
        adj = 6
    elif 10 <= c <= 39:
        adj = 0
    else:  # 0~9
        adj = -10

    try:
        if reports is not None and int(reports) < 3:
            adj = int(adj / 2)
    except Exception:
        pass

    return adj


def adjust_from_internetdb(inetdb: Dict[str, Any]) -> int:
    """
    Shodan InternetDB는 '악성 판정'이 아니라 '노출/서비스 힌트'이므로
    과대평가하지 않도록 보수적으로 포트 기반 가산만 적용.

    정책(기본안):
      - 위험 포트 1개 이상: +5
      - 3개 이상: +10
      - 5개 이상: +15

    위험 포트 목록은 운영 정책에 따라 조정 가능.
    """
    ports = inetdb.get("ports") or []
    if not isinstance(ports, list):
        return 0

    risky_ports = {
        22,   # SSH
        23,   # Telnet
        3389, # RDP
        445,  # SMB
        9200, # Elasticsearch
        6379, # Redis
        11211,# Memcached
        27017,# MongoDB
        1433, # MSSQL
        3306, # MySQL
        5900, # VNC
        25,   # SMTP (오픈 릴레이/스팸 인프라 가능성)
    }

    count = 0
    for p in ports:
        if isinstance(p, int) and p in risky_ports:
            count += 1

    if count >= 5:
        return 15
    if count >= 3:
        return 10
    if count >= 1:
        return 5
    return 0


def apply_scoring(
    tier1_records: Dict[str, Any],
    enrichment: Dict[str, Dict[str, Any]],
    critical: int,
    high: int,
    medium: int,
    enable_source_bonus: bool,
    source_bonus_step: int,
    source_bonus_cap: int,
) -> Dict[str, Dict[str, Any]]:
    """
    Input:
      tier1_records: {indicator: IndicatorRecord-like}
      enrichment: {ip: {"abuseipdb": {...}?, "internetdb": {...}?}}

    Output:
      scored: {
        indicator: {
          indicator, type, category, sources, base_score,
          final_score, risk, enrichment, adjustments
        }
      }
    """
    out: Dict[str, Dict[str, Any]] = {}

    for ind, rec in tier1_records.items():
        base = int(rec.base_score)
        sources = list(rec.sources)

        bonus = (
            compute_source_bonus(len(sources), source_bonus_step, source_bonus_cap)
            if enable_source_bonus
            else 0
        )

        enr = enrichment.get(ind) if enrichment else None
        abuse_adj = 0
        inetdb_adj = 0

        if enr:
            abuse = enr.get("abuseipdb")
            if isinstance(abuse, dict):
                abuse_adj = adjust_from_abuseipdb(abuse)

            inetdb = enr.get("internetdb")
            if isinstance(inetdb, dict):
                inetdb_adj = adjust_from_internetdb(inetdb)

        final_score = clamp(base + bonus + abuse_adj + inetdb_adj)
        risk = risk_bucket(final_score, critical, high, medium)

        out[ind] = {
            "indicator": ind,
            "type": rec.type,
            "category": rec.category,
            "sources": sources,
            "base_score": base,
            "final_score": final_score,
            "risk": risk,
            "enrichment": enr,
            "adjustments": {
                "source_bonus": bonus,
                "abuseipdb": abuse_adj,
                "internetdb": inetdb_adj,
            },
        }

    return out
