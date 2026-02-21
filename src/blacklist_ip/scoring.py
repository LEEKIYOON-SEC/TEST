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
    AbuseIPDB 세분화 스코어링.

    기존 5단계 버킷 → 연속적 점수로 변경하여 동점 IP 차별화.

    구성요소:
      1) confidence 기반: int(c * 0.25) → 0~25 (1점 단위 정밀도)
         - c < 10이면 페널티: -10 (false positive 가능성)
      2) 신고 건수 보너스: min(8, reports // 5) → 0~8
         - 신고가 많을수록 신뢰도 높음
      3) 신고 건수 < 3이면 전체 보정치 50% 감소 (낮은 신뢰도)

    총 범위: -10 ~ +33
    """
    c = abuse.get("abuseConfidenceScore")
    reports = abuse.get("totalReports")

    try:
        c = int(c)
    except Exception:
        return 0

    # 1) confidence 연속 점수
    if c < 10:
        adj = -10
    else:
        adj = int(c * 0.25)  # 10→2, 50→12, 80→20, 100→25

    # 2) 신고 건수 보너스
    try:
        if reports is not None:
            r = int(reports)
            adj += min(8, r // 5)  # 5건→1, 15건→3, 40건→8
    except Exception:
        pass

    # 3) 신고 건수 < 3이면 신뢰도 낮음
    try:
        if reports is not None and int(reports) < 3:
            adj = int(adj * 0.5)
    except Exception:
        pass

    return adj


def adjust_from_internetdb(inetdb: Dict[str, Any]) -> int:
    """
    Shodan InternetDB 세분화 스코어링 (v2.0).

    기존 3단계 버킷 → 위험 포트 수 + 알려진 취약점 수로 세분화.

    구성요소:
      1) 위험 포트: min(15, count * 3) → 0~15
      2) 알려진 취약점(vulns): min(10, len(vulns) * 2) → 0~10

    총 범위: 0 ~ +25
    """
    ports = inetdb.get("ports") or []
    if not isinstance(ports, list):
        ports = []

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

    risky_count = sum(1 for p in ports if isinstance(p, int) and p in risky_ports)
    port_adj = min(15, risky_count * 3)

    # 알려진 취약점 수 (InternetDB vulns 필드)
    vulns = inetdb.get("vulns") or []
    if not isinstance(vulns, list):
        vulns = []
    vuln_adj = min(10, len(vulns) * 2)

    return port_adj + vuln_adj


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