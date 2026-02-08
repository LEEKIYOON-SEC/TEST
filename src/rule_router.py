from __future__ import annotations

from dataclasses import dataclass
from typing import Literal, Optional

RuleScope = Literal["network_only", "host_only", "both"]


@dataclass(frozen=True)
class RouteDecision:
    scope: RuleScope
    include_sigma: bool
    include_network_rules: bool   # snort/suricata
    include_yara: bool
    rationale: str


def decide_rule_scope(cve: dict) -> RouteDecision:
    """
    룰 제공 정책:
    - Sigma: 무조건 제공 (include_sigma=True)
    - Snort/Suricata: 네트워크 탐지가 효율적인 경우 우선
    - YARA: 파일/페이로드 기반 증거가 있을 때만(불필요 남발 금지)

    현재 단계에서 우리가 가진 근거:
      - attack_vector (NETWORK/LOCAL/ADJACENT/PHYSICAL)
      - description_en (문자열 힌트)
      - references (URL 힌트; 단 LLM evidence에서는 URL이 아니라 텍스트를 쓸 예정)

    다음 단계에서 더 정교화:
      - VulnCheck weaponized / exploit PoC 텍스트 분석
      - GitHub/ExploitDB 등에서 수집한 "Evidence Bundle" 기반
    """
    include_sigma = True

    av = (cve.get("attack_vector") or "").upper().strip()
    desc = (cve.get("description_en") or "").lower()

    # 간단 힌트: 파일 기반 키워드
    file_hints = any(k in desc for k in ["file", "upload", "archive", "zip", "pdf", "doc", "macro", "dll", "exe", "payload", "malware"])
    # 네트워크 기반 키워드
    net_hints = any(k in desc for k in ["http", "https", "tcp", "udp", "request", "response", "server", "client", "rpc", "socket", "smtp", "dns", "ssh", "tls"])

    if av == "NETWORK":
        # 기본: 네트워크 탐지 우선
        include_network = True
        include_yara = bool(file_hints)  # 파일 힌트 있으면 both
        scope: RuleScope = "both" if include_yara else "network_only"
        rationale = "Attack Vector=NETWORK → 네트워크 탐지 우선. 파일/페이로드 힌트가 있으면 YARA 병행."
        return RouteDecision(scope, include_sigma, include_network, include_yara, rationale)

    if av in ("LOCAL", "PHYSICAL"):
        # 기본: 호스트 탐지 우선(시그마+YARA)
        include_network = False if not net_hints else True  # 로컬이지만 네트워크 서비스가 언급되면 둘 다
        include_yara = True
        scope = "both" if include_network else "host_only"
        rationale = "Attack Vector=LOCAL/PHYSICAL → 호스트 탐지 우선(Sigma+YARA). 네트워크 힌트가 있으면 네트워크 룰도 병행."
        return RouteDecision(scope, include_sigma, include_network, include_yara, rationale)

    if av == "ADJACENT":
        include_network = True
        include_yara = bool(file_hints)
        scope = "both" if include_yara else "network_only"
        rationale = "Attack Vector=ADJACENT → 네트워크 계열로 분류. 파일 힌트 시 YARA 병행."
        return RouteDecision(scope, include_sigma, include_network, include_yara, rationale)

    # 정보가 없으면 보수적으로 both는 피하고, 네트워크 힌트가 있으면 network_only,
    # 파일 힌트가 있으면 host_only, 둘 다 있으면 both.
    if net_hints and file_hints:
        return RouteDecision("both", include_sigma, True, True, "공격벡터 불명확. 네트워크+파일 힌트 모두 존재 → 둘 다 제공.")
    if net_hints:
        return RouteDecision("network_only", include_sigma, True, False, "공격벡터 불명확. 네트워크 힌트 → 네트워크 룰 우선.")
    if file_hints:
        return RouteDecision("host_only", include_sigma, False, True, "공격벡터 불명확. 파일/페이로드 힌트 → 호스트 룰 우선.")
    return RouteDecision("network_only", include_sigma, True, False, "공격벡터/힌트 불충분 → 기본은 네트워크 룰(오탐 방지 위해 YARA는 제외).")
