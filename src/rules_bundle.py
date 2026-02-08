from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

from .rule_validation import validate_by_engine
from .util.textutil import sha256_hex
from .util.ziputil import write_zip
from .rule_router import decide_rule_scope


@dataclass
class RuleArtifact:
    source: str
    engine: str               # sigma / yara / suricata / snort2 / snort3
    rule_path: str
    rule_text: str
    reference: str
    validated: bool
    validation_details: str
    fingerprint: str          # sha256(text) for dedup/diff


def _fingerprint(rule_text: str) -> str:
    return sha256_hex((rule_text or "").encode("utf-8"))


def _engine_display(engine: str) -> str:
    e = (engine or "").lower()
    if e == "suricata":
        return "Suricata"
    if e == "snort2":
        return "Snort2"
    if e == "snort3":
        return "Snort3"
    if e == "sigma":
        return "Sigma"
    if e == "yara":
        return "YARA"
    return engine


def filter_by_scope(cve: dict, official_hits: List[Dict[str, Any]]) -> Tuple[List[Dict[str, Any]], str]:
    """
    공격벡터 기반으로 어떤 엔진을 포함할지 결정.
    - Sigma: 항상 포함
    - Snort/Suricata: include_network_rules일 때
    - YARA: include_yara일 때
    """
    decision = decide_rule_scope(cve)
    keep: List[Dict[str, Any]] = []

    for h in official_hits:
        eng = (h.get("engine") or "").lower()
        if eng == "sigma" and decision.include_sigma:
            keep.append(h)
        elif eng in ("suricata", "snort2", "snort3") and decision.include_network_rules:
            keep.append(h)
        elif eng == "yara" and decision.include_yara:
            keep.append(h)
        else:
            # 제외(불필요 남발 방지)
            continue

    return keep, decision.rationale


def validate_and_build_bundle(
    *,
    cfg,
    cve: dict,
    official_hits: List[Dict[str, Any]],
) -> Tuple[List[RuleArtifact], Optional[bytes], str, str]:
    """
    공식/공개 룰 hits를:
    1) scope로 필터링(불필요 룰 남발 방지)
    2) 엔진별 검증 통과한 것만 채택
    3) ZIP 번들 생성(rules/<engine>/<source>/<path> 형태)
    4) report에 넣을 룰 섹션 Markdown 생성

    반환:
      - artifacts: RuleArtifact[]
      - zip_bytes: Optional[bytes] (없으면 None)
      - bundle_fingerprint: sha256 of concatenated fingerprints (상태 비교용)
      - rules_section_md: report에 추가할 markdown(복붙/근거 포함)
    """
    scoped_hits, rationale = filter_by_scope(cve, official_hits)

    artifacts: List[RuleArtifact] = []
    zip_files: List[Tuple[str, bytes]] = []

    # "공개 룰은 전부 보내야" 원칙을 지키되,
    # 기업 운영에서 "검증 실패 룰을 배포"하면 사고가 나므로
    # 최종 채택은 validate 통과한 룰만 한다.
    # 대신 실패 룰도 report 섹션에 "검증 실패"로 기록해 추적 가능하게 함.
    report_lines: List[str] = []
    report_lines.append("## 6) Rules (Official/Public)")
    report_lines.append(f"- Routing rationale: {rationale}")
    report_lines.append("")

    if not scoped_hits:
        report_lines.append("- No official/public rules matched or allowed by routing policy.")
        return artifacts, None, sha256_hex(b""), "\n".join(report_lines) + "\n"

    # 엔진별 그룹 요약
    report_lines.append("### 6.1 Matched rule files (pre-validation)")
    for h in scoped_hits:
        report_lines.append(
            f"- [{_engine_display(h.get('engine'))}] {h.get('source')} :: {h.get('rule_path')}  (ref: {h.get('reference')})"
        )
    report_lines.append("")

    # 검증
    report_lines.append("### 6.2 Validation results")
    for h in scoped_hits:
        engine = (h.get("engine") or "").lower()
        rule_text = h.get("rule_text") or ""
        fp = _fingerprint(rule_text)

        vr = validate_by_engine(engine, rule_text)
        ok = bool(vr.ok)

        artifacts.append(
            RuleArtifact(
                source=h.get("source") or "UNKNOWN",
                engine=engine,
                rule_path=h.get("rule_path") or "unknown",
                rule_text=rule_text,
                reference=h.get("reference") or "",
                validated=ok,
                validation_details=vr.details,
                fingerprint=fp,
            )
        )

        status = "PASS" if ok else "FAIL"
        report_lines.append(
            f"- {status} [{_engine_display(engine)}] {h.get('source')} :: {h.get('rule_path')} (fp {fp[:12]})"
        )
    report_lines.append("")

    # ZIP에는 PASS만 포함(운영 안전)
    pass_artifacts = [a for a in artifacts if a.validated]
    if pass_artifacts:
        report_lines.append("### 6.3 Rules bundle (validated only)")
        for a in pass_artifacts:
            zip_path = f"rules/{a.engine}/{a.source}/{a.rule_path}".replace("..", "_")
            zip_files.append((zip_path, (a.rule_text.strip() + "\n").encode("utf-8")))
            report_lines.append(f"- Included: {zip_path} (ref: {a.reference})")
        report_lines.append("")
        zip_bytes = write_zip(zip_files)
    else:
        zip_bytes = None
        report_lines.append("### 6.3 Rules bundle")
        report_lines.append("- No validated rules to bundle.")
        report_lines.append("")

    # 실패 룰은 details를 너무 길게 싣지 않되, 첫 일부는 남김
    fails = [a for a in artifacts if not a.validated]
    if fails:
        report_lines.append("### 6.4 Validation failure details (first 800 chars each)")
        for a in fails:
            details = (a.validation_details or "").strip()
            if len(details) > 800:
                details = details[:800] + "…(truncated)"
            report_lines.append(f"- [{_engine_display(a.engine)}] {a.source} :: {a.rule_path} (fp {a.fingerprint[:12]})")
            report_lines.append("```")
            report_lines.append(details)
            report_lines.append("```")
        report_lines.append("")

    # 번들 지문: PASS 룰 fp들을 안정 결합
    bundle_fp_src = "\n".join(sorted([a.fingerprint for a in pass_artifacts])).encode("utf-8")
    bundle_fingerprint = sha256_hex(bundle_fp_src)

    return artifacts, zip_bytes, bundle_fingerprint, "\n".join(report_lines).strip() + "\n"
