from __future__ import annotations

import os
from dataclasses import dataclass
from typing import List, Tuple, Dict, Optional

from .rule_validation import validate_by_engine
from .util.textutil import sha256_hex


@dataclass
class RuleArtifact:
    engine: str
    source: str
    rule_path: str
    rule_text: str
    validated: bool
    validation_details: str


def _int_setting(db_or_none, key: str, default: int) -> int:
    try:
        if db_or_none is None:
            return default
        v = db_or_none.get_setting_text(key)  # SupabaseDB
        if v is None:
            return default
        return int(v.strip())
    except Exception:
        return default


def _pick_caps(cfg) -> Dict[str, int]:
    """
    cfg에 db 핸들이 없기 때문에(시그니처 유지), env/기본으로 fallback.
    - 실제 상한은 report_store에서도 최종으로 한번 더 강제됨.
    """
    def _env_int(name: str, default: int) -> int:
        try:
            return int(os.getenv(name, str(default)).strip())
        except Exception:
            return default

    return {
        "per_rule_max_bytes": _env_int("ARGUS_RULE_TEXT_MAX_BYTES_PER_RULE", 20_000),
        "max_rules_total": _env_int("ARGUS_ZIP_MAX_RULES_TOTAL", 200),
        "max_rules_per_engine": _env_int("ARGUS_ZIP_MAX_RULES_PER_ENGINE", 80),
    }


def _truncate_rule_text(rule_text: str, cap_bytes: int) -> Tuple[str, bool]:
    raw = (rule_text or "").encode("utf-8")
    if len(raw) <= cap_bytes:
        return rule_text, False
    cut = raw[:cap_bytes].decode("utf-8", errors="ignore")
    # 룰은 텍스트가 잘리면 의미가 깨질 수 있으므로, 원칙적으로는 ZIP에서 제외하는 편이 더 안전.
    # 다만 운영 요구(“복붙 가능한 수준”)을 위해:
    # - 여기서는 “잘라서 넣지 않고 제외”가 더 안전하므로 truncate 대신 제외 정책을 선택하는 게 맞음.
    # => 호출부에서 cap 초과 시 제외 처리하게 하므로 이 함수는 사용하지 않음.
    return cut, True


def validate_and_build_bundle(
    cfg,
    cve: dict,
    official_hits: List[dict],
) -> Tuple[List[RuleArtifact], List[str], str, str]:
    """
    official_hits: [{engine, source, rule_path, rule_text, reference}, ...]
    반환:
      - artifacts: RuleArtifact list (validated 여부 포함)
      - warnings: list[str]
      - official_fp: fingerprint for validated official rules
      - rules_section_md: report 섹션(무엇을 포함/제외했는지 명시)

    정책:
    - 검증은 필수
    - ZIP/저장 폭주 방지:
      - 엔진별/전체 최대 룰 수 제한
      - 룰 텍스트 bytes cap 초과는 ZIP 포함에서 제외(안전)
    """
    caps = _pick_caps(cfg)
    per_rule_max_bytes = int(caps["per_rule_max_bytes"])
    max_rules_total = int(caps["max_rules_total"])
    max_rules_per_engine = int(caps["max_rules_per_engine"])

    warnings: List[str] = []
    artifacts: List[RuleArtifact] = []

    # 엔진별 카운트
    per_engine_count: Dict[str, int] = {}

    excluded_due_to_caps: List[str] = []

    # official_hits 순서는 상위 로직에서 이미 “공신력/우선순위” 기반 정렬되었다고 가정
    for h in official_hits:
        engine = (h.get("engine") or "").strip()
        source = (h.get("source") or "").strip()
        rule_path = (h.get("rule_path") or "rule.txt").strip()
        rule_text = (h.get("rule_text") or "").strip()

        if not engine or not rule_text:
            continue

        # 전체 개수 상한
        if len([a for a in artifacts if a.validated]) >= max_rules_total:
            excluded_due_to_caps.append(f"[CAP:total] {engine} {source} {rule_path}")
            continue

        # 엔진별 상한
        cnt = per_engine_count.get(engine, 0)
        if cnt >= max_rules_per_engine:
            excluded_due_to_caps.append(f"[CAP:engine] {engine} {source} {rule_path}")
            continue

        # 룰 크기 상한(룰을 잘라서 넣으면 오동작 위험이 있으므로, cap 초과는 제외)
        if len(rule_text.encode("utf-8")) > per_rule_max_bytes:
            excluded_due_to_caps.append(f"[CAP:per_rule_bytes] {engine} {source} {rule_path} bytes>{per_rule_max_bytes}")
            continue

        # ✅ 엔진 검증
        vr = validate_by_engine(engine, rule_text)
        art = RuleArtifact(
            engine=engine,
            source=source,
            rule_path=rule_path,
            rule_text=rule_text,
            validated=vr.ok,
            validation_details=vr.details,
        )
        artifacts.append(art)

        if vr.ok:
            per_engine_count[engine] = cnt + 1

    # fingerprint: validated official-only
    validated_texts = []
    for a in artifacts:
        if a.validated:
            # 엔진/경로/본문 기반
            validated_texts.append(f"{a.engine}|{a.source}|{a.rule_path}|{sha256_hex(a.rule_text.encode('utf-8'))}")
    official_fp = sha256_hex(("\n".join(sorted(validated_texts))).encode("utf-8")) if validated_texts else ""

    # Report 섹션
    lines: List[str] = []
    lines.append("## 6) Official / Public Rules (Validated & Bundled)")
    lines.append(f"- Bundling caps: per_rule_max_bytes={per_rule_max_bytes}, max_rules_total={max_rules_total}, max_rules_per_engine={max_rules_per_engine}")
    lines.append("")

    ok_cnt = sum(1 for a in artifacts if a.validated)
    fail_cnt = sum(1 for a in artifacts if not a.validated)
    lines.append(f"- Validation results: PASS={ok_cnt}, FAIL={fail_cnt}")
    lines.append("")

    if excluded_due_to_caps:
        lines.append("### 6.1 Excluded due to caps (to protect Storage limits)")
        for x in excluded_due_to_caps[:200]:
            lines.append(f"- {x}")
        if len(excluded_due_to_caps) > 200:
            lines.append(f"- ...(total excluded due to caps: {len(excluded_due_to_caps)})")
        lines.append("")

    # PASS 목록(Report에서 모두 보여줌)
    lines.append("### 6.2 Included (validated PASS) rules")
    if ok_cnt == 0:
        lines.append("- (none)")
    else:
        for a in [x for x in artifacts if x.validated][:400]:
            lines.append(f"- [{a.engine}] {a.source} :: {a.rule_path}")
        if ok_cnt > 400:
            lines.append(f"- ...(total PASS: {ok_cnt})")
    lines.append("")

    # FAIL 목록(원인)
    if fail_cnt:
        lines.append("### 6.3 Validation FAIL (not bundled into ZIP)")
        for a in [x for x in artifacts if not x.validated][:120]:
            det = (a.validation_details or "").strip()
            det = det[:260].replace("\n", " ") if det else ""
            lines.append(f"- [{a.engine}] {a.source} :: {a.rule_path} :: {det}")
        if fail_cnt > 120:
            lines.append(f"- ...(total FAIL: {fail_cnt})")
        lines.append("")

    rules_section_md = "\n".join(lines).strip() + "\n"
    return artifacts, warnings, official_fp, rules_section_md
