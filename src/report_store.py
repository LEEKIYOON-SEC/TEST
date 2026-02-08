from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

from .util.textutil import sha256_hex
from .util.ziputil import write_zip


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _ts_for_path(dt: datetime) -> str:
    # 20260208T010203Z 형태
    return dt.astimezone(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


def build_report_markdown(
    *,
    cve: dict,
    alert_type: str,
    notify_reason: str,
    change_kind: str,
) -> str:
    """
    Slack이 길어지는 문제를 해결하기 위해, 상세는 Report에 저장.
    여기서는 1차로 "기본 CTI 리포트"만 구성.
    (다음 단계에서: Evidence Bundle / 패치 링크 / 룰 섹션 / LLM 분석 추가)
    """
    cve_id = cve["cve_id"]
    lines: list[str] = []
    lines.append(f"# Argus-AI-Threat Intelligence Report")
    lines.append("")
    lines.append(f"## 1) Summary")
    lines.append(f"- CVE: {cve_id}")
    lines.append(f"- Alert Type: {alert_type}")
    lines.append(f"- Trigger: {notify_reason}")
    lines.append(f"- Change Kind: {change_kind}")
    lines.append(f"- Published: {cve.get('date_published')}")
    lines.append(f"- Updated: {cve.get('date_updated')}")
    lines.append("")
    lines.append(f"## 2) Technical Details (Raw)")
    lines.append(f"- CVSS Score: {cve.get('cvss_score')}")
    lines.append(f"- CVSS Severity: {cve.get('cvss_severity')}")
    lines.append(f"- CVSS Vector: {cve.get('cvss_vector')}")
    lines.append(f"- Attack Vector: {cve.get('attack_vector')}")
    lines.append(f"- CWE: {', '.join(cve.get('cwe_ids') or [])}")
    lines.append(f"- EPSS: {cve.get('epss_score')} (percentile {cve.get('epss_percentile')})")
    lines.append(f"- CISA KEV: {bool(cve.get('is_cisa_kev') or False)} (added {cve.get('kev_added_date')})")
    lines.append("")
    lines.append("## 3) Description (EN)")
    lines.append(cve.get("description_en") or "")
    lines.append("")
    lines.append("## 4) References")
    for r in (cve.get("references") or []):
        lines.append(f"- {r}")
    lines.append("")
    lines.append("## 5) Evidence Bundle (Placeholder)")
    lines.append(
        "- NOTE: Llama-4-maverick은 웹검색 불가이므로, 다음 단계에서 URL이 아닌 '정규화된 텍스트 근거'를 이 섹션에 누적합니다."
    )
    lines.append("")
    return "\n".join(lines).strip() + "\n"


def store_report_and_get_link(
    cfg,
    db,
    *,
    cve_id: str,
    alert_type: str,
    notify_reason: str,
    report_md: str,
    kev_listed: bool,
    rules_zip_bytes: Optional[bytes] = None,
) -> Tuple[str, str, Optional[str]]:
    """
    Supabase Storage에 report.md (+ 선택: rules.zip)을 저장하고,
    report_objects에 메타 기록 후,
    Signed URL을 생성해 반환.

    반환:
      - report_link (signed url)
      - report_path
      - rules_zip_path (optional)
    """
    if not cfg.USE_STORAGE:
        # Storage를 쓰지 않는 경우에도 Slack에 링크 자리에 표시할 값은 필요
        return "Storage disabled", "", None

    now = _utcnow()
    ts = _ts_for_path(now)
    bucket = cfg.STORAGE_BUCKET

    report_path = f"reports/{cve_id}/{ts}.md"
    rules_zip_path = f"rules/{cve_id}/{ts}.zip" if rules_zip_bytes else None

    report_bytes = report_md.encode("utf-8")
    report_sha = sha256_hex(report_bytes)
    rules_sha = sha256_hex(rules_zip_bytes) if rules_zip_bytes else None

    # content_hash: report + rules 결합 지문(중복 방지/갱신 판정에 사용)
    content_hash = sha256_hex((report_sha + (rules_sha or "")).encode("utf-8"))

    # Storage 업로드 (upsert=true)
    storage = db.sb.storage.from_(bucket)
    storage.upload(
        report_path,
        report_bytes,
        file_options={"content-type": "text/markdown; charset=utf-8", "upsert": "true"},
    )

    if rules_zip_bytes and rules_zip_path:
        storage.upload(
            rules_zip_path,
            rules_zip_bytes,
            file_options={"content-type": "application/zip", "upsert": "true"},
        )

    # Signed URL (30일)
    expiry_seconds = int(cfg.REPORT_TTL_DAYS) * 24 * 3600
    signed = storage.create_signed_url(report_path, expiry_seconds)
    report_link = signed.get("signedURL") or signed.get("signedUrl") or str(signed)

    # retention: Storage 과금/용량 보호를 위해 링크 TTL과 동일하게 기본 설정
    retention_until = now + timedelta(days=int(cfg.REPORT_TTL_DAYS))

    # DB 메타 저장
    db.insert_report_object(
        cve_id=cve_id,
        alert_type=alert_type,
        primary_reason=notify_reason,
        report_path=report_path,
        rules_zip_path=rules_zip_path,
        content_hash=content_hash,
        report_sha256=report_sha,
        rules_sha256=rules_sha,
        retention_until=retention_until,
        kev_listed=bool(kev_listed),
        signed_url_expiry_seconds=expiry_seconds,
    )

    return report_link, report_path, rules_zip_path
