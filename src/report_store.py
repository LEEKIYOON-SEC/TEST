from __future__ import annotations

import os
from datetime import datetime, timezone
from typing import Optional, Tuple

from .storage_client import upload_bytes, create_signed_url
from .util.textutil import sha256_hex


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def _ym_prefix(dt: datetime) -> str:
    return f"{dt.year:04d}/{dt.month:02d}"


def _bool_env(name: str, default: bool = False) -> bool:
    v = os.getenv(name, "true" if default else "false").strip().lower()
    return v in ("1", "true", "yes", "y", "on")


def _int_env(name: str, default: int) -> int:
    try:
        return int(os.getenv(name, str(default)).strip())
    except Exception:
        return default


def _get_setting_int(db, key: str, default: int) -> int:
    try:
        v = db.get_setting_text(key)
        if v is None:
            return default
        return int(v.strip())
    except Exception:
        return default


def _cap_bytes_with_notice(md: str, cap: int, *, cve_id: str, alert_type: str) -> Tuple[str, bool]:
    """
    md가 cap(bytes) 초과이면 잘라서 반환.
    - UTF-8 바이트 기준
    - 잘린 경우 Report 최상단에 경고 배너 추가
    """
    raw = (md or "").encode("utf-8")
    if len(raw) <= cap:
        return md, False

    # 안전하게 바이트 기준 슬라이스 후 UTF-8 복원(깨진 시퀀스 제거)
    cut = raw[:cap]
    text = cut.decode("utf-8", errors="ignore")

    banner = (
        f"> ⚠️ TRUNCATED REPORT (size cap exceeded)\n"
        f"> - CVE: {cve_id}\n"
        f"> - Alert: {alert_type}\n"
        f"> - Original bytes: {len(raw)}\n"
        f"> - Stored bytes cap: {cap}\n"
        f"> - NOTE: 일부 Evidence/본문이 저장에서 생략되었습니다. (Slack 링크/원본 URL을 참고)\n\n"
    )
    return banner + text, True


def store_report_and_get_link(
    cfg,
    db,
    *,
    cve_id: str,
    alert_type: str,
    notify_reason: str,
    report_md: str,
    kev_listed: bool,
    rules_zip_bytes: Optional[bytes],
) -> Tuple[str, Optional[str], Optional[str], str, str, str]:
    """
    반환: (report_link, report_path, rules_zip_path, report_sha, rules_sha, content_hash)

    size caps:
    - report stored bytes <= argus_report_max_bytes
    - rules.zip stored bytes <= argus_rules_zip_max_bytes (else omitted)
    """
    use_storage = _bool_env("USE_STORAGE", True) or bool(getattr(cfg, "USE_STORAGE", False))
    bucket = os.getenv("STORAGE_BUCKET", "") or getattr(cfg, "STORAGE_BUCKET", "argus")

    ttl_days = getattr(cfg, "REPORT_TTL_DAYS", None)
    if ttl_days is None:
        ttl_days = _int_env("REPORT_TTL_DAYS", 30)
    ttl_days = max(1, int(ttl_days))
    expires_sec = ttl_days * 24 * 60 * 60

    # ---- size caps from settings (web UI) ----
    report_cap = _get_setting_int(db, "argus_report_max_bytes", 300_000)
    zip_cap = _get_setting_int(db, "argus_rules_zip_max_bytes", 2_000_000)

    now = _utcnow()
    prefix = _ym_prefix(now)

    # 1) cap report
    capped_report_md, report_truncated = _cap_bytes_with_notice(report_md or "", report_cap, cve_id=cve_id, alert_type=alert_type)
    report_bytes = capped_report_md.encode("utf-8")
    report_sha = sha256_hex(report_bytes)

    # 2) cap zip: if too large, omit zip
    rules_sha = sha256_hex(rules_zip_bytes) if rules_zip_bytes else ""
    zip_omitted = False
    if rules_zip_bytes and len(rules_zip_bytes) > zip_cap:
        zip_omitted = True
        rules_zip_bytes = None  # omit
        rules_sha = ""          # sha not applicable

    content_hash = sha256_hex((report_sha + "|" + rules_sha + "|" + alert_type + "|" + (notify_reason or "")).encode("utf-8"))

    if not use_storage:
        return "(storage disabled)", None, None, report_sha, rules_sha, content_hash

    report_path = f"reports/{prefix}/{cve_id}/{cve_id}_{alert_type}.md"
    rules_zip_path = f"rules/{prefix}/{cve_id}/{cve_id}_{alert_type}_rules.zip" if rules_zip_bytes else None

    # upload report
    up1 = upload_bytes(cfg, bucket=bucket, object_path=report_path, data=report_bytes, content_type="text/markdown; charset=utf-8", upsert=True)
    if not up1.ok:
        return f"(report upload failed: {up1.details})", report_path, rules_zip_path, report_sha, rules_sha, content_hash

    # upload zip optional
    if rules_zip_bytes and rules_zip_path:
        up2 = upload_bytes(cfg, bucket=bucket, object_path=rules_zip_path, data=rules_zip_bytes, content_type="application/zip", upsert=True)
        if not up2.ok:
            rules_zip_path = None

    su = create_signed_url(cfg, bucket=bucket, object_path=report_path, expires_in_seconds=expires_sec)
    report_link = su.url if su.ok else f"(signed url failed: {su.details})"

    # DB meta (best-effort)
    try:
        db.insert_report_artifact(
            cve_id=cve_id,
            alert_type=alert_type,
            notify_reason=notify_reason + (" [REPORT_TRUNCATED]" if report_truncated else ""),
            object_path=report_path,
            kind="report_md",
            sha256=report_sha,
            bytes_len=len(report_bytes),
        )
        if rules_zip_path and rules_zip_bytes:
            db.insert_report_artifact(
                cve_id=cve_id,
                alert_type=alert_type,
                notify_reason=notify_reason,
                object_path=rules_zip_path,
                kind="rules_zip",
                sha256=sha256_hex(rules_zip_bytes),
                bytes_len=len(rules_zip_bytes),
            )
        if zip_omitted:
            # zip 생략도 메타로 남기면 운영자가 추적 가능(옵션)
            pass
    except Exception:
        pass

    return report_link, report_path, rules_zip_path, report_sha, (rules_sha or ""), content_hash
