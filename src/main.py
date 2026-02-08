from __future__ import annotations

import os
from datetime import datetime, timezone

from .logging_utils import setup_logging, get_logger
from .config import load_config
from .supabase_db import SupabaseDB
from .slack import post_slack

from .cve_sources import fetch_cveorg_published_since
from .kev_epss import enrich_with_kev_epss
from .dedup import should_notify, classify_change, compute_payload_hash
from .scoring import compute_risk_flags

from .slack_format import format_slack_message
from .report_store import build_report_markdown, store_report_and_get_link

log = get_logger("argus.main")


def _utcnow() -> datetime:
    return datetime.now(timezone.utc)


def main() -> None:
    setup_logging()
    cfg = load_config()
    db = SupabaseDB(cfg.SUPABASE_URL, cfg.SUPABASE_KEY)

    # 스팸 방지: 기본 OFF (운영에서는 false 유지)
    selftest = os.getenv("ARGUS_SELFTEST", "").strip().lower() in ("1", "true", "yes", "y", "on")

    run_ok = False
    try:
        since = db.get_last_poll_time(default_minutes=60)
        now = _utcnow()

        if selftest:
            post_slack(cfg.SLACK_WEBHOOK_URL, "🧪 Argus 셀프테스트: CVE 수집/정책 파이프라인 시작")

        # 1) CVE.org PUBLISHED(= datePublished 존재) 신규 수집 (REJECTED 제외는 cve_sources에서 처리)
        cves = fetch_cveorg_published_since(since, until=now)

        if not cves:
            db.log_run("RUN", True, f"no new CVE PUBLISHED since {since.isoformat()}")
            run_ok = True
            return

        # 2) KEV/EPSS enrich
        cves = enrich_with_kev_epss(cfg, cves)

        # 3) CVE별 정책 판단 + dedup + 저장/발송
        sent = 0
        for cve in cves:
            cve_id = cve["cve_id"]

            # 파생 위험 플래그 계산(내부 dict에 기록)
            flags = compute_risk_flags(cfg, cve)

            prev = db.get_cve_state(cve_id)

            # ⚠️ 중요: 현재 DB에는 references를 저장하지 않으므로
            # dedup.py의 references 비교가 "매번 UPDATE"를 유발할 수 있음.
            # 이번 단계에서는 '비교용 prev 사본'에 현재 references를 주입하여 중복 알림을 방지.
            prev_cmp = None
            if prev:
                prev_cmp = dict(prev)
                if "references" not in prev_cmp:
                    prev_cmp["references"] = cve.get("references") or []

            notify, reason = should_notify(cfg, cve, prev_cmp)

            # DB에는 최소한 last_seen 업데이트는 항상 수행
            # (신규 수집된 CVE라도 notify 조건이 아닐 수 있음)
            if not notify:
                db.upsert_cve_state(cve, last_seen_at=_utcnow())
                continue

            change_kind = classify_change(prev_cmp, cve)

            # alert_type 결정
            if not prev:
                alert_type = "NEW_CVE_PUBLISHED"
            elif change_kind == "ESCALATION":
                alert_type = "UPDATE_ESCALATION"
            else:
                alert_type = "HIGH_RISK"

            # 4) Report 생성/저장 (Storage Signed URL 30일)
            report_md = build_report_markdown(
                cve=cve,
                alert_type=alert_type,
                notify_reason=reason,
                change_kind=change_kind,
            )

            report_link, report_path, rules_zip_path = store_report_and_get_link(
                cfg,
                db,
                cve_id=cve_id,
                alert_type=alert_type,
                notify_reason=reason,
                report_md=report_md,
                kev_listed=bool(cve.get("is_cisa_kev") or False),
                rules_zip_bytes=None,  # 다음 단계에서 룰 zip 저장 연결
            )

            # 5) Slack 메시지 구성/발송
            slack_text = format_slack_message(
                cve=cve,
                alert_type=alert_type,
                notify_reason=reason,
                change_kind=change_kind,
                report_link=report_link,
            )
            post_slack(cfg.SLACK_WEBHOOK_URL, slack_text)

            # 6) payload hash(중복 방지) + state 업데이트
            payload = {
                "cve_id": cve_id,
                "alert_type": alert_type,
                "reason": reason,
                "cvss_score": cve.get("cvss_score"),
                "cvss_vector": cve.get("cvss_vector"),
                "epss_score": cve.get("epss_score"),
                "is_cisa_kev": bool(cve.get("is_cisa_kev") or False),
                "attack_vector": cve.get("attack_vector"),
                # references는 DB 저장 안하므로 hash 입력에서 제외(중복 방지 안정성)
            }
            payload_hash = compute_payload_hash(payload)

            db.upsert_cve_state(
                cve,
                last_seen_at=_utcnow(),
                last_notified_at=_utcnow(),
                last_notified_type=alert_type,
                last_notify_reason=reason,
                last_payload_hash=payload_hash,
                last_report_path=report_path or None,
                last_rules_zip_path=rules_zip_path or None,
                last_rule_status="NONE",
            )

            sent += 1

        db.log_run("RUN", True, f"processed={len(cves)} sent={sent} since={since.isoformat()}")
        run_ok = True

    except Exception as e:
        db.log_run("RUN", False, f"run failed: {e}")
        raise

    finally:
        if run_ok:
            log.info("Run OK")
        else:
            log.error("Run FAILED")


if __name__ == "__main__":
    main()
