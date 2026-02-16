# src/blacklist_ip/main.py
import argparse
import datetime as dt
from zoneinfo import ZoneInfo
from typing import Any, Dict, List, Optional, Tuple

from blacklist_ip.config import load_settings
from blacklist_ip.collector_tier1 import collect_tier1_safe
from blacklist_ip.delta import compute_delta
from blacklist_ip.enricher_tier2 import Enricher
from blacklist_ip.scoring import apply_scoring
from blacklist_ip.blacklist_ip_notifier import build_slack_blocks, send_slack
from blacklist_ip.store_supabase import Store


def kst_today(tz_name: str) -> dt.date:
    tz = ZoneInfo(tz_name)
    return dt.datetime.now(tz).date()


def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument("--mode", default="daily", choices=["daily"])
    p.add_argument("--tz", default="Asia/Seoul")
    return p.parse_args()


def prioritize_new_ips(new_ips: List[str], tier1_records: Dict[str, Any]) -> List[str]:
    """
    Free-tier 방어용 우선순위:
      - base_score desc
      - sources_count desc
    """
    rows: List[Tuple[int, int, str]] = []
    for ip in new_ips:
        rec = tier1_records.get(ip)
        if not rec:
            continue
        base = int(getattr(rec, "base_score", 0))
        scnt = len(getattr(rec, "sources", []) or [])
        rows.append((base, scnt, ip))
    rows.sort(key=lambda x: (x[0], x[1]), reverse=True)
    return [x[2] for x in rows]


def main():
    args = parse_args()
    settings = load_settings()

    report_date = kst_today(args.tz)
    yesterday = report_date - dt.timedelta(days=1)

    store = Store(settings.supabase_url, settings.supabase_key)

    # -------------------------
    # Tier 1: 전체 수집 (피드별 실패 허용)
    # -------------------------
    tier1_records, feed_failures = collect_tier1_safe(settings.feeds_path)
    today_set = set(tier1_records.keys())

    # -------------------------
    # Delta: 어제 대비 신규/제거
    # -------------------------
    y_set = store.get_snapshot_indicator_set(yesterday)
    delta = compute_delta(y_set, today_set)

    # -------------------------
    # Tier 2: 신규 IP만 enrichment (CIDR 제외)
    # -------------------------
    new_ips = [x for x in delta.new_indicators if "/" not in x]
    prioritized_new_ips = prioritize_new_ips(new_ips, tier1_records)

    enricher = Enricher(
        abuseipdb_key=settings.abuseipdb_api_key,
        store=store,
        quotas=settings.quotas,
        cache_ttl_hours=settings.cache_ttl_hours,
        timeouts=settings.timeouts,
        ratelimit=settings.ratelimit,
    )

    # 하드캡을 내부에서 지키며 전수 시도
    enrichment = enricher.enrich_many(prioritized_new_ips)

    # -------------------------
    # Scoring
    # -------------------------
    scored = apply_scoring(
        tier1_records=tier1_records,
        enrichment=enrichment,
        critical=settings.critical_threshold,
        high=settings.high_threshold,
        medium=settings.medium_threshold,
        enable_source_bonus=settings.enable_source_bonus,
        source_bonus_step=settings.source_bonus_step,
        source_bonus_cap=settings.source_bonus_cap,
    )

    api_usage = {
        "abuseipdb": enricher.usage.abuseipdb,
        "internetdb": enricher.usage.internetdb,
    }

    # -------------------------
    # Persist snapshot
    # -------------------------
    store.upsert_snapshot(
        date=report_date,
        scored=scored,
        new_count=len(delta.new_indicators),
        removed_count=len(delta.removed_indicators),
        api_usage=api_usage,
    )

    # -------------------------
    # Slack report
    # -------------------------
    blocks = build_slack_blocks(
        report_date_kst=report_date,
        scored=scored,
        new_indicators=delta.new_indicators,
        removed_indicators=delta.removed_indicators,
        topn=settings.topn_report,
        api_usage=api_usage,
        feed_failures=feed_failures,
    )
    send_slack(settings.slack_webhook_url, blocks)


if __name__ == "__main__":
    main()
