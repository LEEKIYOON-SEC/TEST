# src/blacklist_ip/config.py
import os
from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class Quotas:
    """
    Free-tier 안전 장치.
    - AbuseIPDB: 계정 플랜에 따라 다를 수 있으나, 설계상 하드캡이 필요.
    - InternetDB(Shodan): 키 없이 사용 가능하므로 별도 쿼터를 강제하지 않아도 되지만,
      운영 안전을 위해 옵션으로 상한을 둘 수 있음(기본: 전수).
    """
    abuseipdb_daily_max: int = 1000
    internetdb_daily_max: int = 10_000  # 신규 IP가 200~500 수준이면 사실상 무제한처럼 동작


@dataclass(frozen=True)
class CacheTTLHours:
    """
    캐시 TTL(시간).
    - AbuseIPDB: 신고 데이터는 비교적 빠르게 변할 수 있어 24h 권장.
    - InternetDB: 주간 업데이트 성격이므로 72h~168h(7d)도 가능. 기본 72h.
    """
    abuseipdb: int = 24
    internetdb: int = 72


@dataclass(frozen=True)
class ProviderTimeoutSec:
    abuseipdb: int = 20
    internetdb: int = 10


@dataclass(frozen=True)
class ProviderRateLimit:
    """
    보수적 레이트리밋(초 단위 최소 간격).
    - AbuseIPDB: 너무 빠르게 치면 429 가능 -> 1.0s 기본
    - InternetDB: 높은 rate limit이지만, 예의상 약간 텀(0.1s)
    """
    abuseipdb_min_interval: float = 1.0
    internetdb_min_interval: float = 0.1


@dataclass(frozen=True)
class Settings:
    # Required integrations
    slack_webhook_url: str
    supabase_url: str
    supabase_key: str

    # Tier2 keys
    abuseipdb_api_key: Optional[str]

    # Tier1 feeds
    feeds_path: str = "src/blacklist_ip/feeds.yml"

    # Risk thresholds
    critical_threshold: int = 80
    high_threshold: int = 60
    medium_threshold: int = 40

    # Source bonus policy
    enable_source_bonus: bool = True
    source_bonus_step: int = 5
    source_bonus_cap: int = 15

    # Reporting
    topn_report: int = 10

    # Enrichment 제한 (GitHub Actions 30분 타임아웃 방어)
    max_enrich_count: int = 500  # 최대 enrichment 대상 IP 수
    enrich_workers: int = 10     # InternetDB 병렬 워커 수

    quotas: Quotas = Quotas()
    cache_ttl_hours: CacheTTLHours = CacheTTLHours()
    timeouts: ProviderTimeoutSec = ProviderTimeoutSec()
    ratelimit: ProviderRateLimit = ProviderRateLimit()


def load_settings() -> Settings:
    slack = os.getenv("SLACK_WEBHOOK_URL", "").strip()
    sb_url = os.getenv("SUPABASE_URL", "").strip()
    sb_key = os.getenv("SUPABASE_KEY", "").strip()

    if not slack:
        raise RuntimeError("SLACK_WEBHOOK_URL is required")
    if not sb_url or not sb_key:
        raise RuntimeError("SUPABASE_URL and SUPABASE_KEY are required (delta persistence)")

    abuse_key = os.getenv("ABUSEIPDB_API_KEY", "").strip() or None

    return Settings(
        slack_webhook_url=slack,
        supabase_url=sb_url,
        supabase_key=sb_key,
        abuseipdb_api_key=abuse_key,
    )
