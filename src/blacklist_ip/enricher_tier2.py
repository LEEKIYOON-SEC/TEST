# src/blacklist_ip/enricher_tier2.py
import datetime as dt
import time
from dataclasses import dataclass
from typing import Any, Dict, List, Optional, Tuple

import requests


@dataclass
class APIUsage:
    abuseipdb: int = 0
    internetdb: int = 0


class SimpleRateLimiter:
    """
    가장 단순한 글로벌 레이트리밋(요청 간 최소 간격).
    Free-tier/공개 엔드포인트에서 429를 줄이는 목적.
    """
    def __init__(self, min_interval_sec: float):
        self.min_interval_sec = max(0.0, float(min_interval_sec))
        self._last = 0.0

    def wait(self) -> None:
        if self.min_interval_sec <= 0:
            return
        now = time.time()
        elapsed = now - self._last
        if elapsed < self.min_interval_sec:
            time.sleep(self.min_interval_sec - elapsed)
        self._last = time.time()


def _utc_now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def _safe_json(resp: requests.Response) -> Dict[str, Any]:
    try:
        j = resp.json()
        return j if isinstance(j, dict) else {}
    except Exception:
        return {}


class Enricher:
    """
    Tier 2: "어제 대비 신규 IP"만 enrichment.
    - Provider: AbuseIPDB + Shodan InternetDB
    - 캐시 우선, 하드캡, 부분 실패 허용
    """

    def __init__(
        self,
        abuseipdb_key: Optional[str],
        store,  # store_supabase.Store
        quotas,
        cache_ttl_hours,
        timeouts,
        ratelimit,
    ):
        self.abuseipdb_key = abuseipdb_key
        self.store = store
        self.quotas = quotas
        self.cache_ttl_hours = cache_ttl_hours
        self.timeouts = timeouts
        self.ratelimit = ratelimit

        self.usage = APIUsage()

        self.rl_abuse = SimpleRateLimiter(self.ratelimit.abuseipdb_min_interval)
        self.rl_inetdb = SimpleRateLimiter(self.ratelimit.internetdb_min_interval)

    def enrich_many(self, ips: List[str]) -> Dict[str, Dict[str, Any]]:
        """
        returns:
          {
            "1.2.3.4": {
               "abuseipdb": {...}?,
               "internetdb": {...}?
            },
            ...
          }
        """
        result: Dict[str, Dict[str, Any]] = {}

        for ip in ips:
            result[ip] = {}

            abuse = self._get_cached_or_fetch_abuseipdb(ip)
            if abuse is not None:
                result[ip]["abuseipdb"] = abuse

            inetdb = self._get_cached_or_fetch_internetdb(ip)
            if inetdb is not None:
                result[ip]["internetdb"] = inetdb

        return result

    # -------------------------
    # AbuseIPDB
    # -------------------------
    def _get_cached_or_fetch_abuseipdb(self, ip: str) -> Optional[Dict[str, Any]]:
        if not self.abuseipdb_key:
            return None

        cached = self.store.get_cache(ip, "abuseipdb")
        if cached is not None:
            return cached

        if self.usage.abuseipdb >= int(self.quotas.abuseipdb_daily_max):
            return None

        try:
            self.rl_abuse.wait()
            data = self._fetch_abuseipdb(ip)
            self.usage.abuseipdb += 1

            ttl = _utc_now() + dt.timedelta(hours=int(self.cache_ttl_hours.abuseipdb))
            self.store.put_cache(ip, "abuseipdb", data, ttl)
            return data
        except Exception:
            # 부분 실패 허용: 이 IP의 abuseipdb는 결측으로 남김
            return None

    def _fetch_abuseipdb(self, ip: str) -> Dict[str, Any]:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": self.abuseipdb_key, "Accept": "application/json"}
        params = {
            "ipAddress": ip,
            "maxAgeInDays": 90,
            "verbose": ""  # verbose mode
        }

        r = requests.get(url, headers=headers, params=params, timeout=int(self.timeouts.abuseipdb))
        r.raise_for_status()
        j = _safe_json(r)
        # 핵심만 저장(응답 전체를 저장하면 DB 비용 증가)
        data = j.get("data", {}) if isinstance(j.get("data", {}), dict) else {}
        return {
            "abuseConfidenceScore": data.get("abuseConfidenceScore"),
            "totalReports": data.get("totalReports"),
            "lastReportedAt": data.get("lastReportedAt"),
            "countryCode": data.get("countryCode"),
            "usageType": data.get("usageType"),
            "isp": data.get("isp"),
            "domain": data.get("domain"),
            "hostnames": data.get("hostnames"),
        }

    # -------------------------
    # Shodan InternetDB (키 불필요)
    # -------------------------
    def _get_cached_or_fetch_internetdb(self, ip: str) -> Optional[Dict[str, Any]]:
        cached = self.store.get_cache(ip, "internetdb")
        if cached is not None:
            return cached

        if self.usage.internetdb >= int(self.quotas.internetdb_daily_max):
            return None

        try:
            self.rl_inetdb.wait()
            data = self._fetch_internetdb(ip)
            self.usage.internetdb += 1

            ttl = _utc_now() + dt.timedelta(hours=int(self.cache_ttl_hours.internetdb))
            self.store.put_cache(ip, "internetdb", data, ttl)
            return data
        except Exception:
            return None

    def _fetch_internetdb(self, ip: str) -> Dict[str, Any]:
        """
        InternetDB는 보통 아래 형태로 응답:
        {
          "ip": "1.2.3.4",
          "ports": [80, 443],
          "hostnames": [],
          "tags": [],
          "cpes": [],
          "vulns": []
        }

        NOTE:
        - 없는 IP는 404로 올 수 있음 -> 예외로 처리되어 None 반환(호출부에서)
        """
        url = f"https://internetdb.shodan.io/{ip}"
        r = requests.get(url, timeout=int(self.timeouts.internetdb))
        if r.status_code == 404:
            # 데이터 없음은 정상 케이스
            raise RuntimeError("InternetDB: not found")
        r.raise_for_status()
        j = _safe_json(r)

        ports = j.get("ports", [])
        if not isinstance(ports, list):
            ports = []

        # 저장 비용을 위해 최소만
        return {
            "ports": [p for p in ports if isinstance(p, int)],
            "tags": j.get("tags", []),
            "cpes": j.get("cpes", []),
            "vulns": j.get("vulns", []),
            "hostnames": j.get("hostnames", []),
        }
