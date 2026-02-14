import requests
import datetime
import pytz
import os
import re
import json
import time
from typing import List, Dict, Set, Optional
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from logger import logger

class CollectorError(Exception):
    """데이터 수집 관련 에러"""
    pass

class Collector:
    """
    CVE 데이터 수집 전문 클래스
    
    역할:
    1. KEV (Known Exploited Vulnerabilities) 수집
    2. EPSS (Exploit Prediction Scoring System) 수집
    3. GitHub CVE 리포지토리에서 최신 CVE 수집
    4. CVE 상세 정보 enrichment
    
    개선사항:
    - Rate Limit 관리로 API 차단 방지
    - 재시도 로직으로 일시적 네트워크 오류 극복
    - 명확한 에러 로깅으로 문제 추적 용이
    """
    
    def __init__(self):
        self.kev_set: Set[str] = set()
        self.epss_cache: Dict[str, float] = {}
        self.headers = {
            "Authorization": f"token {os.environ.get('GH_TOKEN')}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        # Rate Limit 추적
        self._last_api_call = {
            "github": 0,
            "epss": 0,
            "kev": 0
        }
    
    def _rate_limit_wait(self, api_name: str, delay: float = 1.0):
        """
        API Rate Limit 관리
        
        마지막 호출 후 일정 시간이 지나지 않았으면 대기합니다.
        이렇게 하면 API 서버가 차단하는 것을 방지할 수 있습니다.
        
        Args:
            api_name: API 이름 (github, epss, kev)
            delay: 최소 대기 시간 (초)
        """
        now = time.time()
        last_call = self._last_api_call.get(api_name, 0)
        elapsed = now - last_call
        
        if elapsed < delay:
            wait_time = delay - elapsed
            logger.debug(f"Rate limit: waiting {wait_time:.1f}s for {api_name}")
            time.sleep(wait_time)
        
        self._last_api_call[api_name] = time.time()
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10),
        retry=retry_if_exception_type(requests.exceptions.RequestException)
    )
    def fetch_kev(self) -> bool:
        """
        CISA KEV 목록 다운로드
        
        KEV는 Known Exploited Vulnerabilities의 약자로,
        실제로 악용되고 있는 취약점 목록입니다.
        이 목록에 있는 CVE는 최우선으로 패치해야 합니다.
        
        Returns:
            성공 여부
        
        재시도 로직 설명:
        - 최대 3번 재시도
        - 실패할 때마다 2초, 4초, 8초로 대기 시간 증가 (exponential backoff)
        - 이렇게 하면 서버가 일시적으로 불안정해도 결국 성공할 확률이 높아집니다
        """
        url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
        
        try:
            self._rate_limit_wait("kev", 2.0)
            logger.info("Fetching CISA KEV list...")
            
            response = requests.get(url, timeout=15)
            response.raise_for_status()
            
            data = response.json()
            self.kev_set = {vuln['cveID'] for vuln in data.get('vulnerabilities', [])}
            
            logger.info(f"Loaded {len(self.kev_set)} KEV entries")
            return True
            
        except requests.exceptions.Timeout:
            logger.error(f"KEV API timeout after 15s")
            return False
        except requests.exceptions.RequestException as e:
            logger.error(f"KEV fetch failed: {e}")
            raise  # 재시도를 위해 예외를 다시 발생시킴
        except Exception as e:
            logger.error(f"Unexpected error in fetch_kev: {e}")
            return False
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    def fetch_epss(self, cve_ids: List[str]) -> Dict[str, float]:
        """
        EPSS 점수 배치 수집
        
        EPSS는 CVE가 실제로 악용될 확률을 예측합니다.
        예: EPSS 0.8 = 80% 확률로 악용될 것으로 예상
        
        Args:
            cve_ids: CVE ID 리스트
        
        Returns:
            CVE ID → EPSS 점수 딕셔너리
        
        배치 처리하는 이유:
        - CVE를 하나씩 요청하면 너무 느립니다
        - 한 번에 50개씩 묶어서 요청하면 훨씬 빠릅니다
        """
        if not cve_ids:
            return {}
        
        chunk_size = 50
        total_chunks = (len(cve_ids) + chunk_size - 1) // chunk_size
        
        logger.info(f"Fetching EPSS scores for {len(cve_ids)} CVEs ({total_chunks} batches)")
        
        for i in range(0, len(cve_ids), chunk_size):
            chunk = cve_ids[i:i + chunk_size]
            chunk_num = (i // chunk_size) + 1
            
            try:
                self._rate_limit_wait("epss", 1.0)
                
                url = f"https://api.first.org/data/v1/epss?cve={','.join(chunk)}"
                response = requests.get(url, timeout=10)
                response.raise_for_status()
                
                for item in response.json().get('data', []):
                    cve_id = item.get('cve')
                    epss = float(item.get('epss', 0.0))
                    self.epss_cache[cve_id] = epss
                
                logger.debug(f"EPSS batch {chunk_num}/{total_chunks} complete")
                
            except Exception as e:
                logger.warning(f"EPSS batch {chunk_num} failed: {e}")
                # 배치 하나 실패해도 계속 진행
                continue
        
        return self.epss_cache
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    def fetch_recent_cves(self, hours: int = 2) -> List[str]:
        """
        GitHub CVEProject에서 최근 CVE 수집
        
        CVEProject/cvelistV5는 모든 CVE의 공식 저장소입니다.
        여기서 최근 N시간 내에 업데이트된 CVE를 찾습니다.
        
        Args:
            hours: 최근 N시간 내 CVE
        
        Returns:
            CVE ID 리스트
        
        작동 원리:
        1. GitHub Commits API로 최근 커밋 가져오기
        2. 각 커밋의 파일 변경 내역 확인
        3. CVE-YYYY-NNNNN 형식의 파일명 추출
        """
        now = datetime.datetime.now(pytz.UTC)
        since_str = (now - datetime.timedelta(hours=hours)).strftime("%Y-%m-%dT%H:%M:%SZ")
        
        url = f"https://api.github.com/repos/CVEProject/cvelistV5/commits?since={since_str}"
        
        try:
            self._rate_limit_wait("github", 1.0)
            logger.info(f"Fetching CVEs from last {hours} hours...")
            
            response = requests.get(url, headers=self.headers, timeout=15)
            response.raise_for_status()
            
            commits = response.json()
            cve_ids = set()
            
            for commit in commits:
                self._rate_limit_wait("github", 0.5)
                
                commit_response = requests.get(commit['url'], headers=self.headers, timeout=10)
                commit_response.raise_for_status()
                
                for file in commit_response.json().get('files', []):
                    filename = file['filename']
                    
                    if filename.endswith(".json") and "CVE-" in filename:
                        match = re.search(r'(CVE-\d{4}-\d{4,7})', filename)
                        if match:
                            cve_ids.add(match.group(1))
            
            cve_list = list(cve_ids)
            logger.info(f"Found {len(cve_list)} unique CVEs")
            return cve_list
            
        except requests.exceptions.RequestException as e:
            logger.error(f"GitHub API error: {e}")
            raise
        except Exception as e:
            logger.error(f"Unexpected error in fetch_recent_cves: {e}")
            return []
    
    def parse_affected(self, affected_list: List[Dict]) -> List[Dict]:
        """
        Affected 정보 파싱
        
        CVE JSON에서 "어떤 벤더의 어떤 제품이 영향받는지" 정보를 추출합니다.
        복잡한 버전 정보를 한국어로 읽기 쉽게 변환합니다.
        
        예:
        - "3.0 부터 3.5 이전"
        - "4.1 이하"
        - "2.0 (단일 버전)"
        """
        results = []
        
        for item in affected_list:
            vendor = item.get('vendor', 'Unknown')
            product = item.get('product', 'Unknown')
            versions = []
            
            for v in item.get('versions', []):
                version = v.get('version', '')
                less_than = v.get('lessThan', '')
                less_than_eq = v.get('lessThanOrEqual', '')
                ver_str = ""
                
                if v.get('status') == "affected":
                    if version and version not in ["0", "n/a"]:
                        ver_str += f"{version} 부터 "
                    if less_than:
                        ver_str += f"{less_than} 이전"
                    elif less_than_eq:
                        ver_str += f"{less_than_eq} 이하"
                    elif not less_than and not less_than_eq and version:
                        ver_str = f"{version} (단일 버전)"
                    
                    if not ver_str:
                        ver_str = "모든 버전"
                    
                    versions.append(ver_str.strip())
            
            results.append({
                "vendor": vendor,
                "product": product,
                "versions": ", ".join(versions) if versions else "정보 없음"
            })
        
        return results
    
    @retry(
        stop=stop_after_attempt(2),
        wait=wait_exponential(multiplier=1, min=1, max=5)
    )
    def enrich_cve(self, cve_id: str) -> Dict:
        """
        CVE 상세 정보 수집
        
        CVE ID만으로는 제목, 설명, CVSS 점수 등을 알 수 없습니다.
        GitHub의 원본 JSON 파일을 다운로드해서 모든 정보를 추출합니다.
        
        Args:
            cve_id: CVE-2024-12345 형식
        
        Returns:
            CVE 전체 정보 딕셔너리
        
        파일 경로 규칙:
        CVE-2024-12345 → cves/2024/12xxx/CVE-2024-12345.json
        """
        try:
            self._rate_limit_wait("github", 0.5)
            
            # CVE ID를 파일 경로로 변환
            parts = cve_id.split('-')
            year, id_num = parts[1], parts[2]
            group_dir = "0xxx" if len(id_num) < 4 else id_num[:-3] + "xxx"
            
            raw_url = f"https://raw.githubusercontent.com/CVEProject/cvelistV5/main/cves/{year}/{group_dir}/{cve_id}.json"
            
            response = requests.get(raw_url, timeout=10)
            response.raise_for_status()
            
            json_data = response.json()
            cna = json_data.get('containers', {}).get('cna', {})
            
            # 기본 데이터 구조
            data = {
                "id": cve_id,
                "title": "N/A",
                "cvss": 0.0,
                "cvss_vector": "N/A",
                "description": "N/A",
                "state": "UNKNOWN",
                "cwe": [],
                "references": [],
                "affected": [],
                "cce": []
            }
            
            # 상태
            data['state'] = json_data.get('cveMetadata', {}).get('state', 'UNKNOWN')
            
            # 제목
            data['title'] = cna.get('title', 'N/A')
            
            # 영향받는 제품
            data['affected'] = self.parse_affected(cna.get('affected', []))
            
            # 설명 (영어만)
            for desc in cna.get('descriptions', []):
                if desc.get('lang') == 'en':
                    data['description'] = desc.get('value', 'N/A')
                    break
            
            # CVSS 점수 (v4.0 → v3.1 → v3.0 우선순위)
            for metric in cna.get('metrics', []):
                if 'cvssV4_0' in metric:
                    data['cvss'] = metric['cvssV4_0'].get('baseScore', 0.0)
                    data['cvss_vector'] = metric['cvssV4_0'].get('vectorString', 'N/A')
                    break
                elif 'cvssV3_1' in metric:
                    data['cvss'] = metric['cvssV3_1'].get('baseScore', 0.0)
                    data['cvss_vector'] = metric['cvssV3_1'].get('vectorString', 'N/A')
                    break
                elif 'cvssV3_0' in metric:
                    data['cvss'] = metric['cvssV3_0'].get('baseScore', 0.0)
                    data['cvss_vector'] = metric['cvssV3_0'].get('vectorString', 'N/A')
                    break
            
            # CWE (취약점 유형)
            for pt in cna.get('problemTypes', []):
                for desc in pt.get('descriptions', []):
                    cwe_id = desc.get('cweId', desc.get('description', ''))
                    if cwe_id:
                        data['cwe'].append(cwe_id)
            
            # 참고 자료
            for ref in cna.get('references', []):
                if 'url' in ref:
                    data['references'].append(ref['url'])
            
            # CCE (Windows 설정 열거) - 보너스 정보
            json_str = json.dumps(json_data)
            cce_matches = re.findall(r'(CCE-\d{4,}-\d+)', json_str)
            if cce_matches:
                data['cce'] = list(set(cce_matches))
            
            logger.debug(f"Enriched {cve_id}: CVSS={data['cvss']}, State={data['state']}")
            return data
            
        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                logger.warning(f"{cve_id} not found (404)")
            else:
                logger.error(f"{cve_id} HTTP error: {e}")
            return self._error_response(cve_id)
        except Exception as e:
            logger.error(f"{cve_id} enrichment failed: {e}")
            return self._error_response(cve_id)
    
    def _error_response(self, cve_id: str) -> Dict:
        """에러 발생 시 기본 응답"""
        return {
            "id": cve_id,
            "title": "Error",
            "cvss": 0.0,
            "cvss_vector": "N/A",
            "description": "Error",
            "state": "ERROR",
            "cwe": [],
            "references": [],
            "affected": [],
            "cce": []
        }
