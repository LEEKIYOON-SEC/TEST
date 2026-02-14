import os
import requests
import tarfile
import io
import re
import yaml
import yara
import time
from groq import Groq
from tenacity import retry, stop_after_attempt, wait_exponential, retry_if_exception_type
from typing import Dict, Optional, Tuple, List
from logger import logger
from config import config
from rate_limiter import rate_limit_manager

class RuleManagerError(Exception):
    """룰 관리 관련 에러"""
    pass

class GitHubSearchRateLimitError(Exception):
    """GitHub Search API 429 전용 에러 (재시도 제어용)"""
    pass

class RuleManager:
    """
    탐지 룰 생성 및 검증 전문가 (v2.2)
    
    v2.2 변경사항:
    - rate_limit_manager 통합 (github_search 전용 limit 사용)
    - 429 응답 시 Retry-After 파싱 후 대기
    - retry 전략을 wait_fixed → wait_exponential로 변경
    - 룰셋 다운로드에도 rate limit 적용
    - 불필요한 time.sleep(1) 제거 (rate_limit_manager가 관리)
    """
    
    def __init__(self):
        self.gh_token = os.environ.get("GH_TOKEN")
        self.groq_client = Groq(api_key=os.environ.get("GROQ_API_KEY"))
        self.model = config.MODEL_PHASE_1
        self.rules_cache: Dict[str, str] = {}
        
        logger.info("✅ RuleManager 초기화 완료 (정규식 검증 모드)")
    
    # ====================================================================
    # [1] 공개 룰 검색
    # ====================================================================
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=2, min=4, max=30),
        retry=retry_if_exception_type(GitHubSearchRateLimitError)
    )
    def _search_github(self, repo: str, query: str) -> Optional[str]:
        """
        GitHub Code Search로 공개 룰 찾기
        
        v2.2 변경사항:
        - rate_limit_manager.check_and_wait("github_search") 사용
        - 429 응답 시 handle_429() 호출 후 GitHubSearchRateLimitError 발생
        - 일반 HTTP 에러는 재시도하지 않고 None 반환 (무한 루프 방지)
        
        Args:
            repo: GitHub 리포지토리
            query: 검색어
        
        Returns:
            룰 코드 또는 None
        """
        logger.debug(f"GitHub 검색: {repo} / {query}")
        
        url = f"https://api.github.com/search/code?q=repo:{repo} {query}"
        headers = {
            "Authorization": f"token {self.gh_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        try:
            # ✅ rate_limit_manager로 통합 관리
            rate_limit_manager.check_and_wait("github_search")
            
            response = requests.get(url, headers=headers, timeout=10)
            
            # ✅ 429 전용 처리
            if response.status_code == 429:
                retry_after = response.headers.get("Retry-After")
                wait_seconds = float(retry_after) if retry_after else None
                
                logger.warning(
                    f"GitHub Search 429 수신 (Retry-After: {wait_seconds or 'N/A'}초)"
                )
                
                rate_limit_manager.handle_429("github_search", wait_seconds)
                raise GitHubSearchRateLimitError("429 Too Many Requests")
            
            # 429 외 에러
            response.raise_for_status()
            
            # ✅ 호출 기록
            rate_limit_manager.record_call("github_search")
            
            data = response.json()
            
            if data.get('total_count', 0) > 0:
                item = data['items'][0]
                logger.info(f"✅ 공개 룰 발견: {item['html_url']}")
                
                raw_url = item['html_url'].replace(
                    'github.com', 'raw.githubusercontent.com'
                ).replace('/blob/', '/')
                
                # Raw 파일 다운로드 (일반 GitHub API 사용)
                rate_limit_manager.check_and_wait("github")
                raw_response = requests.get(raw_url, timeout=10)
                raw_response.raise_for_status()
                rate_limit_manager.record_call("github")
                
                return raw_response.text
            
            logger.debug(f"공개 룰 없음: {repo}")
            return None
            
        except GitHubSearchRateLimitError:
            raise  # 재시도를 위해 전파
        except requests.exceptions.HTTPError as e:
            # 429 외의 HTTP 에러 (403, 422 등) → 재시도하지 않고 None
            logger.warning(f"GitHub 검색 HTTP 에러 ({repo}): {e}")
            return None
        except requests.exceptions.RequestException as e:
            # 네트워크 에러 → 로그만 남기고 None
            logger.warning(f"GitHub 검색 네트워크 에러 ({repo}): {e}")
            return None
        except Exception as e:
            logger.error(f"GitHub 검색 예상치 못한 에러: {e}")
            return None
    
    def _fetch_network_rules(self, cve_id: str) -> List[Dict[str, str]]:
        """
        네트워크 탐지 룰 수집 (Snort + Suricata)
        
        검색 대상:
        1. Snort 2.9 Community Rules
        2. Snort 3 Community Rules
        3. Snort 2.9 ET Open
        4. Suricata 5 ET Open
        5. Suricata 7 ET Open
        """
        logger.debug(f"네트워크 룰셋 검색 시작: {cve_id}")
        
        found_rules = []
        
        if not self.rules_cache:
            self._download_all_rulesets()
        
        for ruleset_name, ruleset_content in self.rules_cache.items():
            for line in ruleset_content.splitlines():
                if cve_id in line and "alert" in line and not line.strip().startswith("#"):
                    engine_type = self._detect_engine_type(ruleset_name)
                    
                    found_rules.append({
                        "code": line.strip(),
                        "source": ruleset_name,
                        "engine": engine_type
                    })
                    
                    logger.info(f"✅ {ruleset_name}에서 룰 발견")
                    break
        
        if not found_rules:
            logger.debug("모든 네트워크 룰셋에서 찾지 못함")
        else:
            logger.info(f"✅ 총 {len(found_rules)}개 엔진의 룰 발견")
        
        return found_rules
    
    def _download_all_rulesets(self):
        """
        모든 네트워크 룰셋 다운로드 (rate_limit_manager 적용)
        
        v2.2: ruleset_download rate limit 사용
        """
        logger.info("📥 네트워크 룰셋 다운로드 중...")
        
        # ===== 1. Snort Community Rules =====
        
        # 1-1. Snort 2.9 Community
        try:
            rate_limit_manager.check_and_wait("ruleset_download")
            logger.debug("  - Snort 2.9 Community 다운로드 중...")
            response = requests.get(
                "https://www.snort.org/downloads/community/community-rules.tar.gz",
                timeout=15
            )
            rate_limit_manager.record_call("ruleset_download")
            
            if response.status_code == 200:
                with tarfile.open(fileobj=io.BytesIO(response.content), mode="r:gz") as tar:
                    for member in tar.getmembers():
                        if "community.rules" in member.name:
                            f = tar.extractfile(member)
                            content = f.read().decode('utf-8', errors='ignore')
                            self.rules_cache["Snort 2.9 Community"] = content
                            logger.info("  ✅ Snort 2.9 Community 로드 완료")
                            break
        except Exception as e:
            logger.warning(f"  ⚠️ Snort 2.9 Community 다운로드 실패: {e}")
        
        # 1-2. Snort 3 Community
        try:
            rate_limit_manager.check_and_wait("ruleset_download")
            logger.debug("  - Snort 3 Community 다운로드 중...")
            response = requests.get(
                "https://www.snort.org/downloads/community/snort3-community-rules.tar.gz",
                timeout=15
            )
            rate_limit_manager.record_call("ruleset_download")
            
            if response.status_code == 200:
                with tarfile.open(fileobj=io.BytesIO(response.content), mode="r:gz") as tar:
                    for member in tar.getmembers():
                        if "snort3-community.rules" in member.name:
                            f = tar.extractfile(member)
                            content = f.read().decode('utf-8', errors='ignore')
                            self.rules_cache["Snort 3 Community"] = content
                            logger.info("  ✅ Snort 3 Community 로드 완료")
                            break
        except Exception as e:
            logger.warning(f"  ⚠️ Snort 3 Community 다운로드 실패: {e}")
        
        # ===== 2. Emerging Threats Open =====
        et_rulesets = [
            ("Snort 2.9 ET Open", "https://rules.emergingthreats.net/open/snort-2.9.0/emerging-all.rules"),
            ("Suricata 5 ET Open", "https://rules.emergingthreats.net/open/suricata-5.0/emerging-all.rules"),
            ("Suricata 7 ET Open", "https://rules.emergingthreats.net/open/suricata-7.0/emerging-all.rules"),
        ]
        
        for name, url in et_rulesets:
            try:
                rate_limit_manager.check_and_wait("ruleset_download")
                logger.debug(f"  - {name} 다운로드 중...")
                response = requests.get(url, timeout=15)
                rate_limit_manager.record_call("ruleset_download")
                
                if response.status_code == 200:
                    self.rules_cache[name] = response.text
                    logger.info(f"  ✅ {name} 로드 완료")
                else:
                    logger.debug(f"  ⚠️ {name} 다운로드 실패: HTTP {response.status_code}")
            except Exception as e:
                logger.debug(f"  ⚠️ {name} 다운로드 실패: {e}")
        
        logger.info(f"✅ 룰셋 다운로드 완료 ({len(self.rules_cache)}개 소스)")
    
    def _detect_engine_type(self, ruleset_name: str) -> str:
        """룰셋 이름에서 엔진 타입 추출"""
        name_lower = ruleset_name.lower()
        
        if "snort 2.9" in name_lower or "snort 2" in name_lower:
            return "snort2"
        elif "snort 3" in name_lower or "snort3" in name_lower:
            return "snort3"
        elif "suricata 5" in name_lower:
            return "suricata5"
        elif "suricata 7" in name_lower:
            return "suricata7"
        elif "suricata edge" in name_lower:
            return "suricata-edge"
        else:
            return "unknown"
    
    # ====================================================================
    # [2] 룰 검증 (정규식 기반)
    # ====================================================================
    
    def _validate_sigma(self, code: str) -> bool:
        """Sigma 룰 검증 (YAML 파싱 + 필수 필드 확인)"""
        try:
            data = yaml.safe_load(code)
            
            if not isinstance(data, dict):
                logger.warning("Sigma: YAML이 딕셔너리가 아님")
                return False
            
            required = ['title', 'logsource', 'detection']
            for field in required:
                if field not in data:
                    logger.warning(f"Sigma: 필수 필드 누락 - {field}")
                    return False
            
            logsource = data['logsource']
            if 'product' not in logsource and 'category' not in logsource:
                logger.warning("Sigma: logsource에 product 또는 category 필요")
                return False
            
            logger.debug("✅ Sigma 검증 통과")
            return True
            
        except yaml.YAMLError as e:
            logger.warning(f"Sigma: YAML 파싱 실패 - {e}")
            return False
        except Exception as e:
            logger.warning(f"Sigma: 예상치 못한 에러 - {e}")
            return False
    
    def _validate_yara(self, code: str) -> bool:
        """Yara 룰 검증 (컴파일 테스트)"""
        try:
            yara.compile(source=code)
            logger.debug("✅ Yara 검증 통과")
            return True
        except yara.SyntaxError as e:
            logger.warning(f"Yara: 문법 에러 - {e}")
            return False
        except Exception as e:
            logger.warning(f"Yara: 컴파일 실패 - {e}")
            return False
    
    def _validate_network_rule(self, code: str) -> bool:
        """네트워크 룰 검증 (6단계 정규식)"""
        code = code.strip()
        
        # 1단계: 기본 구조
        if not re.match(r'^(alert|log|pass|drop|reject|sdrop)\s+(tcp|udp|icmp|ip)\s', code, re.IGNORECASE):
            logger.warning("네트워크 룰: 기본 구조 불일치")
            return False
        
        # 2단계: 필수 요소
        required_patterns = [
            (r'\$\w+', "변수"),
            (r'\d+', "포트"),
            (r'->', "방향"),
            (r'\(', "옵션 시작"),
            (r'\)', "옵션 끝"),
        ]
        for pattern, name in required_patterns:
            if not re.search(pattern, code):
                logger.warning(f"네트워크 룰: {name} 누락")
                return False
        
        # 3단계: msg 필드
        if not re.search(r'msg:\s*["\'].*?["\']', code):
            logger.warning("네트워크 룰: msg 필드 누락")
            return False
        
        # 4단계: sid 필드
        if not re.search(r'sid:\s*\d+', code):
            logger.warning("네트워크 룰: sid 필드 누락")
            return False
        
        # 5단계: 문법 오류
        invalid_patterns = [
            (r'\(\s*\)', "빈 옵션 괄호"),
            (r';\s*;', "연속 세미콜론"),
            (r'\$[^\w]', "잘못된 변수"),
        ]
        for pattern, name in invalid_patterns:
            if re.search(pattern, code):
                logger.warning(f"네트워크 룰: {name} 감지")
                return False
        
        # 6단계: 괄호 균형
        if code.count('(') != code.count(')'):
            logger.warning("네트워크 룰: 괄호 불균형")
            return False
        
        logger.debug("✅ 네트워크 룰 정규식 검증 통과")
        return True
    
    # ====================================================================
    # [3] AI 룰 생성
    # ====================================================================
    
    def _check_observables(self, cve_data: Dict) -> Tuple[bool, str, List[str]]:
        """Observable Gate: 구체적 지표 확인"""
        desc = cve_data['description'].lower()
        
        indicators = []
        indicator_details = []
        
        # 파일 경로
        if '/' in cve_data['description']:
            indicators.append("파일 경로")
            paths = re.findall(r'/[a-zA-Z0-9_\-/\.]+', cve_data['description'])
            if paths:
                indicator_details.append(f"파일 경로 ({paths[0]})")
            else:
                indicator_details.append("파일 경로")
        
        # 웹 파일
        web_files = ['.php', '.jsp', '.asp', '.cgi']
        for ext in web_files:
            if ext in desc:
                indicators.append("웹 파일")
                indicator_details.append(f"웹 파일 ({ext})")
                break
        
        # URL 파라미터
        if 'parameter' in desc or 'param=' in desc or '?' in cve_data['description']:
            indicators.append("URL 파라미터")
            params = re.findall(r'\b\w+\s*=', cve_data['description'])
            if params:
                indicator_details.append(f"URL 파라미터 ({params[0]})")
            else:
                indicator_details.append("URL 파라미터")
        
        # HTTP 헤더
        if ('header' in desc and ('http' in desc or 'user-agent' in desc)):
            indicators.append("HTTP 헤더")
            indicator_details.append("HTTP 헤더")
        
        # Hex 값
        hex_match = re.search(r'0x[0-9a-f]{2,}', desc)
        if hex_match:
            indicators.append("Hex 값")
            indicator_details.append(f"Hex 값 ({hex_match.group()})")
        
        # 레지스트리
        if 'registry' in desc and 'hk' in desc:
            indicators.append("레지스트리")
            indicator_details.append("레지스트리 키")
        
        # 포트
        port_match = re.search(r'port\s+(\d+)', desc)
        if port_match:
            indicators.append("포트 번호")
            indicator_details.append(f"포트 ({port_match.group(1)})")
        
        has_enough = len(indicators) >= 1
        
        if has_enough:
            reason = f"발견된 지표: {', '.join(indicator_details)}"
        else:
            reason = "구체적 지표 부족"
        
        return has_enough, reason, indicator_details
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=2, min=4, max=30)
    )
    def _generate_ai_rule(self, rule_type: str, cve_data: Dict, analysis: Optional[Dict] = None) -> Optional[Tuple[str, List[str]]]:
        """
        AI 기반 탐지 룰 생성
        
        v2.2: groq rate limit 연동
        """
        logger.debug(f"AI {rule_type} 생성 시도")
        
        # Observable Gate
        indicator_details = []
        if rule_type not in ["Sigma", "sigma"]:
            has_indicators, reason, indicator_details = self._check_observables(cve_data)
            if not has_indicators:
                logger.info(f"⛔ {rule_type} 생성 SKIP: {reason}")
                return None
            else:
                logger.debug(f"✅ Observable Gate 통과: {reason}")
        
        prompt = self._build_rule_prompt(rule_type, cve_data, analysis)
        
        try:
            # ✅ Groq rate limit 체크
            rate_limit_manager.check_and_wait("groq")
            
            response = self.groq_client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=config.GROQ_RULE_PARAMS["temperature"],
                top_p=config.GROQ_RULE_PARAMS["top_p"],
                max_completion_tokens=config.GROQ_RULE_PARAMS["max_completion_tokens"],
                reasoning_effort=config.GROQ_RULE_PARAMS["reasoning_effort"]
            )
            
            # ✅ Groq 호출 기록
            rate_limit_manager.record_call("groq")
            
            content = response.choices[0].message.content.strip()
            content = re.sub(r"```[a-z]*\n|```", "", content).strip()
            
            if content == "SKIP" or not content:
                logger.info(f"⛔ AI가 {rule_type} 생성 거부 (근거 부족)")
                return None
            
            # 검증
            is_valid = False
            if rule_type in ["Snort", "Suricata", "snort", "suricata"]:
                is_valid = self._validate_network_rule(content)
            elif rule_type in ["Yara", "yara"]:
                is_valid = self._validate_yara(content)
            elif rule_type in ["Sigma", "sigma"]:
                is_valid = self._validate_sigma(content)
            
            if is_valid:
                logger.info(f"✅ AI {rule_type} 생성 및 검증 성공")
                return (content, indicator_details)
            else:
                logger.warning(f"❌ AI {rule_type} 검증 실패")
                logger.debug(f"실패한 룰:\n{content}")
                return None
                
        except Exception as e:
            logger.error(f"AI 룰 생성 에러: {e}")
            raise
    
    def _build_rule_prompt(self, rule_type: str, cve_data: Dict, analysis: Optional[Dict] = None) -> str:
        """
        AI를 위한 룰 생성 프롬프트 구성
        
        v2.3: References, Affected Products, AI Analysis 추가
        """
        references_str = "None"
        if cve_data.get('references'):
            refs = cve_data['references'][:3]
            references_str = "\n".join([f"- {ref}" for ref in refs])
        
        affected_str = "Unknown"
        if cve_data.get('affected'):
            affected_items = []
            for item in cve_data['affected'][:3]:
                vendor = item.get('vendor', 'Unknown')
                product = item.get('product', 'Unknown')
                versions = item.get('versions', 'Unknown')
                affected_items.append(f"- {vendor} {product} ({versions})")
            if affected_items:
                affected_str = "\n".join(affected_items)
        
        analysis_section = ""
        if analysis:
            root_cause = analysis.get('root_cause', 'N/A')
            attack_scenario = analysis.get('scenario', analysis.get('attack_scenario', 'N/A'))
            if root_cause != 'N/A' or attack_scenario != 'N/A':
                analysis_section = f"""
[AI Analysis - Additional Context]
Root Cause: {root_cause}
Attack Scenario: {attack_scenario}
"""
        
        base_prompt = f"""
You are a Senior Detection Engineer specializing in {rule_type} rules.
Write a valid {rule_type} detection rule for {cve_data['id']}.

[Context]
CVE-ID: {cve_data['id']}
Description: {cve_data['description']}
CVSS Vector: {cve_data.get('cvss_vector', 'N/A')}
CWE: {', '.join(cve_data.get('cwe', []))}

[Affected Products]
{affected_str}

[References]
{references_str}
{analysis_section}
[CRITICAL REQUIREMENTS]
1. **Observable Gate**: If no concrete indicator exists, return exactly: SKIP
2. **No Hallucination**: Use ONLY what's in the description, references, and analysis
3. **Syntax**: Follow standard {rule_type} syntax strictly
4. **Product-Specific**: If affected products are known, tailor the rule
5. **Conservative**: When uncertain, return SKIP

[Output Format]
- Return ONLY the raw rule code (no markdown, no explanation)
- If insufficient information, return exactly: SKIP
"""
        
        if rule_type in ["Snort", "Suricata", "snort", "suricata"]:
            base_prompt += """
[Snort/Suricata Template]
alert tcp $EXTERNAL_NET any -> $HTTP_SERVERS $HTTP_PORTS (
    msg:"CVE-XXXX Exploit Attempt";
    flow:to_server,established;
    content:"specific_string"; http_uri;
    pcre:"/pattern/i";
    classtype:web-application-attack;
    sid:1000001; rev:1;
)

Requirements:
- MUST include: msg, sid
- Use actual content/pcre from description
"""
        elif rule_type in ["Yara", "yara"]:
            base_prompt += """
[Yara Template]
rule CVE_XXXX_Indicator {
    meta:
        description = "Detects CVE-XXXX"
        author = "Argus-AI"
    strings:
        $s1 = "specific_string" ascii
    condition:
        any of ($s*)
}
"""
        elif rule_type in ["Sigma", "sigma"]:
            base_prompt += """
[Sigma Template]
title: CVE-XXXX Detection
status: experimental
description: Detects CVE-XXXX
logsource:
    product: windows
    category: process_creation
detection:
    selection:
        CommandLine|contains: 'pattern'
    condition: selection
level: high
"""
        
        return base_prompt
    
    # ====================================================================
    # [4] 메인 인터페이스
    # ====================================================================
    
    def get_rules(self, cve_data: Dict, feasibility: bool, analysis: Optional[Dict] = None) -> Dict:
        """
        CVE에 대한 탐지 룰 수집
        
        우선순위:
        1. 공개 룰 (신뢰도 100%)
        2. AI 생성 룰 (Observable Gate 통과 시, 검증 후 제공)
        """
        rules = {"sigma": None, "network": [], "yara": None}
        cve_id = cve_data['id']
        
        logger.info(f"룰 수집 시작: {cve_id}")
        
        # ===== Sigma =====
        try:
            public_sigma = self._search_github("SigmaHQ/sigma", f"{cve_id} filename:.yml")
            if public_sigma:
                rules['sigma'] = {
                    "code": public_sigma,
                    "source": "Public (SigmaHQ)",
                    "verified": True,
                    "indicators": None
                }
            else:
                ai_result = self._generate_ai_rule("Sigma", cve_data, analysis)
                if ai_result:
                    ai_sigma, indicators = ai_result
                    rules['sigma'] = {
                        "code": f"# ⚠️ AI-Generated - Review Required\n{ai_sigma}",
                        "source": "AI Generated (Validated)",
                        "verified": False,
                        "indicators": indicators
                    }
        except Exception as e:
            logger.warning(f"Sigma 룰 수집 실패: {e}")
        
        # ===== 네트워크 룰 (Snort + Suricata) =====
        try:
            network_rules = self._fetch_network_rules(cve_id)
            
            if network_rules:
                for rule_info in network_rules:
                    rules['network'].append({
                        "code": rule_info["code"],
                        "source": f"Public ({rule_info['source']})",
                        "engine": rule_info["engine"],
                        "verified": True,
                        "indicators": None
                    })
            else:
                ai_result = self._generate_ai_rule("Snort", cve_data, analysis)
                if ai_result:
                    ai_network, indicators = ai_result
                    rules['network'].append({
                        "code": f"# ⚠️ AI-Generated - Review Required\n{ai_network}",
                        "source": "AI Generated (Regex Validated)",
                        "engine": "generic",
                        "verified": False,
                        "indicators": indicators
                    })
        except Exception as e:
            logger.warning(f"네트워크 룰 수집 실패: {e}")
        
        # ===== Yara =====
        try:
            public_yara = self._search_github("Yara-Rules/rules", f"{cve_id} filename:.yar")
            if public_yara:
                rules['yara'] = {
                    "code": public_yara,
                    "source": "Public (Yara-Rules)",
                    "verified": True,
                    "indicators": None
                }
            else:
                ai_result = self._generate_ai_rule("Yara", cve_data, analysis)
                if ai_result:
                    ai_yara, indicators = ai_result
                    rules['yara'] = {
                        "code": f"// ⚠️ AI-Generated - Review Required\n{ai_yara}",
                        "source": "AI Generated (Compiled)",
                        "verified": False,
                        "indicators": indicators
                    }
        except Exception as e:
            logger.warning(f"Yara 룰 수집 실패: {e}")
        
        # 결과 요약
        sigma_found = "✅" if rules['sigma'] else "❌"
        network_count = len(rules['network'])
        network_found = f"✅ ({network_count}개)" if network_count > 0 else "❌"
        yara_found = "✅" if rules['yara'] else "❌"
        
        logger.info(f"룰 수집 완료: Sigma {sigma_found}, Network {network_found}, Yara {yara_found}")
        
        return rules
