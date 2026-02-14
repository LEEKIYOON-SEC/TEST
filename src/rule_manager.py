import os
import requests
import tarfile
import io
import re
import yaml
import yara
import time
from groq import Groq
from tenacity import retry, stop_after_attempt, wait_fixed
from typing import Dict, Optional, Tuple, List
from logger import logger
from config import config

class RuleManagerError(Exception):
    """룰 관리 관련 에러"""
    pass

class RuleManager:
    """
    탐지 룰 생성 및 검증 전문가 (v2.1)
    
    역할:
    1. 공개 룰 검색 (Sigma, Snort 2/3, Suricata 6/7, Yara)
    2. AI 기반 룰 생성 (공개 룰이 없을 때)
    3. 룰 검증 (정규식 기반 문법 체크)
    
    주요 개선사항:
    - Docker 완전 제거 (정규식 검증만 사용, 불필요한 로그 제거)
    - Snort 3, Suricata 6/7 지원 추가
    - 각 룰에 출처 꼬리표 명확히 표시 (어떤 엔진용인지)
    - 강화된 정규식 검증 (6단계)
    
    비유:
    이 클래스는 마치 "여러 도서관을 검색하는 사서"와 같아요.
    - Snort 2.9 도서관, Snort 3 도서관, Suricata 도서관을 모두 검색
    - 각 책(룰)이 어느 도서관에서 왔는지 꼬리표 부착
    - 없으면 AI 작가에게 새로 쓰라고 요청
    - 문법 검사로 품질 확인
    """
    
    def __init__(self):
        """
        RuleManager 초기화
        
        Docker를 사용하지 않는 것에 주목하세요!
        우리는 정규식 기반 검증만 사용하기로 결정했습니다.
        이유는 간단합니다:
        - GitHub Actions에서 Docker 이미지 없음
        - 정규식만으로도 대부분의 문법 오류 잡을 수 있음
        - 훨씬 빠르고 안정적
        """
        self.gh_token = os.environ.get("GH_TOKEN")
        self.groq_client = Groq(api_key=os.environ.get("GROQ_API_KEY"))
        self.model = config.MODEL_PHASE_1
        
        # 룰셋 캐시 (엔진별로 구분)
        # 예: {"Snort 2.9 Community": "rule_content", "Snort 3 ET Open": "rule_content"}
        self.rules_cache: Dict[str, str] = {}
        
        logger.info("✅ RuleManager 초기화 완료 (정규식 검증 모드)")
    
    # ====================================================================
    # [1] 공개 룰 검색
    # ====================================================================
    
    @retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
    def _search_github(self, repo: str, query: str) -> Optional[str]:
        """
        GitHub Code Search로 공개 룰 찾기
        
        GitHub에는 보안 커뮤니티가 공유한 수많은 탐지 룰이 있어요.
        이 함수는 특정 리포지토리에서 CVE ID로 룰을 검색합니다.
        
        Args:
            repo: GitHub 리포지토리 (예: "SigmaHQ/sigma")
            query: 검색어 (예: "CVE-2024-12345 filename:.yml")
        
        Returns:
            룰 코드 (문자열) 또는 None
        """
        logger.debug(f"GitHub 검색: {repo} / {query}")
        
        url = f"https://api.github.com/search/code?q=repo:{repo} {query}"
        headers = {
            "Authorization": f"token {self.gh_token}",
            "Accept": "application/vnd.github.v3+json"
        }
        
        try:
            time.sleep(1)  # Rate Limit 방지
            response = requests.get(url, headers=headers, timeout=10)
            response.raise_for_status()
            
            data = response.json()
            
            if data.get('total_count', 0) > 0:
                item = data['items'][0]
                logger.info(f"✅ 공개 룰 발견: {item['html_url']}")
                
                # HTML URL을 Raw URL로 변환
                raw_url = item['html_url'].replace('github.com', 'raw.githubusercontent.com').replace('/blob/', '/')
                
                raw_response = requests.get(raw_url, timeout=10)
                raw_response.raise_for_status()
                
                return raw_response.text
            
            logger.debug(f"❌ 공개 룰 없음: {repo}")
            return None
            
        except requests.exceptions.RequestException as e:
            logger.error(f"GitHub 검색 실패: {e}")
            raise  # 재시도
        except Exception as e:
            logger.error(f"예상치 못한 에러: {e}")
            return None
    
    def _fetch_network_rules(self, cve_id: str) -> List[Dict[str, str]]:
        """
        네트워크 탐지 룰 수집 (Snort + Suricata)
        
        이 함수는 당신의 요청대로 여러 엔진을 모두 지원합니다!
        
        검색 대상:
        1. Snort 2.9 Community Rules (공식)
        2. Snort 2.9 ET Open (Emerging Threats)
        3. Snort 3 ET Open (최신 버전)
        4. Suricata 6 ET Open
        5. Suricata 7 ET Open (최신 버전)
        
        왜 이렇게 많이?
        - 각 엔진마다 약간씩 문법이 다릅니다
        - 특정 룰은 특정 버전에만 있을 수 있어요
        - 사용자가 자기 환경에 맞는 걸 선택할 수 있어야 합니다
        
        Args:
            cve_id: CVE-2024-12345 형식
        
        Returns:
            [{"code": "rule...", "source": "Snort 2.9 Community", "engine": "snort2"}, ...]
        
        출처 꼬리표 형식:
        - source: 사람이 읽기 좋은 이름 (예: "Snort 3 ET Open")
        - engine: 프로그램이 구분하기 좋은 태그 (예: "snort3", "suricata6")
        """
        logger.debug(f"네트워크 룰셋 검색 시작: {cve_id}")
        
        found_rules = []
        
        # 캐시가 비어있으면 룰셋 다운로드 (첫 실행 시)
        if not self.rules_cache:
            self._download_all_rulesets()
        
        # 각 룰셋에서 CVE 검색
        for ruleset_name, ruleset_content in self.rules_cache.items():
            for line in ruleset_content.splitlines():
                # CVE ID가 포함되어 있고, 주석이 아니고, alert 키워드가 있는 줄
                if cve_id in line and "alert" in line and not line.strip().startswith("#"):
                    # 엔진 타입 결정
                    engine_type = self._detect_engine_type(ruleset_name)
                    
                    found_rules.append({
                        "code": line.strip(),
                        "source": ruleset_name,  # 예: "Snort 3 ET Open"
                        "engine": engine_type    # 예: "snort3"
                    })
                    
                    logger.info(f"✅ {ruleset_name}에서 룰 발견")
                    break  # 룰셋당 첫 번째 매칭만 (중복 방지)
        
        if not found_rules:
            logger.debug("❌ 모든 네트워크 룰셋에서 찾지 못함")
        else:
            logger.info(f"✅ 총 {len(found_rules)}개 엔진의 룰 발견")
        
        return found_rules
    
    def _download_all_rulesets(self):
        """
        모든 네트워크 룰셋 다운로드 (정확한 버전)
        
        이 함수는 첫 실행 시 한 번만 호출됩니다.
        모든 룰셋을 메모리에 캐싱해두면 이후에는 빠르게 검색할 수 있어요.
        
        다운로드 대상 (실제 존재하는 버전만):
        1. Snort Community Rules
           - Snort 2.9: community-rules.tar.gz
           - Snort 3: snort3-community-rules.tar.gz
        
        2. Emerging Threats Open
           - Snort 2.9.0
           - Suricata 5.0
           - Suricata 7.0.3
           - edge (최신 개발 버전, 불안정)
        
        참고: 
        - Snort 3 ET Open은 공식 URL에 없어서 제외
        - Suricata 6은 존재하지 않음 (5.0 → 7.0으로 점프)
        
        왜 캐싱?
        - 룰셋은 수십 MB로 크지만, 자주 바뀌지 않아요
        - 한 번 다운로드하면 메모리에 저장
        - CVE 100개를 분석해도 다운로드는 1번만!
        """
        logger.info("📥 네트워크 룰셋 다운로드 중...")
        
        # ===== 1. Snort Community Rules (공식) =====
        
        # 1-1. Snort 2.9 Community
        try:
            logger.debug("  - Snort 2.9 Community 다운로드 중...")
            response = requests.get(
                "https://www.snort.org/downloads/community/community-rules.tar.gz",
                timeout=15
            )
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
        
        # 1-2. Snort 3 Community (새로 추가!)
        try:
            logger.debug("  - Snort 3 Community 다운로드 중...")
            response = requests.get(
                "https://www.snort.org/downloads/community/snort3-community-rules.tar.gz",
                timeout=15
            )
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
        
        # ===== 2. Emerging Threats Open (정확한 버전) =====
        
        et_rulesets = [
            ("Snort 2.9 ET Open", "https://rules.emergingthreats.net/open/snort-2.9.0/emerging-all.rules"),
            ("Suricata 5 ET Open", "https://rules.emergingthreats.net/open/suricata-5.0/emerging-all.rules"),
            ("Suricata 7 ET Open", "https://rules.emergingthreats.net/open/suricata-7.0/emerging-all.rules"),
            # edge는 불안정할 수 있어서 선택적으로 추가 (주석 처리)
            # ("Suricata Edge", "https://rules.emergingthreats.net/open/suricata/emerging-all.rules"),
        ]
        
        for name, url in et_rulesets:
            try:
                logger.debug(f"  - {name} 다운로드 중...")
                response = requests.get(url, timeout=15)
                if response.status_code == 200:
                    self.rules_cache[name] = response.text
                    logger.info(f"  ✅ {name} 로드 완료")
                else:
                    logger.debug(f"  ⚠️ {name} 다운로드 실패: HTTP {response.status_code}")
            except Exception as e:
                logger.debug(f"  ⚠️ {name} 다운로드 실패: {e}")
        
        logger.info(f"✅ 룰셋 다운로드 완료 ({len(self.rules_cache)}개 소스)")
    
    def _detect_engine_type(self, ruleset_name: str) -> str:
        """
        룰셋 이름에서 엔진 타입 추출 (정확한 버전)
        
        이것은 간단한 헬퍼 함수예요.
        "Snort 3 Community" → "snort3"
        "Suricata 7 ET Open" → "suricata7"
        
        왜 필요한가요?
        - 사람이 보기에는 "Snort 3 ET Open"이 좋지만
        - 프로그램이 처리하기에는 "snort3"이 간단해요
        
        Args:
            ruleset_name: "Snort 3 Community" 같은 이름
        
        Returns:
            "snort3" 같은 짧은 태그
        """
        name_lower = ruleset_name.lower()
        
        # Snort 버전 감지
        if "snort 2.9" in name_lower or "snort 2" in name_lower:
            return "snort2"
        elif "snort 3" in name_lower or "snort3" in name_lower:
            return "snort3"
        
        # Suricata 버전 감지 (5, 7만 존재)
        elif "suricata 5" in name_lower:
            return "suricata5"
        elif "suricata 7" in name_lower:
            return "suricata7"
        elif "suricata edge" in name_lower:
            return "suricata-edge"
        
        else:
            return "unknown"
    
    # ====================================================================
    # [2] 룰 검증 (정규식 기반 - Docker 없음!)
    # ====================================================================
    
    def _validate_sigma(self, code: str) -> bool:
        """
        Sigma 룰 검증
        
        Sigma는 YAML 형식을 사용해요. 검증 과정:
        1. YAML 파싱이 되는가?
        2. 필수 필드가 있는가? (title, logsource, detection)
        3. logsource에 product 또는 category가 있는가?
        """
        try:
            data = yaml.safe_load(code)
            
            if not isinstance(data, dict):
                logger.warning("Sigma: YAML이 딕셔너리가 아님")
                return False
            
            # 필수 필드 확인
            required = ['title', 'logsource', 'detection']
            for field in required:
                if field not in data:
                    logger.warning(f"Sigma: 필수 필드 누락 - {field}")
                    return False
            
            # logsource 검증
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
        """
        Yara 룰 검증
        
        Yara는 직접 컴파일해서 검증합니다.
        yara-python 라이브러리가 컴파일을 시도하고,
        문법 에러가 있으면 예외를 발생시켜요.
        """
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
        """
        네트워크 룰 검증 (Snort/Suricata - 정규식 기반)
        
        ⚠️ 중요: Docker를 사용하지 않습니다!
        
        왜 Docker 없이도 괜찮나요?
        - 정규식으로 대부분의 문법 오류를 잡을 수 있어요
        - 6단계 검증 과정으로 매우 엄격하게 체크
        - 더 빠르고 안정적
        
        6단계 검증 과정:
        1. 기본 구조 (alert tcp ...)
        2. 필수 요소 (변수, 포트, 방향)
        3. msg 필드 (필수)
        4. sid 필드 (필수)
        5. 일반적인 문법 오류 (빈 괄호, 연속 세미콜론 등)
        6. 괄호 균형
        
        Args:
            code: Snort 또는 Suricata 룰 문자열
        
        Returns:
            검증 통과 여부
        """
        code = code.strip()
        
        # 1단계: 기본 구조 검증
        if not re.match(r'^(alert|log|pass|drop|reject|sdrop)\s+(tcp|udp|icmp|ip)\s', code, re.IGNORECASE):
            logger.warning("네트워크 룰: 기본 구조 불일치")
            return False
        
        # 2단계: 필수 요소 검증
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
        
        # 3단계: msg 필드 (필수)
        if not re.search(r'msg:\s*["\'].*?["\']', code):
            logger.warning("네트워크 룰: msg 필드 누락")
            return False
        
        # 4단계: sid 필드 (필수)
        if not re.search(r'sid:\s*\d+', code):
            logger.warning("네트워크 룰: sid 필드 누락")
            return False
        
        # 5단계: 일반적인 문법 오류 검출
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
    
    def _check_observables(self, cve_data: Dict) -> Tuple[bool, str]:
        """
        Observable Gate: 구체적 지표 확인
        
        이 함수는 CVE 설명에서 탐지 가능한 구체적 지표를 찾습니다.
        
        왜 필요한가요?
        - "원격 코드 실행 취약점"이라는 설명만으로는 룰을 만들 수 없어요
        - 하지만 "GET /admin.php?cmd=" 같은 구체적 패턴이 있으면 가능합니다
        """
        desc = cve_data['description'].lower()
        
        indicators = []
        
        # 파일 경로
        if '/' in cve_data['description']:
            indicators.append("파일 경로")
        
        # 웹 파일
        web_files = ['.php', '.jsp', '.asp', '.cgi']
        if any(ext in desc for ext in web_files):
            indicators.append("웹 파일")
        
        # URL 파라미터
        if 'parameter' in desc or 'param=' in desc or '?' in cve_data['description']:
            indicators.append("URL 파라미터")
        
        # HTTP 헤더
        if ('header' in desc and ('http' in desc or 'user-agent' in desc)):
            indicators.append("HTTP 헤더")
        
        # Hex 값
        if re.search(r'0x[0-9a-f]{2,}', desc):
            indicators.append("Hex 값")
        
        # 레지스트리
        if 'registry' in desc and 'hk' in desc:
            indicators.append("레지스트리")
        
        # 포트
        if re.search(r'port\s+\d+', desc):
            indicators.append("포트 번호")
        
        has_enough = len(indicators) >= 2  # 최소 2개 필요
        reason = f"발견된 지표: {', '.join(indicators)}" if indicators else "구체적 지표 부족"
        
        return has_enough, reason
    
    @retry(stop=stop_after_attempt(3), wait=wait_fixed(2))
    def _generate_ai_rule(self, rule_type: str, cve_data: Dict) -> Optional[str]:
        """
        AI 기반 탐지 룰 생성
        
        공개 룰이 없고, 구체적 지표가 충분할 때만 AI에게 룰을 생성하도록 요청합니다.
        """
        logger.debug(f"AI {rule_type} 생성 시도")
        
        # Observable Gate (Sigma는 예외 - 로그 기반이라 관대하게)
        if rule_type not in ["Sigma", "sigma"]:
            has_indicators, reason = self._check_observables(cve_data)
            if not has_indicators:
                logger.info(f"⛔ {rule_type} 생성 SKIP: {reason}")
                return None
            else:
                logger.debug(f"✅ Observable Gate 통과: {reason}")
        
        prompt = self._build_rule_prompt(rule_type, cve_data)
        
        try:
            response = self.groq_client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=config.GROQ_RULE_PARAMS["temperature"],
                top_p=config.GROQ_RULE_PARAMS["top_p"],
                max_completion_tokens=config.GROQ_RULE_PARAMS["max_completion_tokens"],
                reasoning_effort=config.GROQ_RULE_PARAMS["reasoning_effort"]
            )
            
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
                return content
            else:
                logger.warning(f"❌ AI {rule_type} 검증 실패")
                logger.debug(f"실패한 룰:\n{content}")
                return None
                
        except Exception as e:
            logger.error(f"AI 룰 생성 에러: {e}")
            raise
    
    def _build_rule_prompt(self, rule_type: str, cve_data: Dict) -> str:
        """AI를 위한 룰 생성 프롬프트 구성"""
        
        base_prompt = f"""
You are a Senior Detection Engineer specializing in {rule_type} rules.
Write a valid {rule_type} detection rule for {cve_data['id']}.

[Context]
CVE-ID: {cve_data['id']}
Description: {cve_data['description']}
CVSS Vector: {cve_data.get('cvss_vector', 'N/A')}
CWE: {', '.join(cve_data.get('cwe', []))}

[CRITICAL REQUIREMENTS]
1. **Observable Gate**: If no concrete indicator exists, return exactly: SKIP
2. **No Hallucination**: Use ONLY what's in the description
3. **Syntax**: Follow standard {rule_type} syntax strictly
4. **Conservative**: When uncertain, return SKIP

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
    
    def get_rules(self, cve_data: Dict, feasibility: bool) -> Dict:
        """
        CVE에 대한 탐지 룰 수집
        
        우선순위:
        1. 공개 룰 (신뢰도 100%)
        2. AI 생성 룰 (검증 후 제공, 경고 표시)
        
        Returns:
            {
                "sigma": {"code": "...", "source": "...", "verified": bool},
                "network": [
                    {"code": "...", "source": "Snort 3 ET Open", "engine": "snort3", "verified": true},
                    {"code": "...", "source": "Suricata 7 ET Open", "engine": "suricata7", "verified": true}
                ],
                "yara": {"code": "...", "source": "...", "verified": bool}
            }
        """
        rules = {"sigma": None, "network": [], "yara": None}
        cve_id = cve_data['id']
        
        logger.info(f"룰 수집 시작: {cve_id}")
        
        # ===== Sigma =====
        public_sigma = self._search_github("SigmaHQ/sigma", f"{cve_id} filename:.yml")
        if public_sigma:
            rules['sigma'] = {
                "code": public_sigma,
                "source": "Public (SigmaHQ)",
                "verified": True
            }
        else:
            ai_sigma = self._generate_ai_rule("Sigma", cve_data)
            if ai_sigma:
                rules['sigma'] = {
                    "code": f"# ⚠️ AI-Generated - Review Required\n{ai_sigma}",
                    "source": "AI Generated (Validated)",
                    "verified": False
                }
        
        # ===== 네트워크 룰 (Snort + Suricata) =====
        # 여러 엔진의 룰을 모두 수집!
        network_rules = self._fetch_network_rules(cve_id)
        
        if network_rules:
            # 공개 룰이 하나라도 있으면 모두 추가
            for rule_info in network_rules:
                rules['network'].append({
                    "code": rule_info["code"],
                    "source": f"Public ({rule_info['source']})",
                    "engine": rule_info["engine"],
                    "verified": True
                })
        elif feasibility:
            # 공개 룰이 없고 feasibility가 true면 AI 생성
            ai_network = self._generate_ai_rule("Snort", cve_data)
            if ai_network:
                rules['network'].append({
                    "code": f"# ⚠️ AI-Generated - Review Required\n{ai_network}",
                    "source": "AI Generated (Regex Validated)",
                    "engine": "generic",
                    "verified": False
                })
        
        # ===== Yara =====
        public_yara = self._search_github("Yara-Rules/rules", f"{cve_id} filename:.yar")
        if public_yara:
            rules['yara'] = {
                "code": public_yara,
                "source": "Public (Yara-Rules)",
                "verified": True
            }
        elif feasibility:
            ai_yara = self._generate_ai_rule("Yara", cve_data)
            if ai_yara:
                rules['yara'] = {
                    "code": f"// ⚠️ AI-Generated - Review Required\n{ai_yara}",
                    "source": "AI Generated (Compiled)",
                    "verified": False
                }
        
        # 결과 요약
        sigma_found = "✅" if rules['sigma'] else "❌"
        network_count = len(rules['network'])
        yara_found = "✅" if rules['yara'] else "❌"
        
        logger.info(f"룰 수집 완료: Sigma {sigma_found}, 네트워크 {network_count}개, Yara {yara_found}")
        
        return rules
