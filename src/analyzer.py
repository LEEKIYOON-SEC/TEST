import os
import json
from groq import Groq
from tenacity import retry, stop_after_attempt, wait_exponential
from typing import Dict, Optional
from logger import logger
from config import config

class AnalyzerError(Exception):
    """분석 관련 에러"""
    pass

class Analyzer:
    """
    CVE 심층 분석 엔진
    
    AI를 사용해서 CVE를 분석하고 다음을 제공합니다:
    1. 기술적 원인 (Root Cause)
    2. 공격 시나리오 (Kill Chain)
    3. 비즈니스 영향 (CIA Impact)
    4. 대응 방안 (Mitigation)
    5. 탐지 룰 생성 가능성 (Rule Feasibility)
    
    개선사항:
    - 더 명확한 프롬프트로 AI의 정확도 향상
    - 에러 발생 시 폴백 메커니즘 제공
    - 토큰 한도 증가로 복잡한 CVE도 분석 가능
    """
    
    def __init__(self):
        api_key = os.environ.get("GROQ_API_KEY")
        if not api_key:
            raise AnalyzerError("GROQ_API_KEY not found")
        
        self.client = Groq(api_key=api_key)
        self.model = config.MODEL_PHASE_1
        
        logger.info(f"Analyzer initialized with model: {self.model}")
    
    @retry(
        stop=stop_after_attempt(3),
        wait=wait_exponential(multiplier=1, min=2, max=10)
    )
    def analyze_cve(self, cve_data: Dict) -> Dict:
        """
        CVE 심층 분석 수행
        
        이 함수는 AI에게 CVE를 분석하도록 요청합니다.
        마치 보안 전문가에게 "이 취약점을 분석해주세요"라고 부탁하는 것과 같아요.
        
        Args:
            cve_data: CVE 정보 딕셔너리
        
        Returns:
            분석 결과 딕셔너리
        
        재시도 로직:
        - AI API도 가끔 실패할 수 있어요 (서버 과부하 등)
        - 최대 3번까지 재시도하며, 실패할 때마다 대기 시간 증가
        - 3번 모두 실패하면 안전한 기본값 반환
        """
        logger.info(f"Analyzing {cve_data['id']} with AI...")
        
        try:
            prompt = self._build_analysis_prompt(cve_data)
            
            response = self.client.chat.completions.create(
                model=self.model,
                messages=[{"role": "user", "content": prompt}],
                temperature=config.GROQ_ANALYSIS_PARAMS["temperature"],
                top_p=config.GROQ_ANALYSIS_PARAMS["top_p"],
                max_completion_tokens=config.GROQ_ANALYSIS_PARAMS["max_completion_tokens"],
                reasoning_effort=config.GROQ_ANALYSIS_PARAMS["reasoning_effort"],
                response_format=config.GROQ_ANALYSIS_PARAMS["response_format"]
            )
            
            result = json.loads(response.choices[0].message.content)
            
            # 결과 검증
            if not self._validate_analysis_result(result):
                logger.warning(f"{cve_data['id']}: Invalid AI response, using fallback")
                return self._fallback_analysis(cve_data)
            
            logger.info(f"{cve_data['id']}: Analysis complete (feasibility={result.get('rule_feasibility')})")
            return result
            
        except json.JSONDecodeError as e:
            logger.error(f"{cve_data['id']}: Failed to parse AI JSON response: {e}")
            raise  # 재시도
        except Exception as e:
            logger.error(f"{cve_data['id']}: Analysis error: {e}")
            # 3번 재시도 후에도 실패하면 여기로 옴
            return self._fallback_analysis(cve_data)
    
    def _build_analysis_prompt(self, cve_data: Dict) -> str:
        """
        AI를 위한 프롬프트 생성
        
        프롬프트는 AI에게 주는 지시사항이에요.
        좋은 프롬프트를 만드는 것은 좋은 질문을 하는 것과 같습니다.
        
        핵심 포인트:
        1. 명확한 역할 부여 ("당신은 시니어 보안 분석가입니다")
        2. 구체적인 작업 설명
        3. 예시와 제약사항 제공
        4. 출력 형식 명시
        
        이렇게 하면 AI가 더 정확하고 일관된 답변을 합니다.
        """
        return f"""
You are a Senior Security Analyst with expertise in vulnerability assessment and threat intelligence.
Analyze the following CVE deeply and professionally.

[Context]
CVE-ID: {cve_data['id']}
Description: {cve_data['description']}
CWE: {', '.join(cve_data.get('cwe', ['Unknown']))}
CVSS Vector: {cve_data.get('cvss_vector', 'N/A')}
Affected Products: {json.dumps(cve_data.get('affected', []))}

[Analysis Tasks]
Provide a comprehensive security analysis with the following sections:

1. **Root Cause Analysis**
   - Identify the technical root cause (e.g., "Buffer overflow in X parser due to missing bounds check")
   - Be specific about the vulnerable component
   - Explain why the vulnerability exists

2. **Attack Scenario (Kill Chain)**
   - Describe a realistic attack flow using MITRE ATT&CK framework
   - Include stages: Initial Access → Execution → Impact
   - Be concrete and actionable

3. **Business Impact Assessment**
   - Evaluate impact on Confidentiality, Integrity, and Availability (CIA)
   - Consider real-world consequences (data breach, service disruption, etc.)
   - Assess severity for different organization types

4. **Mitigation Strategy**
   - Provide specific remediation steps
   - Include patching guidance (which versions to upgrade to)
   - Suggest workarounds if patches aren't available
   - Prioritize actions by urgency

5. **Detection Rule Feasibility**
   - **CRITICAL GATE:** Set to **true** ONLY IF you can identify AT LEAST 3 of these indicators:
     * Specific file paths (e.g., "/etc/config/settings.xml")
     * Exact URL parameters (e.g., "?id=", "&cmd=")
     * Known magic bytes or file signatures (e.g., "0x4D5A")
     * Specific function names or API calls (e.g., "strcpy()", "eval()")
     * HTTP headers or User-Agent patterns
     * Registry keys (Windows)
     * Port numbers with protocol behaviors
     * Known exploit strings or payloads
     * Log patterns with exact field names
   
   - Set to **false** if:
     * Description is generic ("unspecified vulnerability", "memory corruption")
     * Attack vectors are vague ("remote code execution" without specifics)
     * Technical details are missing
   
   - **NEVER GUESS OR HALLUCINATE INDICATORS**

[Language & Terminology]
- Translate ALL output values into Korean (한국어)
- KEEP technical terms in standard English or Korean transliteration:
  - Good: "Buffer Overflow", "버퍼 오버플로우", "SQL Injection", "SQL 인젝션"
  - Bad: "완충 범람", "SQL 주입"
- JSON keys must remain in English

[Output Format]
Return ONLY a valid JSON object with these exact keys:
{{
  "root_cause": "한국어 설명",
  "scenario": "한국어 공격 시나리오",
  "impact": "한국어 영향도 평가",
  "mitigation": ["단계별", "대응", "방안"],
  "rule_feasibility": true or false
}}

Do NOT include markdown code fences, explanations, or any text outside the JSON object.
"""
    
    def _validate_analysis_result(self, result: Dict) -> bool:
        """
        AI 응답 검증
        
        AI가 때때로 잘못된 형식으로 답변할 수 있어요.
        이 함수는 필수 필드가 모두 있는지, 타입이 올바른지 확인합니다.
        
        마치 학생의 답안지를 채점하기 전에 이름과 학번이 적혀있는지 
        확인하는 것과 같습니다.
        """
        required_keys = ['root_cause', 'scenario', 'impact', 'mitigation', 'rule_feasibility']
        
        # 필수 키 확인
        for key in required_keys:
            if key not in result:
                logger.warning(f"Missing required key: {key}")
                return False
        
        # 타입 확인
        if not isinstance(result['mitigation'], list):
            logger.warning("mitigation must be a list")
            return False
        
        if not isinstance(result['rule_feasibility'], bool):
            logger.warning("rule_feasibility must be boolean")
            return False
        
        return True
    
    def _fallback_analysis(self, cve_data: Dict) -> Dict:
        """
        폴백 분석 결과
        
        AI 분석이 완전히 실패했을 때 사용하는 안전한 기본값입니다.
        "분석 불가"라고 표시하되, 시스템이 중단되지 않도록 합니다.
        
        이것은 마치 비상구와 같아요. 평소엔 사용 안 하지만,
        문제가 생겼을 때 시스템이 멈추지 않도록 보호합니다.
        """
        logger.warning(f"{cve_data['id']}: Using fallback analysis (AI failed)")
        
        return {
            "root_cause": f"자동 분석 실패 - {cve_data.get('description', 'No description')[:100]}",
            "scenario": "AI 분석을 수행할 수 없습니다. 제조사의 권고사항을 참조하세요.",
            "impact": "정보 부족으로 영향도를 평가할 수 없습니다.",
            "mitigation": [
                "제조사 보안 권고문 확인",
                "영향받는 버전 확인",
                "가능한 빠른 시일 내 패치 적용"
            ],
            "rule_feasibility": False  # 정보 부족 시 룰 생성 불가
        }
