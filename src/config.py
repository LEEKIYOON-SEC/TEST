import json
import os

# [1] AI 모델 설정
MODEL_PHASE_0 = "gemma-3-27b-it"        # 리포트/번역용 (기존)
MODEL_PHASE_1 = "openai/gpt-oss-120b"   # [Phase 1] 심층 분석 및 룰 생성용

# [Phase 1] Groq High Reasoning 파라미터 (문서 권장 사항 준수)
GROQ_PARAMS = {
    "temperature": 0.6,             # 권장 범위: 0.5 ~ 0.7
    "top_p": 0.95,                  # 권장 값
    "max_completion_tokens": 4096,  # 복잡한 추론을 위해 넉넉하게 설정
    "reasoning_effort": "high",     # [핵심] 고추론 활성화
    # "reasoning_format": "parsed", # (라이브러리 버전에 따라 지원 여부 확인 필요, 일단 제외하거나 옵션으로 사용)
    "response_format": {"type": "json_object"} # 구조화된 출력
}

# [2] 감시 대상 로드 (assets.json)
def load_assets():
    file_path = "assets.json"
    default_rules = [{"vendor": "*", "product": "*"}]
    if not os.path.exists(file_path):
        return default_rules
    try:
        with open(file_path, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get("active_rules", default_rules)
    except:
        return default_rules

TARGET_ASSETS = load_assets()