import os
import datetime
import time
import requests
import pytz
import json
from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Dict, List, Tuple, Optional
from google import genai
from google.genai import types

# 우리가 만든 모듈들
from logger import logger
from config import config
from collector import Collector
from database import ArgusDB
from notifier import SlackNotifier
from analyzer import Analyzer
from rule_manager import RuleManager
from rate_limiter import rate_limit_manager

# KST 타임존 (한국 표준시)
KST = pytz.timezone('Asia/Seoul')

# Gemini 클라이언트 (한국어 번역용)
gemini_client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))

# ==============================================================================
# [1] CVSS 벡터 해석 매핑
# ==============================================================================
CVSS_MAP = {
    "AV:N": "공격 경로: 네트워크", "AV:A": "공격 경로: 인접", "AV:L": "공격 경로: 로컬", "AV:P": "공격 경로: 물리적",
    "AC:L": "복잡성: 낮음", "AC:H": "복잡성: 높음",
    "PR:N": "필요 권한: 없음", "PR:L": "필요 권한: 낮음", "PR:H": "필요 권한: 높음",
    "UI:N": "사용자 관여: 없음", "UI:R": "사용자 관여: 필수",
    "S:U": "범위: 변경 없음", "S:C": "범위: 변경됨",
    "C:H": "기밀성: 높음", "C:L": "기밀성: 낮음", "C:N": "기밀성: 없음",
    "I:H": "무결성: 높음", "I:L": "무결성: 낮음", "I:N": "무결성: 없음",
    "A:H": "가용성: 높음", "A:L": "가용성: 낮음", "A:N": "가용성: 없음",
}

# ==============================================================================
# [2] 유틸리티 함수들
# ==============================================================================

def parse_cvss_vector(vector_str: str) -> str:
    """CVSS 벡터 문자열을 한국어로 변환"""
    if not vector_str or vector_str == "N/A":
        return "정보 없음"
    
    parts = vector_str.split('/')
    mapped_parts = []
    
    for part in parts:
        if ':' in part:
            full_key = part
            desc = CVSS_MAP.get(full_key, f"**{part}**")
            if full_key in CVSS_MAP:
                mapped_parts.append(f"• {desc}")
            else:
                mapped_parts.append(f"• {part}")
    
    return "<br>".join(mapped_parts)

def is_target_asset(cve_description: str, cve_id: str) -> Tuple[bool, Optional[str]]:
    """자산 필터링 (감시 대상인지 확인)"""
    desc_lower = cve_description.lower()
    
    for target in config.get_target_assets():
        vendor = target.get('vendor', '').lower()
        product = target.get('product', '').lower()
        
        if vendor == "*" and product == "*":
            return True, "All Assets (*)"
        
        if vendor in desc_lower and (product == "*" or product in desc_lower):
            return True, f"Matched: {vendor}/{product}"
    
    return False, None

def generate_korean_summary(cve_data: Dict) -> Tuple[str, str]:
    """Gemini를 사용한 한국어 번역"""
    prompt = f"""
Task: Translate Title and Summarize Description into Korean.
[Input] Title: {cve_data['title']} / Desc: {cve_data['description']}
[Format]
제목: [Korean Title]
내용: [Korean Summary (Max 3 lines)]
Do NOT add intro/outro.
"""
    
    try:
        rate_limit_manager.check_and_wait("gemini")
        
        response = gemini_client.models.generate_content(
            model=config.MODEL_PHASE_0,
            contents=prompt,
            config=types.GenerateContentConfig(
                safety_settings=[types.SafetySetting(
                    category="HARM_CATEGORY_DANGEROUS_CONTENT",
                    threshold="BLOCK_NONE"
                )]
            )
        )
        
        rate_limit_manager.record_call("gemini")
        
        text = response.text.strip()
        title_ko, desc_ko = cve_data['title'], cve_data['description'][:200]
        
        for line in text.split('\n'):
            if line.startswith("제목:"):
                title_ko = line.replace("제목:", "").strip()
            if line.startswith("내용:"):
                desc_ko = line.replace("내용:", "").strip()
        
        return title_ko, desc_ko
        
    except Exception as e:
        logger.warning(f"번역 실패: {e}, 원본 사용")
        return cve_data['title'], cve_data['description'][:200]

# ==============================================================================
# [3] GitHub Issue 생성/업데이트
# ==============================================================================

def create_github_issue(cve_data: Dict, reason: str) -> Tuple[Optional[str], Optional[Dict]]:
    """
    GitHub Issue 생성
    
    High Risk CVE에 대해 상세한 분석 리포트를 GitHub Issue로 생성합니다.
    """
    token = os.environ.get("GH_TOKEN")
    repo = os.environ.get("GITHUB_REPOSITORY")
    
    if not repo:
        logger.warning("GITHUB_REPOSITORY 미설정, Issue 생성 건너뜀")
        return None, None
    
    try:
        # Step 1: AI 분석
        logger.info(f"AI 분석 시작: {cve_data['id']}")
        analyzer = Analyzer()
        analysis = analyzer.analyze_cve(cve_data)
        
        # Step 2: 룰 생성/수집
        logger.info(f"룰 수집 시작: {cve_data['id']}")
        rule_manager = RuleManager()
        rules = rule_manager.get_rules(cve_data, analysis.get('rule_feasibility', False), analysis)
        
        # Step 3: 공식 룰 존재 여부 확인
        has_official = any([
            rules.get('sigma') and rules['sigma'].get('verified'),
            any(r.get('verified') for r in rules.get('network', [])),
            rules.get('yara') and rules['yara'].get('verified')
        ])
        
        # Step 4: 마크다운 리포트 구성
        body = _build_issue_body(cve_data, reason, analysis, rules, has_official)
        
        # Step 5: GitHub API 호출
        rate_limit_manager.check_and_wait("github")
        
        url = f"https://api.github.com/repos/{repo}/issues"
        headers = {
            "Authorization": f"token {token}",
            "Accept": "application/vnd.github.v3+json"
        }
        payload = {
            "title": f"[Argus] {cve_data['id']}: {cve_data['title_ko']}",
            "body": body,
            "labels": ["security", "cve"]
        }
        
        response = requests.post(url, headers=headers, json=payload, timeout=15)
        response.raise_for_status()
        rate_limit_manager.record_call("github")
        
        issue_url = response.json().get("html_url")
        logger.info(f"GitHub Issue 생성 성공: {issue_url}")
        
        return issue_url, {"has_official": has_official, "rules": rules}
        
    except Exception as e:
        logger.error(f"GitHub Issue 생성 실패: {e}")
        return None, None

def _build_issue_body(cve_data: Dict, reason: str, analysis: Dict, rules: Dict, has_official: bool) -> str:
    """GitHub Issue 본문 구성"""
    score = cve_data['cvss']
    if score >= 9.0: color = "FF0000"
    elif score >= 7.0: color = "FD7E14"
    elif score >= 4.0: color = "FFC107"
    elif score > 0: color = "28A745"
    else: color = "CCCCCC"
    
    kev_color = "FF0000" if cve_data['is_kev'] else "CCCCCC"
    
    badges = f"![CVSS](https://img.shields.io/badge/CVSS-{score}-{color}) ![EPSS](https://img.shields.io/badge/EPSS-{cve_data['epss']*100:.2f}%25-blue) ![KEV](https://img.shields.io/badge/KEV-{'YES' if cve_data['is_kev'] else 'No'}-{kev_color})"
    
    cwe_str = ", ".join(cve_data['cwe']) if cve_data['cwe'] else "N/A"
    
    # 영향받는 자산 테이블
    affected_rows = ""
    for item in cve_data.get('affected', []):
        affected_rows += f"| {item['vendor']} | {item['product']} | {item['versions']} |\n"
    if not affected_rows:
        affected_rows = "| - | - | - |"
    
    # 대응 방안
    mitigation_list = "\n".join([f"- {m}" for m in analysis.get('mitigation', [])])
    
    # 참고 자료
    ref_list = "\n".join([f"- {r}" for r in cve_data['references']])
    
    # CVSS 벡터 해석
    vector_details = parse_cvss_vector(cve_data.get('cvss_vector', 'N/A'))
    
    # 룰 섹션
    rules_section = ""
    has_any_rules = rules.get('sigma') or rules.get('network') or rules.get('yara')
    
    if has_any_rules:
        rules_section = "## 🛡️ 탐지 룰 (Detection Rules)\n\n"
        
        if not has_official:
            rules_section += "> ⚠️ **주의:** AI 생성 룰은 실제 배포 전 보안 전문가의 검토가 필요합니다.\n\n"
        
        # Sigma 룰
        if rules.get('sigma'):
            is_verified = rules['sigma'].get('verified')
            badge = "🟢 **공식 검증**" if is_verified else "🔶 **AI 생성 - 검토 필요**"
            
            indicator_info = ""
            if not is_verified and rules['sigma'].get('indicators'):
                indicators = rules['sigma']['indicators']
                if indicators:
                    indicator_info = f"\n> **Based on:** {', '.join(indicators)}\n"
            
            rules_section += f"### Sigma Rule ({rules['sigma']['source']}) {badge}\n{indicator_info}```yaml\n{rules['sigma']['code']}\n```\n\n"
        
        # 네트워크 룰 (여러 개 가능)
        if rules.get('network'):
            for idx, net_rule in enumerate(rules['network'], 1):
                is_verified = net_rule.get('verified')
                badge = "🟢 **공식 검증**" if is_verified else "🔶 **AI 생성 - 검토 필요**"
                engine_name = net_rule.get('engine', 'unknown').upper()
                
                indicator_info = ""
                if not is_verified and net_rule.get('indicators'):
                    indicators = net_rule['indicators']
                    if indicators:
                        indicator_info = f"\n> **Based on:** {', '.join(indicators)}\n"
                
                rules_section += f"### Network Rule #{idx} ({net_rule['source']} - {engine_name}) {badge}\n{indicator_info}```bash\n{net_rule['code']}\n```\n\n"
        
        # Yara 룰
        if rules.get('yara'):
            is_verified = rules['yara'].get('verified')
            badge = "🟢 **공식 검증**" if is_verified else "🔶 **AI 생성 - 검토 필요**"
            
            indicator_info = ""
            if not is_verified and rules['yara'].get('indicators'):
                indicators = rules['yara']['indicators']
                if indicators:
                    indicator_info = f"\n> **Based on:** {', '.join(indicators)}\n"
            
            rules_section += f"### Yara Rule ({rules['yara']['source']}) {badge}\n{indicator_info}```yara\n{rules['yara']['code']}\n```\n\n"
    
    now_kst = datetime.datetime.now(KST).strftime('%Y-%m-%d %H:%M:%S (KST)')
    
    body = f"""# 🛡️ {cve_data['title_ko']}

> **탐지 일시:** {now_kst}
> **탐지 사유:** {reason}

{badges}
**취약점 유형 (CWE):** {cwe_str}

## 📦 영향 받는 자산
| 벤더 | 제품 | 버전 |
| :--- | :--- | :--- |
{affected_rows}

## 🔍 심층 분석
| 항목 | 내용 |
| :--- | :--- |
| **기술적 원인** | {analysis.get('root_cause', '-')} |
| **비즈니스 영향** | {analysis.get('impact', '-')} |

### 🏹 공격 시나리오
> {analysis.get('scenario', '정보 없음')}

### 🏹 공격 벡터 상세
| 항목 | 내용 |
| :--- | :--- |
| **공식 벡터** | `{cve_data.get('cvss_vector', 'N/A')}` |
| **상세 분석** | {vector_details} |

## 🛡️ 대응 방안
{mitigation_list}

{rules_section}

## 🔗 참고 자료
{ref_list}
"""
    return body.strip()

def update_github_issue_with_official_rules(issue_url: str, cve_id: str, rules: Dict) -> bool:
    """GitHub Issue에 공식 룰 발견 댓글 추가"""
    comment = f"""## ✅ 공식 탐지 룰 발견

{cve_id}에 대한 **공식 검증된 탐지 룰**이 발견되었습니다. AI 생성 룰을 이것으로 교체하시기 바랍니다.

"""
    
    if rules.get('sigma') and rules['sigma'].get('verified'):
        comment += f"### Sigma Rule ({rules['sigma']['source']})\n```yaml\n{rules['sigma']['code']}\n```\n\n"
    
    if rules.get('network'):
        for idx, net_rule in enumerate(rules['network'], 1):
            if net_rule.get('verified'):
                engine = net_rule.get('engine', 'unknown').upper()
                comment += f"### Network Rule #{idx} ({net_rule['source']} - {engine})\n```bash\n{net_rule['code']}\n```\n\n"
    
    if rules.get('yara') and rules['yara'].get('verified'):
        comment += f"### Yara Rule ({rules['yara']['source']})\n```yara\n{rules['yara']['code']}\n```\n\n"
    
    notifier = SlackNotifier()
    return notifier.update_github_issue(issue_url, comment)

# ==============================================================================
# [4] CVE 처리 (단일)
# ==============================================================================

def process_single_cve(cve_id: str, collector: Collector, db: ArgusDB, notifier: SlackNotifier) -> Optional[Dict]:
    """
    단일 CVE 처리
    
    과정:
    1. CVE 상세 정보 수집
    2. 자산 필터링
    3. 알림 필요성 판단
    4. High Risk면 GitHub Issue 생성
    5. Slack 알림 전송
    6. DB에 저장
    """
    try:
        # Step 1: CVE 상세 정보 수집
        raw_data = collector.enrich_cve(cve_id)
        
        if raw_data.get('state') != 'PUBLISHED':
            logger.debug(f"{cve_id}: PUBLISHED 상태 아님, 건너뜀")
            return None
        
        # Step 2: 자산 필터링
        is_target, match_info = is_target_asset(raw_data['description'], cve_id)
        if not is_target:
            logger.debug(f"{cve_id}: 감시 대상 아님, 건너뜀")
            return None
        
        # Step 3: 현재 상태 구성
        current_state = {
            "id": cve_id,
            "title": raw_data['title'],
            "cvss": raw_data['cvss'],
            "cvss_vector": raw_data['cvss_vector'],
            "is_kev": cve_id in collector.kev_set,
            "epss": collector.epss_cache.get(cve_id, 0.0),
            "description": raw_data['description'],
            "cwe": raw_data['cwe'],
            "references": raw_data['references'],
            "affected": raw_data['affected']
        }
        
        # Step 4: 알림 필요성 판단
        last_record = db.get_cve(cve_id)
        last_state = last_record.get('last_alert_state') if last_record else None
        
        should_alert, alert_reason, is_high_risk = _should_send_alert(
            current_state, last_state
        )
        
        if not should_alert:
            db.upsert_cve({
                "id": cve_id,
                "updated_at": datetime.datetime.now(KST).isoformat()
            })
            return None
        
        # Step 5: 한국어 번역
        logger.info(f"알림 발송 준비: {cve_id} (HighRisk: {is_high_risk})")
        title_ko, desc_ko = generate_korean_summary(current_state)
        current_state['title_ko'] = title_ko
        current_state['desc_ko'] = desc_ko
        
        # Step 6: High Risk면 GitHub Issue 생성
        report_url = None
        rules_info = None
        if is_high_risk:
            report_url, rules_info = create_github_issue(current_state, alert_reason)
        
        # Step 7: Slack 알림
        notifier.send_alert(current_state, alert_reason, report_url)
        
        # Step 8: DB 저장
        db_data = {
            "id": cve_id,
            "cvss_score": current_state['cvss'],
            "epss_score": current_state['epss'],
            "is_kev": current_state['is_kev'],
            "last_alert_at": datetime.datetime.now(KST).isoformat(),
            "last_alert_state": current_state,
            "report_url": report_url,
            "updated_at": datetime.datetime.now(KST).isoformat()
        }
        
        if rules_info:
            db_data["has_official_rules"] = rules_info.get('has_official', False)
            db_data["rules_snapshot"] = rules_info.get('rules')
            db_data["last_rule_check_at"] = datetime.datetime.now(KST).isoformat()
        
        db.upsert_cve(db_data)
        
        return {"cve_id": cve_id, "status": "success"}
        
    except Exception as e:
        logger.error(f"{cve_id} 처리 실패: {e}", exc_info=True)
        return None

def _should_send_alert(current: Dict, last: Optional[Dict]) -> Tuple[bool, str, bool]:
    """알림 필요성 판단"""
    is_high_risk = current['cvss'] >= 7.0 or current['is_kev']
    
    if last is None:
        return True, "신규 취약점", is_high_risk
    
    if current['is_kev'] and not last.get('is_kev'):
        return True, "🚨 KEV 등재", True
    
    if current['epss'] >= 0.1 and (current['epss'] - last.get('epss', 0)) > 0.05:
        return True, "📈 EPSS 급증", True
    
    if current['cvss'] >= 7.0 and last.get('cvss', 0) < 7.0:
        return True, "🔺 CVSS 위험도 상향", True
    
    return False, "", is_high_risk

# ==============================================================================
# [5] 공식 룰 재발견
# ==============================================================================

def check_for_official_rules() -> None:
    """
    AI 생성 룰 CVE의 공식 룰 재발견
    
    v2.0 변경사항:
    - RuleManager 인스턴스를 공유하여 룰셋 캐시 재활용
    - rate_limit_manager가 GitHub Search 간격을 자동 관리
    - 개별 CVE 실패 시에도 계속 진행
    """
    try:
        logger.info("=== 공식 룰 재발견 체크 시작 ===")
        
        db = ArgusDB()
        notifier = SlackNotifier()
        collector = Collector()
        
        # ✅ RuleManager를 한 번만 생성하여 룰셋 캐시 공유
        rule_manager = RuleManager()
        
        ai_cves = db.get_ai_generated_cves()
        
        if not ai_cves:
            logger.info("재확인 대상 없음")
            return
        
        logger.info(f"재확인 대상: {len(ai_cves)}건")
        
        # ✅ GitHub Search API 현재 상태 로깅
        search_status = rate_limit_manager.get_status("github_search")
        logger.info(
            f"GitHub Search API 상태: "
            f"{search_status.get('used', 0)}/{search_status.get('limit', 0)} "
            f"(잔여: {search_status.get('remaining', 0)})"
        )
        
        for idx, record in enumerate(ai_cves, 1):
            cve_id = record['id']
            
            try:
                logger.info(f"[{idx}/{len(ai_cves)}] {cve_id} 공식 룰 재확인 중...")
                
                # CVE 정보 재수집
                raw_data = collector.enrich_cve(cve_id)
                if raw_data.get('state') != 'PUBLISHED':
                    logger.debug(f"{cve_id}: PUBLISHED 상태 아님, 건너뜀")
                    continue
                
                cve_temp = {
                    "id": cve_id,
                    "description": raw_data['description'],
                    "cvss_vector": raw_data['cvss_vector'],
                    "cwe": raw_data['cwe'],
                    "references": raw_data.get('references', []),
                    "affected": raw_data.get('affected', [])
                }
                
                # ✅ 공개 룰만 검색 (analysis=None이면 AI 생성 시도 안 함? 아님!)
                #    get_rules는 공개 룰 없으면 AI 생성을 시도하지만,
                #    재발견 목적이므로 공식 룰만 체크하면 됨.
                #    하지만 현재 구조상 get_rules를 그대로 사용.
                rules = rule_manager.get_rules(cve_temp, feasibility=True, analysis=None)
                
                # 공식 룰 존재 확인
                has_official = any([
                    rules.get('sigma') and rules['sigma'].get('verified'),
                    any(r.get('verified') for r in rules.get('network', [])),
                    rules.get('yara') and rules['yara'].get('verified')
                ])
                
                if has_official:
                    logger.info(f"✅ {cve_id}: 공식 룰 발견!")
                    
                    title_ko = record.get('last_alert_state', {}).get('title_ko', cve_id)
                    notifier.send_official_rule_update(
                        cve_id=cve_id,
                        title=title_ko,
                        rules_info=rules,
                        original_report_url=record.get('report_url')
                    )
                    
                    if record.get('report_url'):
                        update_github_issue_with_official_rules(
                            record['report_url'],
                            cve_id,
                            rules
                        )
                    
                    db.upsert_cve({
                        "id": cve_id,
                        "has_official_rules": True,
                        "rules_snapshot": rules,
                        "last_rule_check_at": datetime.datetime.now(KST).isoformat(),
                        "updated_at": datetime.datetime.now(KST).isoformat()
                    })
                else:
                    logger.debug(f"{cve_id}: 공식 룰 아직 없음")
                
            except Exception as e:
                logger.warning(f"{cve_id} 공식 룰 체크 실패: {e}")
                continue
        
        logger.info("=== 공식 룰 재발견 체크 완료 ===")
        
    except Exception as e:
        logger.error(f"공식 룰 체크 프로세스 실패: {e}")

# ==============================================================================
# [6] 메인 실행 로직
# ==============================================================================

def main():
    """
    Argus 메인 실행 함수
    
    v2.0 변경사항:
    - rate_limit_manager.print_summary() 추가 (종료 시 API 사용량 출력)
    - 로그 통일성 개선
    """
    start_time = time.time()
    logger.info("=" * 60)
    logger.info(f"Argus Phase 1 시작 (Model: {config.MODEL_PHASE_1})")
    logger.info("=" * 60)
    
    # Step 1: 헬스체크
    health = config.health_check()
    if not all(health.values()):
        logger.error(f"헬스체크 실패: {health}")
        return
    logger.info(f"✅ 헬스체크 통과: {health}")
    
    # Step 2: 모듈 초기화
    collector = Collector()
    db = ArgusDB()
    notifier = SlackNotifier()
    
    # Step 3: 공식 룰 재발견
    check_for_official_rules()
    
    # Step 4: KEV 및 최신 CVE 수집
    collector.fetch_kev()
    target_cve_ids = collector.fetch_recent_cves(hours=config.PERFORMANCE["cve_fetch_hours"])
    
    if not target_cve_ids:
        logger.info("처리할 CVE 없음")
        # ✅ CVE 없어도 rate limit 요약은 출력
        _print_final_summary(start_time, 0, 0)
        return
    
    # Step 5: EPSS 수집
    collector.fetch_epss(target_cve_ids)
    
    logger.info(f"분석 대상: {len(target_cve_ids)}건")
    
    # Step 6: 병렬 처리로 CVE 분석
    results = []
    max_workers = config.PERFORMANCE["max_workers"]
    
    logger.info(f"병렬 처리 시작 (워커: {max_workers}명)")
    
    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        future_to_cve = {
            executor.submit(process_single_cve, cve_id, collector, db, notifier): cve_id
            for cve_id in target_cve_ids
        }
        
        for future in as_completed(future_to_cve):
            cve_id = future_to_cve[future]
            try:
                result = future.result()
                if result:
                    results.append(result)
            except Exception as e:
                logger.error(f"{cve_id} 처리 중 예외 발생: {e}")
    
    # Step 7: 결과 요약
    _print_final_summary(start_time, len(results), len(target_cve_ids))

def _print_final_summary(start_time: float, success_count: int, total_count: int):
    """
    최종 결과 요약 출력
    
    처리 결과 + Rate Limit 사용량을 함께 보여줍니다.
    """
    elapsed = time.time() - start_time
    
    logger.info("")
    logger.info("=" * 60)
    logger.info("📋 Argus 실행 결과 요약")
    logger.info("=" * 60)
    logger.info(f"  처리 완료: {success_count}/{total_count}건 성공")
    logger.info(f"  소요 시간: {elapsed:.1f}초")
    logger.info("=" * 60)
    
    # ✅ Rate Limit 사용 요약
    rate_limit_manager.print_summary()

if __name__ == "__main__":
    main()
