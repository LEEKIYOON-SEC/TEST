import os
import datetime
import time
from google import genai  # [변경] 최신 SDK 호출 방식
from groq import Groq
from collector import Collector
from database import ArgusDB
from notifier import SlackNotifier
import config

# [수정] 최신 google-genai Client 초기화
client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))

def is_target_asset(cve_description, cve_id):
    desc_lower = cve_description.lower()
    for target in config.TARGET_ASSETS:
        vendor = target.get('vendor', '').lower()
        product = target.get('product', '').lower()
        if vendor == "*" and product == "*": return True, "All Assets (*)"
        if vendor in desc_lower and (product == "*" or product in desc_lower):
            return True, f"Matched: {vendor}/{product}"
    return False, None

def generate_report_content(cve_data, reason):
    """최신 SDK 방식을 이용한 리포트 생성"""
    selected_model = config.MODEL_PHASE_0
    
    prompt = f"""
    보안 분석가로서 다음 CVE 정보를 한국어로 분석하여 리포트를 작성하세요.
    ID: {cve_data['id']}
    정보: {cve_data['description']}
    사유: {reason}
    
    작성 규칙: 전문적인 한국어를 사용하고, 기술 용어는 원문을 유지하며 Markdown 형식으로 작성하세요.
    """

    try:
        # [수정] 최신 SDK 호출 문법: client.models.generate_content
        response = client.models.generate_content(
            model=selected_model,
            contents=prompt
        )
        ai_analysis = response.text
    except Exception as e:
        print(f"[WARN] Google AI Failed: {e}")
        ai_analysis = f"⚠️ **AI 분석 실패**\n\n원문:\n{cve_data['description']}"

    return f"""
# 🛡️ Argus Intelligence Report
**Target:** `{cve_data['id']}`
**Alert:** {reason}

---
## 🤖 AI 보안 분석 (Korean)
**Engine:** `{selected_model}`

{ai_analysis}

---
## 📊 Risk Stats
- **CVSS Score:** {cve_data['cvss']}
- **EPSS Prob:** {cve_data['epss']*100:.2f}%
- **KEV Listed:** {'🚨 YES' if cve_data['is_kev'] else 'No'}
"""

def main():
    print(f"[*] Argus Phase 0 시작 (모델: {config.MODEL_PHASE_0})")
    
    collector = Collector()
    db = ArgusDB()
    notifier = SlackNotifier()
    
    collector.fetch_kev()
    target_cve_ids = collector.fetch_recent_cves(hours=2) 
    
    if not target_cve_ids:
        print("[*] 신규 취약점이 없습니다.")
        return

    collector.fetch_epss(target_cve_ids)
    print(f"[*] 분석 대상: {len(target_cve_ids)}건")

    for cve_id in target_cve_ids:
        try:
            # RPM 제한을 위해 2초 대기
            time.sleep(2) 
            
            raw_data = collector.enrich_cve(cve_id)
            is_target, match_info = is_target_asset(raw_data['description'], cve_id)
            
            if not is_target:
                continue 

            current_state = {
                "id": cve_id,
                "cvss": raw_data['cvss'],
                "epss": collector.epss_cache.get(cve_id, 0.0),
                "is_kev": cve_id in collector.kev_set,
                "description": raw_data['description']
            }
            
            last_record = db.get_cve(cve_id)
            last_state = last_record['last_alert_state'] if last_record else None
            
            should_alert = False
            alert_reason = ""
            
            if last_record is None:
                should_alert = True
                alert_reason = f"신규 취약점 ({match_info})"
            else:
                if current_state['is_kev'] and not last_state.get('is_kev'):
                    should_alert = True
                    alert_reason = "🚨 KEV 등재 확인"
                elif current_state['epss'] >= 0.1 and (current_state['epss'] - last_state.get('epss', 0)) > 0.05:
                    should_alert = True
                    alert_reason = "📈 EPSS 위험도 급증"

            if should_alert:
                print(f"[!] 알림 발송: {cve_id}")
                report_content = generate_report_content(current_state, alert_reason)
                report_url = db.upload_report(cve_id, report_content)
                notifier.send_alert(current_state, alert_reason, report_url['signedURL'])
                
                db.upsert_cve({
                    "id": cve_id,
                    "cvss_score": current_state['cvss'],
                    "epss_score": current_state['epss'],
                    "is_kev": current_state['is_kev'],
                    "last_alert_at": datetime.datetime.now().isoformat(),
                    "last_alert_state": current_state,
                    "updated_at": datetime.datetime.now().isoformat()
                })
            else:
                db.upsert_cve({
                    "id": cve_id,
                    "cvss_score": current_state['cvss'],
                    "epss_score": current_state['epss'],
                    "is_kev": current_state['is_kev'],
                    "updated_at": datetime.datetime.now().isoformat()
                })
            
        except Exception as e:
            print(f"[ERR] {cve_id} 처리 중 오류: {e}")
            continue

if __name__ == "__main__":
    main()