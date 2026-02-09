import os
import datetime
import time
from google import genai
from collector import Collector
from database import ArgusDB
from notifier import SlackNotifier
import config

# AI Client 초기화
client = genai.Client(api_key=os.environ.get("GEMINI_API_KEY"))

def is_target_asset(cve_description, cve_id):
    desc_lower = cve_description.lower()
    for target in config.TARGET_ASSETS:
        vendor, product = target.get('vendor', '').lower(), target.get('product', '').lower()
        if vendor == "*" and product == "*": return True, "All Assets (*)"
        if vendor in desc_lower and (product == "*" or product in desc_lower):
            return True, f"Matched: {vendor}/{product}"
    return False, None

def generate_korean_summary(cve_data):
    """
    [수정] 제목과 설명을 포함하여 깔끔한 한글 요약 생성 (잡담 금지)
    """
    prompt = f"""
    You are a security analyst system.
    Task: Translate the Title and Summarize the Description into Korean.
    
    [Input]
    Title: {cve_data['title']}
    Description: {cve_data['description']}
    
    [Constraints]
    1. Output MUST be strictly in the following format:
       제목: [Translated Title]
       내용: [Summarized Description (Max 3 lines)]
    2. Do NOT add any introductory text like "Here is the translation".
    3. Do NOT add any explanations or notes at the end.
    4. Keep technical terms (SQL Injection, XSS) in English.
    """
    try:
        response = client.models.generate_content(model=config.MODEL_PHASE_0, contents=prompt)
        return response.text.strip()
    except:
        return f"제목: {cve_data['title']}\n내용: {cve_data['description'][:200]}"

def generate_report_content(cve_data, reason):
    """
    [수정] 리포트 생성 시에도 잡담 금지
    """
    prompt = f"""
    Role: Security Analyst.
    Task: Analyze this CVE and create a report in KOREAN.
    
    [Input]
    ID: {cve_data['id']}
    Title: {cve_data['title']}
    Description: {cve_data['description']}
    Reason: {reason}
    
    [Constraints]
    1. Language: Korean (Natural, Professional).
    2. Output Format: Markdown only. No conversational filler.
    3. Structure:
       - **개요**: 1-2 sentences summary.
       - **상세 분석**: Attack vector and impact.
       - **대응 방안**: Mitigation steps.
    """
    try:
        response = client.models.generate_content(model=config.MODEL_PHASE_0, contents=prompt)
        ai_text = response.text.strip()
        # 혹시 모를 마크다운 코드블럭 제거
        if ai_text.startswith("```markdown"): ai_text = ai_text[11:]
        if ai_text.startswith("```"): ai_text = ai_text[3:]
        if ai_text.endswith("```"): ai_text = ai_text[:-3]
        
        return f"# 🛡️ Argus Intelligence Report\n**Target:** `{cve_data['id']}`\n**Alert:** {reason}\n\n--- \n## 🤖 AI 보안 분석 (Korean)\n**Engine:** `{config.MODEL_PHASE_0}`\n\n{ai_text}\n\n--- \n## 📊 Risk Stats\n- **CVSS Score:** {cve_data['cvss']}\n- **EPSS Prob:** {cve_data['epss']*100:.2f}%\n- **KEV Listed:** {'🚨 YES' if cve_data['is_kev'] else 'No'}"
    except:
        return f"# 🛡️ Argus Report\nAI 분석 실패\n\n원문:\n{cve_data['description']}"

def main():
    print(f"[*] Argus Phase 0 시작 (모델: {config.MODEL_PHASE_0})")
    collector, db, notifier = Collector(), ArgusDB(), SlackNotifier()
    collector.fetch_kev()
    target_cve_ids = collector.fetch_recent_cves(hours=2)
    
    if not target_cve_ids: return
    collector.fetch_epss(target_cve_ids)
    print(f"[*] 분석 대상: {len(target_cve_ids)}건")

    for cve_id in target_cve_ids:
        try:
            time.sleep(20)
            raw_data = collector.enrich_cve(cve_id)
            
            if raw_data.get('state') != 'PUBLISHED':
                print(f"[-] 스킵: {cve_id} (상태: {raw_data.get('state')})")
                continue

            is_target, match_info = is_target_asset(raw_data['description'], cve_id)
            if not is_target: continue

            current_state = {
                "id": cve_id, "title": raw_data['title'], "cvss": raw_data['cvss'],
                "is_kev": cve_id in collector.kev_set, "epss": collector.epss_cache.get(cve_id, 0.0),
                "description": raw_data['description']
            }
            
            last_record = db.get_cve(cve_id)
            last_state = last_record['last_alert_state'] if last_record else None
            should_alert, alert_reason = False, ""
            
            if last_record is None:
                should_alert, alert_reason = True, f"신규 취약점 ({match_info})"
            else:
                if current_state['is_kev'] and not last_state.get('is_kev'):
                    should_alert, alert_reason = True, "🚨 KEV 등재 확인"
                elif current_state['epss'] >= 0.1 and (current_state['epss'] - last_state.get('epss', 0)) > 0.05:
                    should_alert, alert_reason = True, "📈 EPSS 위험도 급증"

            if should_alert:
                print(f"[!] 알림 발송: {cve_id}")
                
                # [변경] 한글 요약 (제목+내용) 생성
                summary_text = generate_korean_summary(current_state)
                # AI가 줄바꿈으로 제목/내용을 구분했을 것이므로 파싱 시도
                lines = summary_text.split('\n')
                title_ko = current_state['title']
                desc_ko = summary_text
                
                for line in lines:
                    if line.startswith("제목:"): title_ko = line.replace("제목:", "").strip()
                    if line.startswith("내용:"): desc_ko = line.replace("내용:", "").strip()
                
                # 파싱된 정보를 current_state에 업데이트 (슬랙 전송용)
                current_state['title_ko'] = title_ko
                current_state['desc_ko'] = desc_ko
                
                report_content = generate_report_content(current_state, alert_reason)
                report_url = db.upload_report(cve_id, report_content)
                notifier.send_alert(current_state, alert_reason, report_url['signedURL'])
                
                db.upsert_cve({
                    "id": cve_id, "cvss_score": current_state['cvss'], "epss_score": current_state['epss'],
                    "is_kev": current_state['is_kev'], "last_alert_at": datetime.datetime.now().isoformat(),
                    "last_alert_state": current_state, "updated_at": datetime.datetime.now().isoformat()
                })
            else:
                print(f"[-] 중복 스킵: {cve_id}")
                db.upsert_cve({
                    "id": cve_id, "cvss_score": current_state['cvss'], "epss_score": current_state['epss'],
                    "is_kev": current_state['is_kev'], "updated_at": datetime.datetime.now().isoformat()
                })
        except Exception as e:
            print(f"[ERR] {cve_id}: {e}")

if __name__ == "__main__":
    main()