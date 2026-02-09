import os
import datetime
import time
from google import genai
from google.genai import types # [추가] 설정 타입 임포트
from collector import Collector
from database import ArgusDB
from notifier import SlackNotifier
import config

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
    """슬랙용 요약 (안전 필터 완화 적용)"""
    prompt = f"""
    Role: Security Expert.
    Task: Translate Title and Summarize Description into Korean (Max 3 lines).
    
    [Input]
    Title: {cve_data['title']}
    Desc: {cve_data['description']}
    
    [STRICT RULES]
    1. DO NOT translate technical acronyms (SSRF, XSS, RCE, SQLi).
    2. Format:
       제목: [Korean Title]
       내용: [Korean Summary]
    3. No intro/outro text.
    """
    try:
        # [수정] 안전 설정 추가 (보안 분석 내용은 차단하지 않도록)
        response = client.models.generate_content(
            model=config.MODEL_PHASE_0, 
            contents=prompt,
            config=types.GenerateContentConfig(
                safety_settings=[
                    types.SafetySetting(category="HARM_CATEGORY_DANGEROUS_CONTENT", threshold="BLOCK_NONE"),
                    types.SafetySetting(category="HARM_CATEGORY_HARASSMENT", threshold="BLOCK_NONE"),
                    types.SafetySetting(category="HARM_CATEGORY_HATE_SPEECH", threshold="BLOCK_NONE"),
                    types.SafetySetting(category="HARM_CATEGORY_SEXUALLY_EXPLICIT", threshold="BLOCK_NONE"),
                ]
            )
        )
        return response.text.strip()
    except Exception as e:
        # 실패 시 로그에 원인 출력
        print(f"[WARN] Summary Gen Failed: {e}")
        return f"제목: {cve_data['title']}\n내용: {cve_data['description'][:200]}"

def generate_report_content(cve_data, reason):
    """HTML 리포트 본문 생성"""
    cwe_str = ", ".join(cve_data['cwe']) if cve_data['cwe'] else "N/A"
    ref_list = "".join([f"<li><a href='{r}' target='_blank'>{r[:60]}...</a></li>" for r in cve_data['references']])
    
    score = cve_data['cvss']
    badge_color = "badge-gray"
    if score >= 9.0: badge_color = "badge-red"
    elif score >= 7.0: badge_color = "badge-orange"
    elif score >= 4.0: badge_color = "badge-green"

    prompt = f"""
    Role: Cyber Threat Intelligence Analyst.
    Task: Create a detailed vulnerability report in KOREAN HTML format content.
    
    [Data]
    ID: {cve_data['id']}
    Title: {cve_data['title']}
    Desc: {cve_data['description']}
    CWE: {cwe_str}
    
    [Rules]
    1. Language: Professional Korean.
    2. Terminology: Keep standard terms (SSRF, XSS, RCE).
    3. Output: Provide ONLY the inner HTML content (<h3>, <p>, <ul>).
    """
    
    ai_body = ""
    try:
        # [수정] 리포트 생성 시에도 안전 설정 적용
        response = client.models.generate_content(
            model=config.MODEL_PHASE_0, 
            contents=prompt,
            config=types.GenerateContentConfig(
                safety_settings=[
                    types.SafetySetting(category="HARM_CATEGORY_DANGEROUS_CONTENT", threshold="BLOCK_NONE"),
                    types.SafetySetting(category="HARM_CATEGORY_HARASSMENT", threshold="BLOCK_NONE"),
                    types.SafetySetting(category="HARM_CATEGORY_HATE_SPEECH", threshold="BLOCK_NONE"),
                    types.SafetySetting(category="HARM_CATEGORY_SEXUALLY_EXPLICIT", threshold="BLOCK_NONE"),
                ]
            )
        )
        ai_body = response.text.replace("```html", "").replace("```", "").strip()
    except Exception as e:
        print(f"[ERR] Report Gen Failed: {e}")
        ai_body = f"<p style='color:red'>AI 분석 실패 (Error Reason: {str(e)})</p>"

    return f"""
    <div class="header">
        <h1>🛡️ {cve_data['id']} : {cve_data['title_ko']}</h1>
        <div class="meta">Detected: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')} | Reason: {reason}</div>
    </div>

    <div class="card">
        <h2>📊 Risk Assessment</h2>
        <span class="badge {badge_color}">CVSS: {score}</span>
        <span class="badge badge-gray">EPSS: {cve_data['epss']*100:.2f}%</span>
        <span class="badge {'badge-red' if cve_data['is_kev'] else 'badge-gray'}">KEV: {'YES' if cve_data['is_kev'] else 'No'}</span>
        <p><strong>CWE:</strong> {cwe_str}</p>
    </div>

    <div class="card">
        <h2>🤖 AI Intelligence Analysis</h2>
        {ai_body}
    </div>

    <div class="card">
        <h2>🔗 References</h2>
        <ul class="ref-box">
            {ref_list if ref_list else "<li>No references provided.</li>"}
        </ul>
    </div>
    """

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
            if raw_data.get('state') != 'PUBLISHED': continue
            is_target, match_info = is_target_asset(raw_data['description'], cve_id)
            if not is_target: continue

            current_state = {
                "id": cve_id, "title": raw_data['title'], "cvss": raw_data['cvss'],
                "is_kev": cve_id in collector.kev_set, "epss": collector.epss_cache.get(cve_id, 0.0),
                "description": raw_data['description'],
                "cwe": raw_data['cwe'], "references": raw_data['references']
            }
            
            last_record = db.get_cve(cve_id)
            last_state = last_record['last_alert_state'] if last_record else None
            should_alert, alert_reason = False, ""
            
            if last_record is None: should_alert, alert_reason = True, f"신규 취약점 ({match_info})"
            else:
                if current_state['is_kev'] and not last_state.get('is_kev'): should_alert, alert_reason = True, "🚨 KEV 등재"
                elif current_state['epss'] >= 0.1 and (current_state['epss'] - last_state.get('epss', 0)) > 0.05: should_alert, alert_reason = True, "📈 EPSS 급증"

            if should_alert:
                print(f"[!] 알림 발송: {cve_id}")
                
                summary_text = generate_korean_summary(current_state)
                lines = summary_text.split('\n')
                title_ko = current_state['title']
                desc_ko = summary_text
                for line in lines:
                    if "제목:" in line: title_ko = line.split("제목:", 1)[1].strip()
                    if "내용:" in line: desc_ko = line.split("내용:", 1)[1].strip()
                
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
                db.upsert_cve({"id": cve_id, "updated_at": datetime.datetime.now().isoformat()})
        except Exception as e:
            print(f"[ERR] {cve_id}: {e}")

if __name__ == "__main__":
    main()