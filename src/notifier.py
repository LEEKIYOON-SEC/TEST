import requests
import os

class SlackNotifier:
    def __init__(self):
        self.webhook_url = os.environ.get("SLACK_WEBHOOK_URL")

    def send_alert(self, cve_data, reason, report_url=None):
        clean_reason = reason.split(' (')[0] if ' (' in reason else reason
        emoji = "🚨" if "KEV" in reason else "🆕"
        
        display_title = cve_data.get('title_ko', cve_data.get('title', 'N/A'))
        display_desc = cve_data.get('desc_ko', cve_data.get('summary_ko', cve_data['description']))
        cwe_info = ", ".join(cve_data.get('cwe', [])) if cve_data.get('cwe') else "N/A"

        # Vendor 정보 포맷팅
        affected_text = "정보 없음"
        if cve_data.get('affected'):
            first = cve_data['affected'][0]
            affected_text = f"• *Vendor:* {first['vendor']}\n• *Product:* {first['product']}\n• *Versions:* {first['versions']}"
            if len(cve_data['affected']) > 1:
                affected_text += f"\n(외 {len(cve_data['affected'])-1}건)"

        # [추가] CCE 정보 포맷팅 (있을 때만 표시)
        cce_list = cve_data.get('cce', [])
        cce_text = ", ".join(cce_list) if cce_list else None

        # 통계 필드 구성
        stats_fields = [
            {"type": "mrkdwn", "text": f"*CVSS:*\n{cve_data['cvss']}"},
            {"type": "mrkdwn", "text": f"*EPSS:*\n{cve_data['epss']*100:.2f}%"},
            {"type": "mrkdwn", "text": f"*KEV:*\n{'✅ YES' if cve_data['is_kev'] else '❌ No'}"},
            {"type": "mrkdwn", "text": f"*CWE:*\n{cwe_info}"},
        ]
        
        # CCE가 있으면 통계 필드에 추가 (없으면 기존 유지)
        if cce_text:
            stats_fields.append({"type": "mrkdwn", "text": f"*CCE:*\n{cce_text}"})

        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{emoji} {clean_reason}: {cve_data['id']}"}
            },
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": f"*Title:*\n*{display_title}*"}
            },
            {"type": "divider"},
            {
                "type": "section",
                "text": {"type": "mrkdwn", "text": affected_text}
            },
            {"type": "divider"},
            {
                "type": "section",
                "fields": stats_fields # 동적으로 구성된 필드 사용
            }
        ]

        if "(" in reason and "*" not in reason:
            target_info = reason.split('(')[-1].replace(')', '')
            blocks.append({
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"🎯 *Target Asset:* {target_info}"}]
            })
        
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Description:*\n{display_desc}"}
        })

        if report_url:
            blocks.append({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {"type": "plain_text", "text": "📄 상세 분석 리포트 확인 (30일 유효)"},
                        "url": report_url,
                        "style": "primary"
                    }
                ]
            })

        requests.post(self.webhook_url, json={"blocks": blocks})