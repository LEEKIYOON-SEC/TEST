import requests
import os

class SlackNotifier:
    def __init__(self):
        self.webhook_url = os.environ.get("SLACK_WEBHOOK_URL")

    def send_alert(self, cve_data, reason, report_url=None):
        # 헤더에서 중복되는 (All Assets (*)) 제거를 위해 정리
        clean_reason = reason.split(' (')[0] if ' (' in reason else reason
        emoji = "🚨" if "KEV" in reason else "🆕"
        
        blocks = [
            {
                "type": "header",
                "text": {"type": "plain_text", "text": f"{emoji} {clean_reason}: {cve_data['id']}"}
            },
            {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*CVSS Score:*\n{cve_data['cvss']}"},
                    {"type": "mrkdwn", "text": f"*EPSS Prob:*\n{cve_data['epss']*100:.2f}%"},
                    {"type": "mrkdwn", "text": f"*KEV Listed:*\n{'✅ YES' if cve_data['is_kev'] else '❌ No'}"},
                ]
            }
        ]

        # Target Matched가 '*'인 경우 노이즈이므로 생략, 특정 자산일 때만 표시
        if "(" in reason and "*" not in reason:
            target_info = reason.split('(')[-1].replace(')', '')
            blocks.append({
                "type": "context",
                "elements": [{"type": "mrkdwn", "text": f"🎯 *Target Asset:* {target_info}"}]
            })

        # Description 제한 해제 (최대 2000자까지 허용)
        blocks.append({
            "type": "section",
            "text": {"type": "mrkdwn", "text": f"*Description:*\n{cve_data['description'][:2000]}"}
        })

        if report_url:
            blocks.append({
                "type": "actions",
                "elements": [
                    {
                        "type": "button",
                        "text": {
                            "type": "plain_text", 
                            "text": "📄 상세 분석 리포트 확인(30일 유효)" 
                        },
                        "url": report_url,
                        "style": "primary"
                    }
                ]
            })

        payload = {"blocks": blocks}
        requests.post(self.webhook_url, json=payload)