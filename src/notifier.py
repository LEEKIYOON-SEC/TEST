import requests
import os
import re
from typing import Dict, Optional
from logger import logger

class NotifierError(Exception):
    """알림 관련 에러"""
    pass

class SlackNotifier:
    """
    Slack 알림 전문가
    
    역할:
    1. 신규/업데이트 CVE 알림
    2. 공식 룰 발견 알림
    3. GitHub Issue에 댓글 추가
    
    개선사항:
    - GitHub Issue 업데이트 기능
    - 에러 처리 강화
    - 더 깔끔한 메시지 포맷
    
    비유:
    이 클래스는 비서와 같아요.
    - 중요한 일이 생기면 즉시 알려주고
    - 보고서를 업데이트하고
    - 팀원들에게 공지합니다
    """
    
    def __init__(self):
        """
        Slack Webhook 초기화
        
        Slack Webhook URL은 마치 우편함 주소와 같아요.
        메시지를 이 주소로 보내면 Slack에 나타납니다.
        """
        self.webhook_url = os.environ.get("SLACK_WEBHOOK_URL")
        
        if not self.webhook_url:
            raise NotifierError("SLACK_WEBHOOK_URL이 설정되지 않음")
        
        logger.info("Slack Notifier 초기화 완료")
    
    def send_alert(self, cve_data: Dict, reason: str, report_url: Optional[str] = None) -> bool:
        """
        CVE 알림 발송
        
        새로운 취약점이나 상태 변화를 Slack으로 알립니다.
        
        Args:
            cve_data: CVE 정보
            reason: 알림 사유 (신규, KEV 등재 등)
            report_url: GitHub Issue URL (선택)
        
        Returns:
            성공 여부
        
        메시지 구조:
        - 헤더: 이모지 + 사유 + CVE ID
        - 제목: 한국어 제목
        - 영향받는 제품
        - 통계 (CVSS, EPSS, KEV)
        - 설명 + 참고 자료
        - 리포트 링크 (있으면)
        """
        try:
            clean_reason = reason.split(' (')[0] if ' (' in reason else reason
            emoji = "🚨" if "KEV" in reason else "🆕"
            
            display_title = cve_data.get('title_ko', cve_data.get('title', 'N/A'))
            display_desc = cve_data.get('desc_ko', cve_data.get('summary_ko', cve_data['description']))
            cwe_info = ", ".join(cve_data.get('cwe', [])) if cve_data.get('cwe') else "N/A"

            # 영향받는 제품 요약
            affected_text = "정보 없음"
            if cve_data.get('affected'):
                first = cve_data['affected'][0]
                affected_text = f"• *Vendor:* {first['vendor']}\n• *Product:* {first['product']}\n• *Versions:* {first['versions']}"
                if first.get('patch_version'):
                    affected_text += f"\n• *Patch:* {first['patch_version']} 이상"
                if len(cve_data['affected']) > 1:
                    affected_text += f"\n(외 {len(cve_data['affected'])-1}건)"

            # 통계 필드
            stats_fields = [
                {"type": "mrkdwn", "text": f"*CVSS:*\n{cve_data['cvss']}"},
                {"type": "mrkdwn", "text": f"*EPSS:*\n{cve_data['epss']*100:.2f}%"},
                {"type": "mrkdwn", "text": f"*KEV:*\n{'✅ YES' if cve_data['is_kev'] else '❌ No'}"},
                {"type": "mrkdwn", "text": f"*CWE:*\n{cwe_info}"},
            ]
            
            # PoC/VulnCheck 추가 필드
            extra_fields = []
            if cve_data.get('has_poc'):
                extra_fields.append(
                    {"type": "mrkdwn", "text": f"*🔥 PoC:*\n공개 ({cve_data.get('poc_count', 0)}건)"}
                )
            if cve_data.get('is_vulncheck_kev') and not cve_data['is_kev']:
                extra_fields.append(
                    {"type": "mrkdwn", "text": "*📋 VulnCheck KEV:*\n✅ YES"}
                )

            # 참고 자료 링크
            ref_text = ""
            if cve_data.get('references'):
                links = cve_data['references'][:3]
                ref_text = "\n\n*🔗 References:*\n• " + "\n• ".join([f"<{r}>" for r in links])

            # Slack 블록 구성
            blocks = [
                {"type": "header", "text": {"type": "plain_text", "text": f"{emoji} {clean_reason}: {cve_data['id']}"}},
                {"type": "section", "text": {"type": "mrkdwn", "text": f"*Title:*\n*{display_title}*"}},
                {"type": "divider"},
                {"type": "section", "text": {"type": "mrkdwn", "text": affected_text}},
                {"type": "divider"},
                {"type": "section", "fields": stats_fields},
            ]
            
            # PoC/VulnCheck 추가 필드 (있으면)
            if extra_fields:
                blocks.append({"type": "section", "fields": extra_fields})
            
            blocks.append(
                {"type": "section", "text": {"type": "mrkdwn", "text": f"*Description:*\n{display_desc}{ref_text}"}}
            )

            # 타겟 자산 정보 (있으면)
            if "(" in reason and "*" not in reason:
                target_info = reason.split('(')[-1].replace(')', '')
                blocks.append({"type": "context", "elements": [{"type": "mrkdwn", "text": f"🎯 *Target Asset:* {target_info}"}]})
            
            # 리포트 링크 버튼
            if report_url:
                blocks.append({
                    "type": "actions",
                    "elements": [{"type": "button", "text": {"type": "plain_text", "text": "AI 상세 분석 리포트"}, "url": report_url, "style": "primary"}]
                })

            # Slack 전송
            response = requests.post(self.webhook_url, json={"blocks": blocks}, timeout=10)
            response.raise_for_status()
            
            logger.info(f"Slack 알림 전송: {cve_data['id']}")
            return True
            
        except requests.exceptions.RequestException as e:
            logger.error(f"Slack 전송 실패: {e}")
            return False
        except Exception as e:
            logger.error(f"알림 생성 에러: {e}")
            return False
    
    def send_official_rule_update(self, cve_id: str, title: str, rules_info: Dict, original_report_url: Optional[str] = None) -> bool:
        """
        공식 룰 발견 알림
        
        이전에 AI 생성 룰로 보고된 CVE에 대해
        공식 룰이 발견되었을 때 알림을 보냅니다.
        
        Args:
            cve_id: CVE ID
            title: CVE 제목
            rules_info: 룰 정보 (get_rules 결과)
            original_report_url: 원본 GitHub Issue URL
        
        Returns:
            성공 여부
        
        왜 별도 알림?
        - 공식 룰은 AI 룰보다 훨씬 신뢰할 수 있어요
        - 보안팀이 빠르게 교체할 수 있도록 알려줍니다
        """
        try:
            blocks = [
                {"type": "header", "text": {"type": "plain_text", "text": f"✅ 공식 룰 발견: {cve_id}"}},
                {"type": "section", "text": {"type": "mrkdwn", "text": f"*{title}*\n\n이전에 AI 생성 룰로 보고된 취약점에 대한 *공식 검증된 룰*이 발견되었습니다."}},
                {"type": "divider"}
            ]
            
            # 발견된 공식 룰 표시
            rule_text = "*🛡️ 발견된 공식 룰:*\n"
            
            # Sigma
            if rules_info.get('sigma') and rules_info['sigma'].get('verified'):
                rule_text += f"• Sigma: {rules_info['sigma']['source']}\n"
            
            # Network (여러 개 가능)
            if rules_info.get('network'):
                for net_rule in rules_info['network']:
                    if net_rule.get('verified'):
                        engine = net_rule.get('engine', 'unknown').upper()
                        rule_text += f"• Network ({engine}): {net_rule['source']}\n"
            
            # Yara
            if rules_info.get('yara') and rules_info['yara'].get('verified'):
                rule_text += f"• Yara: {rules_info['yara']['source']}\n"
            
            blocks.append({"type": "section", "text": {"type": "mrkdwn", "text": rule_text}})
            
            # 원본 리포트 링크
            if original_report_url:
                blocks.append({
                    "type": "actions",
                    "elements": [
                        {"type": "button", "text": {"type": "plain_text", "text": "업데이트된 리포트 보기"}, "url": original_report_url, "style": "primary"}
                    ]
                })
            
            response = requests.post(self.webhook_url, json={"blocks": blocks}, timeout=10)
            response.raise_for_status()
            
            logger.info(f"공식 룰 발견 알림 전송: {cve_id}")
            return True
            
        except Exception as e:
            logger.error(f"공식 룰 알림 실패: {e}")
            return False
    
    def update_github_issue(self, issue_url: str, comment: str) -> bool:
        """
        GitHub Issue에 댓글 추가
        
        공식 룰이 발견되면 기존 Issue에 업데이트 댓글을 남깁니다.
        
        Args:
            issue_url: GitHub Issue URL
            comment: 댓글 내용
        
        Returns:
            성공 여부
        
        작동 원리:
        1. Issue URL에서 API URL로 변환
        2. GitHub API로 댓글 POST
        
        예:
        https://github.com/user/repo/issues/123
        → https://api.github.com/repos/user/repo/issues/123/comments
        """
        try:
            # URL 파싱
            match = re.search(r'github\.com/([^/]+)/([^/]+)/issues/(\d+)', issue_url)
            if not match:
                logger.error(f"잘못된 Issue URL: {issue_url}")
                return False
            
            owner, repo, issue_number = match.groups()
            api_url = f"https://api.github.com/repos/{owner}/{repo}/issues/{issue_number}/comments"
            
            # 댓글 작성
            headers = {
                "Authorization": f"token {os.environ.get('GH_TOKEN')}",
                "Accept": "application/vnd.github.v3+json"
            }
            
            payload = {"body": comment}
            
            response = requests.post(api_url, headers=headers, json=payload, timeout=10)
            response.raise_for_status()
            
            logger.info(f"GitHub Issue 댓글 추가: {issue_url}")
            return True
            
        except requests.exceptions.RequestException as e:
            logger.error(f"GitHub 댓글 추가 실패: {e}")
            return False
        except Exception as e:
            logger.error(f"Issue 업데이트 에러: {e}")
            return False