import os
import datetime
from supabase import create_client, Client
from typing import Dict, List, Optional
from logger import logger

class DatabaseError(Exception):
    """데이터베이스 관련 에러"""
    pass

class ArgusDB:
    def __init__(self):
        """데이터베이스 연결 초기화"""
        url = os.environ.get("SUPABASE_URL")
        key = os.environ.get("SUPABASE_KEY")
        
        if not url or not key:
            raise DatabaseError("SUPABASE_URL 또는 SUPABASE_KEY가 설정되지 않음")
        
        try:
            self.client: Client = create_client(url, key)
            logger.info("Supabase 연결 성공")
        except Exception as e:
            raise DatabaseError(f"Supabase 연결 실패: {e}")
    
    def get_cve(self, cve_id: str) -> Optional[Dict]:
        try:
            response = self.client.table("cves").select("*").eq("id", cve_id).execute()
            
            if response.data:
                logger.debug(f"CVE 발견: {cve_id}")
                return response.data[0]
            else:
                logger.debug(f"신규 CVE: {cve_id}")
                return None
                
        except Exception as e:
            logger.error(f"CVE 조회 실패 ({cve_id}): {e}")
            return None
    
    def upsert_cve(self, data: Dict) -> bool:
        try:
            self.client.table("cves").upsert(data).execute()
            logger.debug(f"CVE 저장 성공: {data.get('id')}")
            return True
        except Exception as e:
            logger.error(f"CVE 저장 실패 ({data.get('id')}): {e}")
            return False
    
    def get_ai_generated_cves(self, days: int = 7) -> List[Dict]:
        try:
            response = self.client.table("cves") \
                .select("*") \
                .eq("has_official_rules", False) \
                .not_.is_("rules_snapshot", "null") \
                .execute()
            
            if not response.data:
                logger.info("AI 생성 룰 CVE: 0건")
                return []
            
            now = datetime.datetime.now(datetime.timezone.utc)
            eligible = []
            
            for record in response.data:
                cvss = record.get('cvss_score', 0) or 0
                is_kev = record.get('is_kev', False)
                epss = record.get('epss_score', 0) or 0
                
                # 최근 7일 이내에 이미 체크했으면 스킵
                last_check = record.get('last_rule_check_at', '')
                if last_check:
                    try:
                        last_check_dt = datetime.datetime.fromisoformat(last_check.replace('Z', '+00:00'))
                        if (now - last_check_dt).days < 7:
                            continue
                    except (ValueError, TypeError):
                        pass
                
                # KEV 등재 또는 EPSS > 0 → 무기한 (보존 기간 제한 없음)
                if is_kev or epss > 0:
                    eligible.append(record)
                    continue
                
                # CVSS 7.0 미만 → 재확인 안 함
                if cvss < 7.0:
                    continue
                
                # CVSS 기반 보존 기간
                max_age_days = 180 if cvss >= 9.0 else 90
                
                created_at = record.get('last_alert_at', record.get('created_at', ''))
                if created_at:
                    try:
                        created_dt = datetime.datetime.fromisoformat(created_at.replace('Z', '+00:00'))
                        if (now - created_dt).days > max_age_days:
                            continue
                    except (ValueError, TypeError):
                        pass
                
                eligible.append(record)
            
            logger.info(f"AI 생성 룰 CVE: {len(response.data)}건 중 재확인 대상: {len(eligible)}건")
            return eligible
            
        except Exception as e:
            logger.error(f"AI 생성 CVE 조회 실패: {e}")
            return []
    
    def get_report_url(self, cve_id: str) -> Optional[str]:
        try:
            record = self.get_cve(cve_id)
            return record.get('report_url') if record else None
        except Exception as e:
            logger.error(f"Report URL 조회 실패: {e}")
            return None