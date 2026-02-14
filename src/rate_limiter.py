import time
from typing import Dict, Optional
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from logger import logger

@dataclass
class RateLimitInfo:
    """
    API Rate Limit 정보를 담는 데이터 클래스
    
    이것은 마치 "API 사용 내역서"와 같아요.
    얼마나 썼고, 얼마나 남았고, 언제 리셋되는지 모두 기록합니다.
    
    Attributes:
        limit: 최대 호출 가능 횟수 (예: 5000/hour)
        used: 사용한 횟수
        reset_at: 리셋 시간 (datetime)
        window_seconds: 시간 윈도우 (초)
    """
    limit: int
    used: int = 0
    reset_at: datetime = field(default_factory=datetime.now)
    window_seconds: int = 3600  # 기본 1시간
    
    @property
    def remaining(self) -> int:
        """남은 호출 가능 횟수"""
        return max(0, self.limit - self.used)
    
    @property
    def usage_percent(self) -> float:
        """사용률 (0-100%)"""
        if self.limit == 0:
            return 0
        return (self.used / self.limit) * 100
    
    @property
    def is_exhausted(self) -> bool:
        """한도 소진 여부"""
        return self.used >= self.limit
    
    @property
    def time_until_reset(self) -> float:
        """리셋까지 남은 시간 (초)"""
        now = datetime.now()
        if now >= self.reset_at:
            return 0
        return (self.reset_at - now).total_seconds()
    
    def should_wait(self) -> bool:
        """대기가 필요한지 판단"""
        # 80% 이상 사용 시 속도 조절
        return self.usage_percent >= 80

class RateLimitManager:
    """
    API Rate Limit 통합 관리자
    
    역할:
    1. 각 API의 호출 횟수 추적
    2. 한도 근접 시 자동 속도 조절
    3. 한도 초과 방지
    4. 통계 및 경고
    
    작동 원리:
    - 매 API 호출 전에 check_and_wait() 호출
    - 사용 가능하면 True 반환, 아니면 대기 후 True
    - 호출 후 record_call()로 기록
    
    비유:
    이 클래스는 마치 "교통 신호등"과 같아요.
    - 초록불(여유): 빠르게 진행
    - 노란불(80%): 속도 조절
    - 빨간불(100%): 일시 정지
    """
    
    def __init__(self):
        """
        Rate Limit 정보 초기화
        
        각 API마다 별도의 추적 정보를 관리합니다.
        마치 각 신용카드마다 별도의 한도가 있는 것과 같아요.
        """
        self.limits: Dict[str, RateLimitInfo] = {
            "github": RateLimitInfo(
                limit=5000,
                window_seconds=3600  # 1시간
            ),
            "groq": RateLimitInfo(
                limit=30,
                window_seconds=60  # 1분
            ),
            "epss": RateLimitInfo(
                limit=60,
                window_seconds=60  # 1분
            ),
            "kev": RateLimitInfo(
                limit=10,  # 보수적으로 설정
                window_seconds=3600  # 1시간
            ),
            "gemini": RateLimitInfo(
                limit=60,
                window_seconds=60  # 1분
            )
        }
        
        # 통계
        self.stats = {
            "total_calls": 0,
            "total_waits": 0,
            "total_wait_time": 0.0
        }
        
        logger.info("Rate Limit Manager 초기화 완료")
    
    def check_and_wait(self, api_name: str) -> bool:
        """
        API 호출 가능 여부 확인 및 대기
        
        이 함수는 API를 호출하기 전에 반드시 호출해야 합니다.
        마치 횡단보도를 건너기 전에 신호등을 확인하는 것과 같아요.
        
        작동 과정:
        1. 리셋 시간이 지났으면 카운터 초기화
        2. 한도 소진 시 리셋까지 대기
        3. 80% 이상 사용 시 속도 조절
        4. 90% 이상 사용 시 경고 로그
        
        Args:
            api_name: API 이름 (github, groq, epss 등)
        
        Returns:
            항상 True (호출 가능 상태가 될 때까지 대기)
        
        예시:
            >>> manager = RateLimitManager()
            >>> manager.check_and_wait("github")  # 호출 가능 확인
            >>> # GitHub API 호출...
            >>> manager.record_call("github")  # 호출 기록
        """
        if api_name not in self.limits:
            logger.warning(f"알 수 없는 API: {api_name}, Rate Limit 적용 안 됨")
            return True
        
        info = self.limits[api_name]
        now = datetime.now()
        
        # Step 1: 리셋 시간 확인 및 초기화
        if now >= info.reset_at:
            old_used = info.used
            info.used = 0
            info.reset_at = now + timedelta(seconds=info.window_seconds)
            
            if old_used > 0:
                logger.debug(f"{api_name} Rate Limit 리셋 (이전 사용: {old_used}/{info.limit})")
        
        # Step 2: 한도 소진 확인
        if info.is_exhausted:
            wait_time = info.time_until_reset
            logger.warning(
                f"⚠️ {api_name} Rate Limit 도달! "
                f"({info.used}/{info.limit}) "
                f"{wait_time:.0f}초 대기 중..."
            )
            
            time.sleep(wait_time + 1)  # 안전 마진 1초
            self.stats["total_waits"] += 1
            self.stats["total_wait_time"] += wait_time
            
            # 리셋 후 재귀 호출
            return self.check_and_wait(api_name)
        
        # Step 3: 사용률 기반 속도 조절
        usage = info.usage_percent
        
        if usage >= 90:
            # 90% 이상: 경고 + 긴 대기
            logger.warning(
                f"⚠️ {api_name} 사용률 높음: {usage:.1f}% "
                f"({info.remaining}개 남음) - 속도 조절 중"
            )
            wait_time = 5.0  # 5초 대기
            time.sleep(wait_time)
            self.stats["total_wait_time"] += wait_time
            
        elif usage >= 80:
            # 80-90%: 적당한 대기
            logger.debug(
                f"{api_name} 사용률: {usage:.1f}% "
                f"({info.remaining}개 남음) - 속도 조절"
            )
            wait_time = 2.0  # 2초 대기
            time.sleep(wait_time)
            self.stats["total_wait_time"] += wait_time
        
        return True
    
    def record_call(self, api_name: str):
        """
        API 호출 기록
        
        API를 호출한 후에 이 함수를 호출해서 사용 횟수를 증가시킵니다.
        마치 전화 통화 후에 통화 시간이 자동으로 기록되는 것과 같아요.
        
        Args:
            api_name: API 이름
        
        예시:
            >>> response = requests.get(github_url)  # API 호출
            >>> manager.record_call("github")  # 기록
        """
        if api_name not in self.limits:
            return
        
        info = self.limits[api_name]
        info.used += 1
        self.stats["total_calls"] += 1
        
        logger.debug(
            f"{api_name} 호출 기록: {info.used}/{info.limit} "
            f"({info.usage_percent:.1f}%)"
        )
    
    def get_status(self, api_name: Optional[str] = None) -> Dict:
        """
        현재 상태 조회
        
        Args:
            api_name: 특정 API 이름 (None이면 전체)
        
        Returns:
            상태 정보 딕셔너리
        """
        if api_name:
            if api_name not in self.limits:
                return {}
            
            info = self.limits[api_name]
            return {
                "api": api_name,
                "used": info.used,
                "limit": info.limit,
                "remaining": info.remaining,
                "usage_percent": round(info.usage_percent, 1),
                "reset_in": round(info.time_until_reset, 0)
            }
        
        # 전체 상태
        return {
            "apis": {
                name: {
                    "used": info.used,
                    "limit": info.limit,
                    "remaining": info.remaining,
                    "usage": f"{info.usage_percent:.1f}%"
                }
                for name, info in self.limits.items()
            },
            "stats": self.stats
        }
    
    def print_summary(self):
        """
        실행 종료 시 요약 출력
        
        이것은 마치 "이번 달 통신비 청구서"와 같아요.
        어떤 API를 얼마나 썼는지 요약해서 보여줍니다.
        """
        logger.info("=" * 60)
        logger.info("Rate Limit 사용 요약")
        logger.info("=" * 60)
        
        for name, info in self.limits.items():
            usage_bar = self._create_usage_bar(info.usage_percent)
            logger.info(
                f"{name:10s}: {info.used:4d}/{info.limit:4d} "
                f"[{usage_bar}] {info.usage_percent:5.1f}%"
            )
        
        logger.info("-" * 60)
        logger.info(f"총 호출 횟수: {self.stats['total_calls']}")
        logger.info(f"대기 횟수: {self.stats['total_waits']}")
        logger.info(f"총 대기 시간: {self.stats['total_wait_time']:.1f}초")
        logger.info("=" * 60)
    
    def _create_usage_bar(self, percent: float) -> str:
        """
        사용률 시각화 바 생성
        
        예: [████████░░] 80%
        
        왜 필요한가요?
        - 숫자만 보면 직관적이지 않아요
        - 시각화하면 한눈에 파악 가능합니다
        """
        bar_length = 10
        filled = int((percent / 100) * bar_length)
        empty = bar_length - filled
        
        # 색상 선택
        if percent >= 90:
            symbol = "█"  # 위험 (빨강 느낌)
        elif percent >= 70:
            symbol = "▓"  # 주의 (노랑 느낌)
        else:
            symbol = "░"  # 안전 (초록 느낌)
        
        bar = symbol * filled + "░" * empty
        return bar

# 전역 Rate Limit Manager 인스턴스
# 모든 모듈에서 이것을 import해서 사용합니다
rate_limit_manager = RateLimitManager()
