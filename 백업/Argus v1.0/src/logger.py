import logging
import sys
from datetime import datetime

class ColoredFormatter(logging.Formatter):
    """
    컬러 출력을 지원하는 로그 포매터
    GitHub Actions 환경에서도 가독성 좋은 로그를 제공합니다.
    """
    
    # ANSI 색상 코드
    COLORS = {
        'DEBUG': '\033[36m',     # Cyan
        'INFO': '\033[32m',      # Green
        'WARNING': '\033[33m',   # Yellow
        'ERROR': '\033[31m',     # Red
        'CRITICAL': '\033[35m',  # Magenta
        'RESET': '\033[0m'
    }
    
    def format(self, record):
        """로그 레코드에 색상 적용"""
        log_color = self.COLORS.get(record.levelname, self.COLORS['RESET'])
        reset = self.COLORS['RESET']
        
        # 로그 메시지 포맷: [시간] [레벨] 메시지
        formatted = f"{log_color}[{record.levelname}]{reset} {record.getMessage()}"
        
        # 에러인 경우 스택 트레이스 추가
        if record.exc_info:
            formatted += f"\n{self.formatException(record.exc_info)}"
        
        return formatted

def setup_logger(name="Argus", level=logging.INFO):
    """
    Argus 시스템 전용 로거 설정
    
    특징:
    - 콘솔 출력: 컬러로 구분된 로그
    - 파일 저장: 장기 보관용 (선택적)
    - 레벨 관리: INFO 이상만 출력
    
    Args:
        name: 로거 이름
        level: 최소 로그 레벨 (기본: INFO)
    
    Returns:
        설정된 logger 객체
    """
    logger = logging.getLogger(name)
    logger.setLevel(level)
    
    # 중복 핸들러 방지
    if logger.handlers:
        return logger
    
    # 콘솔 핸들러 (컬러 출력)
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(level)
    console_handler.setFormatter(ColoredFormatter())
    logger.addHandler(console_handler)
    
    return logger

# 전역 로거 인스턴스
logger = setup_logger()
