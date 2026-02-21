import time
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
from logger import logger

@dataclass
class PerformanceMetric:
    """
    성능 메트릭 데이터 클래스
    
    각 작업의 성능을 측정하고 기록합니다.
    마치 "스톱워치 기록"과 같아요.
    
    Attributes:
        name: 작업 이름
        start_time: 시작 시간
        end_time: 종료 시간
        duration: 소요 시간 (초)
        success: 성공 여부
        metadata: 추가 정보
    """
    name: str
    start_time: float = field(default_factory=time.time)
    end_time: Optional[float] = None
    duration: Optional[float] = None
    success: bool = True
    metadata: Dict = field(default_factory=dict)
    
    def stop(self, success: bool = True, **metadata):
        """측정 종료"""
        self.end_time = time.time()
        self.duration = self.end_time - self.start_time
        self.success = success
        self.metadata.update(metadata)
        return self

class PerformanceMonitor:
    """
    성능 모니터링 시스템
    
    역할:
    1. 작업별 소요 시간 측정
    2. 성공/실패 통계 수집
    3. 병목 구간 자동 감지
    4. 상세 리포트 생성
    
    작동 원리:
    - with monitor.measure("작업명"): 블록으로 자동 측정
    - 또는 start/stop으로 수동 제어
    - 모든 데이터를 메모리에 보관
    - 종료 시 분석 및 리포트 생성
    
    비유:
    이 클래스는 마치 "경기 분석 시스템"과 같아요.
    - 각 선수(작업)의 기록을 측정
    - 팀 전체 성적 분석
    - 개선점 제안
    
    예시:
        >>> monitor = PerformanceMonitor()
        >>> 
        >>> # 방법 1: with 블록 (권장)
        >>> with monitor.measure("CVE 수집"):
        >>>     collector.fetch_cves()
        >>> 
        >>> # 방법 2: 수동 제어
        >>> metric = monitor.start("AI 분석")
        >>> analyzer.analyze(cve)
        >>> monitor.stop(metric, success=True)
    """
    
    def __init__(self):
        """모니터 초기화"""
        self.metrics: List[PerformanceMetric] = []
        self.counters: Dict[str, int] = defaultdict(int)
        self.start_time = time.time()
        
        logger.info("Performance Monitor 초기화")
    
    def measure(self, name: str):
        """
        컨텍스트 매니저로 자동 측정
        
        이것은 가장 편리한 방법이에요.
        with 블록이 끝나면 자동으로 시간을 측정하고 기록합니다.
        
        Args:
            name: 작업 이름
        
        Returns:
            MeasurementContext 객체
        
        예시:
            >>> with monitor.measure("데이터 수집"):
            >>>     # 여기서 작업 수행
            >>>     collect_data()
            >>> # 블록이 끝나면 자동으로 측정 완료
        """
        return MeasurementContext(self, name)
    
    def start(self, name: str, **metadata) -> PerformanceMetric:
        """
        측정 시작 (수동)
        
        더 세밀한 제어가 필요할 때 사용합니다.
        
        Args:
            name: 작업 이름
            **metadata: 추가 정보
        
        Returns:
            PerformanceMetric 객체 (나중에 stop에 전달)
        """
        metric = PerformanceMetric(name=name, metadata=metadata)
        logger.debug(f"⏱️ 측정 시작: {name}")
        return metric
    
    def stop(self, metric: PerformanceMetric, success: bool = True, **metadata):
        """
        측정 종료 (수동)
        
        Args:
            metric: start()에서 반환된 객체
            success: 성공 여부
            **metadata: 추가 정보
        """
        metric.stop(success=success, **metadata)
        self.metrics.append(metric)
        
        status = "✅" if success else "❌"
        logger.debug(
            f"{status} 측정 완료: {metric.name} "
            f"({metric.duration:.2f}초)"
        )
    
    def count(self, counter_name: str, increment: int = 1):
        """
        카운터 증가
        
        횟수를 세어야 할 때 사용합니다.
        예: CVE 처리 건수, 알림 발송 횟수 등
        
        Args:
            counter_name: 카운터 이름
            increment: 증가량 (기본 1)
        
        예시:
            >>> monitor.count("CVE 처리")
            >>> monitor.count("알림 발송", increment=5)
        """
        self.counters[counter_name] += increment
    
    def get_stats(self) -> Dict:
        """
        현재 통계 반환
        
        Returns:
            통계 딕셔너리
        """
        if not self.metrics:
            return {
                "total_operations": 0,
                "total_time": 0,
                "success_rate": 0,
                "counters": dict(self.counters)
            }
        
        successful = [m for m in self.metrics if m.success]
        failed = [m for m in self.metrics if not m.success]
        
        total_time = sum(m.duration for m in self.metrics if m.duration)
        
        return {
            "total_operations": len(self.metrics),
            "successful": len(successful),
            "failed": len(failed),
            "success_rate": (len(successful) / len(self.metrics)) * 100,
            "total_time": total_time,
            "average_time": total_time / len(self.metrics) if self.metrics else 0,
            "counters": dict(self.counters)
        }
    
    def find_bottlenecks(self, threshold: float = 10.0) -> List[Dict]:
        """
        병목 구간 탐지
        
        어떤 작업이 오래 걸리는지 자동으로 찾아줍니다.
        마치 "교통 체증 구간"을 찾는 것과 같아요.
        
        Args:
            threshold: 느린 것으로 간주할 시간 (초, 기본 10초)
        
        Returns:
            느린 작업 리스트
        
        예시:
            >>> bottlenecks = monitor.find_bottlenecks(threshold=5.0)
            >>> for item in bottlenecks:
            >>>     print(f"{item['name']}: {item['duration']}초")
        """
        slow_operations = []
        
        for metric in self.metrics:
            if metric.duration and metric.duration > threshold:
                slow_operations.append({
                    "name": metric.name,
                    "duration": round(metric.duration, 2),
                    "success": metric.success,
                    "metadata": metric.metadata
                })
        
        # 느린 순으로 정렬
        slow_operations.sort(key=lambda x: x['duration'], reverse=True)
        
        return slow_operations
    
    def get_operation_breakdown(self) -> Dict[str, Dict]:
        """
        작업별 통계 집계
        
        같은 이름의 작업들을 모아서 평균, 최소, 최대를 계산합니다.
        마치 "성적표"를 만드는 것과 같아요.
        
        Returns:
            작업별 통계 딕셔너리
        
        예시 반환값:
            {
                "CVE 수집": {
                    "count": 100,
                    "avg_duration": 2.5,
                    "min_duration": 1.2,
                    "max_duration": 5.3,
                    "success_rate": 98.0
                }
            }
        """
        breakdown = defaultdict(lambda: {
            "durations": [],
            "successes": 0,
            "failures": 0
        })
        
        for metric in self.metrics:
            data = breakdown[metric.name]
            if metric.duration:
                data["durations"].append(metric.duration)
            
            if metric.success:
                data["successes"] += 1
            else:
                data["failures"] += 1
        
        # 통계 계산
        result = {}
        for name, data in breakdown.items():
            durations = data["durations"]
            total = data["successes"] + data["failures"]
            
            result[name] = {
                "count": total,
                "success_rate": (data["successes"] / total * 100) if total > 0 else 0,
                "avg_duration": sum(durations) / len(durations) if durations else 0,
                "min_duration": min(durations) if durations else 0,
                "max_duration": max(durations) if durations else 0
            }
        
        return result
    
    def print_summary(self):
        """
        실행 종료 시 상세 리포트 출력
        
        이것은 마치 "학기말 성적표"와 같아요.
        전체 성적, 과목별 점수, 개선점을 모두 보여줍니다.
        """
        elapsed = time.time() - self.start_time
        stats = self.get_stats()
        breakdown = self.get_operation_breakdown()
        bottlenecks = self.find_bottlenecks(threshold=10.0)
        
        logger.info("")
        logger.info("=" * 70)
        logger.info("📊 성능 모니터링 리포트")
        logger.info("=" * 70)
        
        # 전체 요약
        logger.info(f"총 실행 시간: {elapsed:.1f}초")
        logger.info(f"총 작업 수: {stats['total_operations']}건")
        logger.info(f"성공률: {stats['success_rate']:.1f}%")
        logger.info(f"평균 작업 시간: {stats['average_time']:.2f}초")
        
        # 카운터
        if self.counters:
            logger.info("")
            logger.info("-" * 70)
            logger.info("📈 작업 통계")
            logger.info("-" * 70)
            for name, count in self.counters.items():
                logger.info(f"  {name}: {count}건")
        
        # 작업별 상세 통계
        if breakdown:
            logger.info("")
            logger.info("-" * 70)
            logger.info("⏱️  작업별 상세 통계")
            logger.info("-" * 70)
            
            for name, data in sorted(breakdown.items(), key=lambda x: x[1]['avg_duration'], reverse=True):
                logger.info(
                    f"  {name:30s} | "
                    f"평균: {data['avg_duration']:6.2f}초 | "
                    f"횟수: {data['count']:3d}건 | "
                    f"성공률: {data['success_rate']:5.1f}%"
                )
        
        # 병목 구간
        if bottlenecks:
            logger.info("")
            logger.info("-" * 70)
            logger.info("🐌 병목 구간 (10초 이상 소요)")
            logger.info("-" * 70)
            
            for i, item in enumerate(bottlenecks[:5], 1):  # 상위 5개만
                status = "✅" if item['success'] else "❌"
                logger.info(
                    f"  {i}. {status} {item['name']} - {item['duration']}초"
                )
            
            if len(bottlenecks) > 5:
                logger.info(f"  ... 외 {len(bottlenecks) - 5}건")
        
        # 성능 등급
        logger.info("")
        logger.info("-" * 70)
        grade = self._calculate_performance_grade(stats, elapsed)
        logger.info(f"🏆 전체 성능 등급: {grade}")
        logger.info("=" * 70)
        logger.info("")
    
    def _calculate_performance_grade(self, stats: Dict, elapsed: float) -> str:
        """
        성능 등급 계산
        
        여러 지표를 종합해서 A, B, C 등급을 매깁니다.
        마치 학교 성적표의 등급과 같아요.
        
        평가 기준:
        - 성공률 (높을수록 좋음)
        - 평균 작업 시간 (짧을수록 좋음)
        - 총 실행 시간 (적당한 게 좋음)
        """
        score = 0
        
        # 성공률 평가 (50점)
        success_rate = stats.get('success_rate', 0)
        if success_rate >= 95:
            score += 50
        elif success_rate >= 90:
            score += 40
        elif success_rate >= 80:
            score += 30
        else:
            score += 20
        
        # 평균 작업 시간 평가 (30점)
        avg_time = stats.get('average_time', 0)
        if avg_time < 5:
            score += 30
        elif avg_time < 10:
            score += 20
        elif avg_time < 20:
            score += 10
        else:
            score += 5
        
        # 총 실행 시간 평가 (20점)
        if elapsed < 300:  # 5분 이내
            score += 20
        elif elapsed < 600:  # 10분 이내
            score += 15
        elif elapsed < 1200:  # 20분 이내
            score += 10
        else:
            score += 5
        
        # 등급 변환
        if score >= 90:
            return "A+ (탁월함)"
        elif score >= 80:
            return "A (우수함)"
        elif score >= 70:
            return "B (양호함)"
        elif score >= 60:
            return "C (보통)"
        else:
            return "D (개선 필요)"

class MeasurementContext:
    """
    with 블록을 위한 컨텍스트 매니저
    
    이 클래스는 사용자가 직접 사용하지 않아요.
    monitor.measure()가 내부적으로 사용합니다.
    
    작동 원리:
    - __enter__: with 블록 시작 시 측정 시작
    - __exit__: with 블록 종료 시 측정 종료
    """
    
    def __init__(self, monitor: PerformanceMonitor, name: str):
        self.monitor = monitor
        self.name = name
        self.metric = None
    
    def __enter__(self):
        self.metric = self.monitor.start(self.name)
        return self
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        # 예외 발생 시 실패로 기록
        success = exc_type is None
        self.monitor.stop(self.metric, success=success)
        return False  # 예외를 다시 발생시킴

# 전역 Performance Monitor 인스턴스
performance_monitor = PerformanceMonitor()
