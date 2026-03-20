import time
from typing import Dict, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
from collections import defaultdict
from logger import logger

@dataclass
class PerformanceMetric:
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
    def __init__(self):
        """모니터 초기화"""
        self.metrics: List[PerformanceMetric] = []
        self.counters: Dict[str, int] = defaultdict(int)
        self.start_time = time.time()
        
        logger.info("Performance Monitor 초기화")
    
    def measure(self, name: str):
        return MeasurementContext(self, name)
    
    def start(self, name: str, **metadata) -> PerformanceMetric:
        metric = PerformanceMetric(name=name, metadata=metadata)
        logger.debug(f"⏱️ 측정 시작: {name}")
        return metric
    
    def stop(self, metric: PerformanceMetric, success: bool = True, **metadata):
        metric.stop(success=success, **metadata)
        self.metrics.append(metric)
        
        status = "✅" if success else "❌"
        logger.debug(
            f"{status} 측정 완료: {metric.name} "
            f"({metric.duration:.2f}초)"
        )
    
    def count(self, counter_name: str, increment: int = 1):
        self.counters[counter_name] += increment
    
    def get_stats(self) -> Dict:
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
        return False

performance_monitor = PerformanceMonitor()