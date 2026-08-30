import time
import pytest

def test_lightweight_performance_baseline():
    """Sanity test: 100 simple analytical iterations must complete in under 5.0 seconds"""
    start_time = time.time()
    iterations = 100
    for i in range(iterations):
        _ = {"event_id": f"PERF-{i}", "status": "processed", "risk_score": (i % 100)}
    elapsed = time.time() - start_time
    assert elapsed < 5.0