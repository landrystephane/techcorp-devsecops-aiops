from aiops.detector import detect_anomaly, make_report

def test_threshold():
    assert not detect_anomaly(2)
    assert detect_anomaly(3)

def test_approval_required():
    assert make_report(4, [], 'pending')['human_approval_required'] is True
