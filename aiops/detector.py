"""Starter: students implement anomaly detection, evidence and Ollama report."""
import json
import urllib.request
from pathlib import Path
PROMETHEUS="http://localhost:9090/api/v1/query"
QUERY='sum(increase(techcorp_http_requests_total{status="500"}[1m]))'

def get_error_count():
    from urllib.parse import urlencode
    with urllib.request.urlopen(PROMETHEUS+'?'+urlencode({'query':QUERY}), timeout=5) as response:
        payload=json.load(response)
    series=payload.get('data',{}).get('result',[])
    return float(series[0]['value'][1]) if series else 0.0

def detect_anomaly(count, threshold=3):
    # TODO: Enhance with baseline and explain why a threshold is insufficient for ML AIOps.
    return count >= threshold

def make_report(count, logs, hypothesis):
    return {'incident_id':'INC-2026-1042', 'observations':{'http_500_last_minute':count,'logs':logs},
            'hypothesis':hypothesis,'checks_read_only':[], 'confidence':'unverified',
            'human_approval_required':True}

if __name__=='__main__':
    count=get_error_count()
    report=make_report(count, [], 'TODO: collect evidence and request Ollama interpretation')
    Path('report.json').write_text(json.dumps(report,indent=2,ensure_ascii=False),encoding='utf-8')
    print('anomaly=',detect_anomaly(count),' report.json generated')
