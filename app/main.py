import os, time, logging
from fastapi import FastAPI, HTTPException
from prometheus_client import Counter, Histogram, generate_latest, CONTENT_TYPE_LATEST
from fastapi.responses import Response

app=FastAPI(title="TECHCORP Orders API")
REQUESTS=Counter("techcorp_http_requests_total", "Requests", ["path", "status"])
LATENCY=Histogram("techcorp_request_duration_seconds", "Latency", ["path"])
logger=logging.getLogger("uvicorn.error")

@app.get("/health")
def health():
    REQUESTS.labels("/health", "200").inc()
    return {"status":"ok"}

@app.get("/orders")
def orders():
    start=time.monotonic()
    try:
        if os.getenv("SIMULATE_FAILURE", "false").lower()=="true":
            REQUESTS.labels("/orders", "500").inc()
            logger.error("order_processing_failed db_connection_timeout event=INC-2026-1042")
            raise HTTPException(status_code=500, detail="Order processing unavailable")
        REQUESTS.labels("/orders", "200").inc()
        return {"orders":[],"status":"ready"}
    finally:
        LATENCY.labels("/orders").observe(time.monotonic()-start)

@app.get("/metrics")
def metrics():
    return Response(generate_latest(), media_type=CONTENT_TYPE_LATEST)
