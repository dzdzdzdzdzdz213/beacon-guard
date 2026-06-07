"""
BeaconGuard API Server

Provides REST + SSE endpoints for the eBPF behavioral guard.
Receives alerts from the Go loader, stores them, and streams to the dashboard.
"""

import asyncio
import json
import time
from collections import defaultdict
from datetime import datetime, timezone
from typing import Optional

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sse_starlette.sse import EventSourceResponse

app = FastAPI(
    title="BeaconGuard API",
    version="0.1.0",
    description="Behavioral Kernel Guard — real-time process anomaly detection",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# In-memory store
alerts: list[dict] = []
processes: dict[int, dict] = {}
config = {
    "learning_mode": True,
    "suspicion_threshold": 100,
    "auto_kill": False,
    "max_connections_per_min": 50,
}

# SSE subscribers
subscribers: list[asyncio.Queue] = []


# ─── Models ────────────────────────────────────────────────────────────────

class AlertIn(BaseModel):
    timestamp: str
    severity: str
    rule: str
    description: str
    pid: int
    comm: str = ""
    score: int = 0
    action: str = "alert"
    details: dict = {}


class ConfigUpdate(BaseModel):
    learning_mode: Optional[bool] = None
    suspicion_threshold: Optional[int] = None
    auto_kill: Optional[bool] = None
    max_connections_per_min: Optional[int] = None


# ─── Endpoints ─────────────────────────────────────────────────────────────

@app.get("/api/v1/health")
async def health():
    return {
        "status": "ok",
        "version": "0.1.0",
        "uptime": time.time() - start_time,
        "alerts_total": len(alerts),
        "processes_tracked": len(processes),
        "subscribers": len(subscribers),
    }


@app.get("/api/v1/stats")
async def stats():
    severity_counts = defaultdict(int)
    rule_counts = defaultdict(int)
    for a in alerts:
        severity_counts[a.get("severity", "unknown")] += 1
        rule_counts[a.get("rule", "unknown")] += 1

    process_summary = {
        "total": len(processes),
        "with_alerts": sum(1 for p in processes.values() if p.get("alert_count", 0) > 0),
    }

    return {
        "alerts": {
            "total": len(alerts),
            "by_severity": dict(severity_counts),
            "by_rule": dict(rule_counts),
            "last_hour": sum(
                1
                for a in alerts
                if datetime.fromisoformat(a["timestamp"]).timestamp()
                > time.time() - 3600
            ),
        },
        "processes": process_summary,
        "config": config,
    }


@app.get("/api/v1/alerts")
async def get_alerts(limit: int = 100, severity: Optional[str] = None):
    filtered = alerts
    if severity:
        filtered = [a for a in alerts if a.get("severity") == severity]
    return filtered[-limit:]


@app.post("/api/v1/alerts")
async def post_alert(alert: AlertIn):
    entry = alert.model_dump()
    entry["received_at"] = datetime.now(timezone.utc).isoformat()
    entry["id"] = len(alerts) + 1

    # Update process state
    pid = entry["pid"]
    if pid not in processes:
        processes[pid] = {
            "pid": pid,
            "comm": entry["comm"],
            "first_seen": entry["timestamp"],
            "alert_count": 0,
            "suspicion_score": 0,
            "state": "learning",
        }
    proc = processes[pid]
    proc["alert_count"] += 1
    proc["suspicion_score"] += entry.get("score", 0)
    proc["last_alert"] = entry["timestamp"]
    proc["comm"] = entry["comm"] or proc["comm"]

    if config["learning_mode"]:
        proc["state"] = "learning"
    elif proc["suspicion_score"] >= config["suspicion_threshold"]:
        proc["state"] = "anomalous"
    else:
        proc["state"] = "baseline"

    alerts.append(entry)
    if len(alerts) > 10000:
        alerts[:5000] = []

    # Broadcast to SSE subscribers
    payload = json.dumps(entry)
    dead: list[asyncio.Queue] = []
    for q in subscribers:
        try:
            q.put_nowait(payload)
        except asyncio.QueueFull:
            dead.append(q)
    for q in dead:
        subscribers.remove(q)

    return {"status": "received", "id": entry["id"]}


@app.get("/api/v1/alerts/stream")
async def alert_stream(request: Request):
    queue: asyncio.Queue = asyncio.Queue(maxsize=500)
    subscribers.append(queue)

    async def event_generator():
        try:
            while True:
                if await request.is_disconnected():
                    break
                try:
                    data = await asyncio.wait_for(queue.get(), timeout=30)
                    yield {"event": "alert", "data": data}
                except asyncio.TimeoutError:
                    yield {"event": "ping", "data": "keepalive"}
        finally:
            if queue in subscribers:
                subscribers.remove(queue)

    return EventSourceResponse(event_generator())


@app.get("/api/v1/processes")
async def get_processes(state: Optional[str] = None, limit: int = 100):
    items = list(processes.values())
    if state:
        items = [p for p in items if p.get("state") == state]
    items.sort(key=lambda p: p.get("suspicion_score", 0), reverse=True)
    return items[:limit]


@app.get("/api/v1/config")
async def get_config():
    return config


@app.post("/api/v1/config")
async def update_config(update: ConfigUpdate):
    for field, value in update.model_dump(exclude_none=True).items():
        config[field] = value
    return {"status": "updated", "config": config}


@app.get("/api/v1/alerts/timeline")
async def alert_timeline(window_min: int = 60):
    """Return alert counts per minute for the timeline chart."""
    now = time.time()
    window_sec = window_min * 60
    buckets: dict[int, int] = {}

    for a in alerts:
        ts = datetime.fromisoformat(a["timestamp"]).timestamp()
        if now - ts > window_sec:
            continue
        minute_bucket = int(ts / 60)
        buckets[minute_bucket] = buckets.get(minute_bucket, 0) + 1

    return [
        {"time": bucket * 60, "count": count}
        for bucket, count in sorted(buckets.items())
    ]


start_time = time.time()


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=9091)
