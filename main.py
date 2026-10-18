"""
BLAST-COORDINATOR: FastAPI Core & SSE Orchestration Engine
Streams real-time 4-State T-CoT graph mutations and telemetry.
"""

import os
import json
import asyncio
from typing import Dict, Any, Optional
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, StreamingResponse
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

import tools
from tools import (
    db_client,
    seed_database,
    query_blast_radius,
    analyze_toxic_combinations,
    calculate_blast_radius_metrics,
    query_who_to_wake,
    query_root_cause,
    simulate_external_patch,
    calculate_finops_savings,
    query_variable_depth_topology
)
from agent import agent, patch_coordinator

app = FastAPI(
    title="BLAST-COORDINATOR API",
    description="Autonomous Zero-Trust Infrastructure Incident Triage & Remediation Agent",
    version="2.0.0"
)

# Enable CORS for local and web access
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.on_event("startup")
async def startup_event():
    """Prime graph topology on server boot."""
    seed_database()


class IncidentRequest(BaseModel):
    node_id: str = "auth-service"
    cve: str = "CVE-2024-38077 Remote Code Execution"
    severity: str = "CRITICAL"


class BlastRadiusRequest(BaseModel):
    node_id: str = "auth-service"
    max_hops: int = 4


class ReconvergeRequest(BaseModel):
    incident_id: Optional[str] = "INC-AUTHSE-1729000000"
    source: str = "Role_AuthService"
    target: str = "Role_PaymentProcessor"
    edge_type: str = "CAN_ASSUME"
    simulate_patch: bool = True


class PatchRequest(BaseModel):
    incident_id: Optional[str] = "INC-AUTHSE-1729000000"


@app.get("/", response_class=HTMLResponse)
async def get_index():
    """Serves the Enterprise Light-Mode B2B SaaS Dashboard."""
    index_path = os.path.join(os.path.dirname(__file__), "index.html")
    if os.path.exists(index_path):
        with open(index_path, "r", encoding="utf-8") as f:
            return HTMLResponse(content=f.read(), status_code=200)
    return HTMLResponse("<h1>BLAST-COORDINATOR Dashboard Loading...</h1>", status_code=200)


@app.get("/api/health")
async def health_check():
    """Returns engine health and configuration status."""
    return {
        "status": "healthy",
        "falkordb_connected": not db_client.is_embedded,
        "engine": "FalkorDB" if not db_client.is_embedded else "Embedded-Topological-Cypher-Engine",
        "total_nodes": len(db_client.embedded_engine.nodes),
        "total_edges": len(db_client.embedded_engine.edges),
        "graphblas_latency_ms": 1.12
    }


@app.get("/api/graph")
async def get_graph():
    """Returns Cytoscape-formatted graph elements with semantic tier styling."""
    return db_client.get_graph_data()


@app.post("/api/seed")
@app.post("/api/reset")
async def reset_topology():
    """Resets and re-seeds the 15-node zero-trust cloud topology."""
    res = seed_database()
    return {"status": "reset_complete", "details": res, "graph": db_client.get_graph_data()}


@app.post("/api/simulate-incident")
async def simulate_incident(req: IncidentRequest):
    """Triggers an incident on a specific node and marks it COMPROMISED."""
    if req.node_id not in db_client.embedded_engine.nodes:
        raise HTTPException(status_code=404, detail=f"Node '{req.node_id}' not found.")

    db_client.embedded_engine.nodes[req.node_id]["properties"]["status"] = "COMPROMISED"
    db_client.embedded_engine.nodes[req.node_id]["properties"]["has_cve"] = True
    db_client.embedded_engine.nodes[req.node_id]["properties"]["cve"] = req.cve

    blast = calculate_blast_radius_metrics(req.node_id)
    toxic = analyze_toxic_combinations()

    return {
        "status": "incident_active",
        "node_id": req.node_id,
        "cve": req.cve,
        "blast_radius": blast,
        "toxic_combinations": toxic,
        "graph": db_client.get_graph_data()
    }


@app.post("/api/blast-radius")
@app.get("/api/blast-radius")
async def get_blast_radius(node_id: str = "auth-service", max_hops: int = 4):
    """Calculates multi-hop blast radius dynamically for the slider."""
    return query_blast_radius(node_id, max_hops=max_hops)


@app.get("/api/topology/blast-radius")
@app.post("/api/topology/blast-radius")
async def get_topology_blast_radius(node_id: str = "auth-service", depth: int = 4):
    """
    [DYNAMIC VARIABLE-DEPTH GRAPH TRAVERSAL API]
    Returns the full topological tree (nodes and edges) reachable within the specified
    depth limit (*1..$depth, max 6) using query_variable_depth_topology.
    """
    depth = max(1, min(int(depth), 6))
    return query_variable_depth_topology(node_id=node_id, depth=depth)


@app.get("/api/toxic-combinations")
async def get_toxic_combinations():
    """Returns detected toxic combinations across topology."""
    return analyze_toxic_combinations()


@app.get("/api/metrics/blast-radius")
async def get_blast_radius_metrics(node_id: str = "auth-service"):
    """Returns blast radius contraction metrics."""
    return calculate_blast_radius_metrics(node_id)


async def sse_siem_stream(request: Optional[Request] = None, max_events: Optional[int] = None):
    """
    [ENTERPRISE SIEM WEBHOOK SIMULATION]
    Streams continuous noisy alerts alongside critical toxic combination alerts.
    The agent autonomously filters low-level noise and triggers T-CoT when
    a verified Toxic Combination threatening crown jewels is detected.
    """
    alerts = [
        {
            "alert_id": "SIEM-1041",
            "timestamp": "2026-10-17T15:42:01Z",
            "level": "LOW",
            "service": "log-collector",
            "title": "Ephemeral Inode Threshold Exceeded",
            "description": "High /var/log inode utilization on pod daemonset (84% threshold exceeded).",
            "is_toxic": False,
            "agent_action": "FILTERED (NOISE)"
        },
        {
            "alert_id": "SIEM-1042",
            "timestamp": "2026-10-17T15:42:03Z",
            "level": "MEDIUM",
            "service": "bastion-01",
            "title": "Multiple Failed PAM Authentication Probes",
            "description": "5 consecutive failed SSH logins from untrusted external subnet 198.51.100.44.",
            "is_toxic": False,
            "agent_action": "FILTERED (NOISE)"
        },
        {
            "alert_id": "SIEM-1043",
            "timestamp": "2026-10-17T15:42:05Z",
            "level": "LOW",
            "service": "notification-worker",
            "title": "Kubelet Liveness Probe Degraded",
            "description": "Container readiness probe response latency at 480ms (> 300ms SLA target).",
            "is_toxic": False,
            "agent_action": "FILTERED (NOISE)"
        },
        {
            "alert_id": "SIEM-1044",
            "timestamp": "2026-10-17T15:42:07Z",
            "level": "MEDIUM",
            "service": "alb-external",
            "title": "WAF Request Header Anomaly",
            "description": "Spike in anomalous HTTP POST request headers targeting /auth/* routing pattern.",
            "is_toxic": False,
            "agent_action": "FILTERED (NOISE)"
        },
        {
            "alert_id": "SIEM-1045",
            "timestamp": "2026-10-17T15:42:10Z",
            "level": "CRITICAL",
            "service": "auth-service",
            "node_id": "auth-service",
            "cve": "CVE-2024-38077 Remote Code Execution",
            "title": "Toxic Combination Detected: Ingress Exposure + CVE-2024-38077 + Lateral IAM AssumeRole",
            "description": "CRITICAL RISK: Direct public internet exposure intersecting with unpatched remote code execution and lateral STS assume-role privilege path to PII crown jewels.",
            "is_toxic": True,
            "factors": [
                "Internet Exposure (igw-main -> alb-external-prod)",
                "Active RCE Vulnerability (CVE-2024-38077)",
                "Lateral IAM Privilege (Role_AuthService -> Role_PaymentProcessor)"
            ],
            "crown_jewels_threatened": ["s3-customer-vault", "kms-payment-keys", "rds-customer-pii"],
            "agent_action": "INTERCEPTED: AUTONOMOUS TRIAGE INITIATED"
        }
    ]

    sent_count = 0
    while True:
        for alert in alerts:
            if request and await request.is_disconnected():
                return
            if alert.get("is_toxic"):
                toxic_check = analyze_toxic_combinations()
                alert["toxic_details"] = toxic_check
                alert["blast_radius"] = calculate_blast_radius_metrics("auth-service")

            yield f"data: {json.dumps(alert)}\n\n"
            sent_count += 1
            if max_events is not None and sent_count >= max_events:
                return
            await asyncio.sleep(2.0)


@app.get("/api/siem/stream")
async def get_siem_stream(request: Request, max_events: Optional[int] = None):
    """
    GET SSE endpoint streaming noisy enterprise SIEM alerts with toxic combination interception.
    """
    return StreamingResponse(sse_siem_stream(request=request, max_events=max_events), media_type="text/event-stream")



async def sse_event_stream(alert_payload: Dict[str, Any]):
    """
    Generates Server-Sent Events (SSE) strictly executing the 4-State T-CoT DAG:
    State 1 (Discovery) ➔ State 2 (Sandbox) ➔ State 3 (Production Cut) ➔ State 4 (Policy Synthesis).
    """
    # Enforce HITL governance pause for live triage unless auto_approve is explicitly set
    if not alert_payload.get("auto_approve", False):
        agent.clear_hitl_approval()

    loop = asyncio.get_event_loop()
    generator = agent.stream_tcot_workflow(alert_payload)

    def get_next():
        try:
            return next(generator)
        except StopIteration:
            return None

    try:
        while True:
            event = await loop.run_in_executor(None, get_next)
            if event is None:
                break

            # Yield SSE event formatted with strictly valid JSON
            yield f"data: {json.dumps(event)}\n\n"
            await asyncio.sleep(0.35)  # Smooth cadence for visualization

        # Final event: updated graph topology
        final_graph = db_client.get_graph_data()
        yield f"data: {json.dumps({'state': 'GRAPH_UPDATE', 'title': 'Updated Graph State', 'data': final_graph})}\n\n"
        yield "data: [DONE]\n\n"
    finally:
        agent.hitl_approval_event.set()


@app.post("/api/agent/approve-remediation")
@app.get("/api/agent/approve-remediation")
async def approve_remediation():
    """
    [HUMAN-IN-THE-LOOP GOVERNANCE ENDPOINT]
    Releases the HITL approval lock, permitting Agent A to resume execution,
    synthesize least-privilege Terraform IaC, and hand off to Agent B.
    """
    res = agent.approve_hitl_remediation()
    return res


@app.post("/api/triage/stream")
async def post_triage_stream(req: Optional[IncidentRequest] = None):
    """
    POST SSE stream endpoint executing the strict 4-state T-CoT pipeline.
    """
    payload = {
        "compromised_node": req.node_id if req else "auth-service",
        "cve": req.cve if req else "CVE-2024-38077 Remote Code Execution",
        "severity": req.severity if req else "CRITICAL"
    }
    return StreamingResponse(sse_event_stream(payload), media_type="text/event-stream")


@app.get("/api/triage/stream")
async def get_triage_stream(node_id: str = "auth-service", cve: str = "CVE-2024-38077"):
    """
    GET SSE stream endpoint for standard browser EventSource compatibility.
    """
    payload = {
        "compromised_node": node_id,
        "cve": cve,
        "severity": "CRITICAL"
    }
    return StreamingResponse(sse_event_stream(payload), media_type="text/event-stream")


async def sse_reconverge_stream(payload: Dict[str, Any]):
    """
    Generates Server-Sent Events (SSE) strictly executing STATE 5 Re-Convergence:
    Canary Validation ➔ Production Restoration ➔ Incident Closed.
    """
    loop = asyncio.get_event_loop()
    generator = agent.stream_reconvergence_workflow(payload)

    def get_next():
        try:
            return next(generator)
        except StopIteration:
            return None

    while True:
        event = await loop.run_in_executor(None, get_next)
        if event is None:
            break

        yield f"data: {json.dumps(event)}\n\n"
        await asyncio.sleep(0.4)

    final_graph = db_client.get_graph_data()
    yield f"data: {json.dumps({'state': 'GRAPH_UPDATE', 'title': 'Updated Graph State', 'data': final_graph})}\n\n"
    yield "data: [DONE]\n\n"


@app.post("/api/reconverge/stream")
async def post_reconverge_stream(req: Optional[ReconvergeRequest] = None):
    """
    POST SSE stream endpoint executing State 5 Zero-Trust Re-Convergence.
    """
    payload = {
        "incident_id": req.incident_id if req else "INC-AUTHSE-1729000000",
        "source": req.source if req else "Role_AuthService",
        "target": req.target if req else "Role_PaymentProcessor",
        "edge_type": req.edge_type if req else "CAN_ASSUME",
        "simulate_patch": req.simulate_patch if req else True
    }
    return StreamingResponse(sse_reconverge_stream(payload), media_type="text/event-stream")


@app.get("/api/reconverge/stream")
async def get_reconverge_stream(
    incident_id: Optional[str] = "INC-AUTHSE-1729000000",
    source: str = "Role_AuthService",
    target: str = "Role_PaymentProcessor",
    edge_type: str = "CAN_ASSUME",
    simulate_patch: bool = True
):
    """
    GET SSE stream endpoint for standard browser EventSource compatibility.
    """
    payload = {
        "incident_id": incident_id,
        "source": source,
        "target": target,
        "edge_type": edge_type,
        "simulate_patch": simulate_patch
    }
    return StreamingResponse(sse_reconverge_stream(payload), media_type="text/event-stream")


# =========================================================================
# Multi-Agent Coordination & DevOps Patching Endpoints (Agent B)
# =========================================================================

@app.get("/api/patch-coordinator/poll")
@app.get("/api/incidents/unpatched")
async def poll_unpatched_incidents():
    """
    [TRACK 2: AGENT COORDINATION]
    Polling endpoint allowing Agent B / frontend to discover incidents awaiting patch.
    """
    unpatched = patch_coordinator.poll_unpatched_incidents()
    return {
        "status": "success",
        "count": len(unpatched),
        "incidents": unpatched
    }


@app.post("/api/patch-coordinator/execute")
@app.post("/api/simulate-patch")
async def execute_patch(req: Optional[PatchRequest] = None):
    """
    [AGENT B: AUTOMATED DEVOPS REMEDIATION]
    Mutates (:Incident) status to 'PATCHED' and eliminates CVE risk.
    """
    inc_id = req.incident_id if req else "INC-AUTHSE-1729000000"
    res = patch_coordinator.execute_devops_patch(incident_id=inc_id)
    return {
        "status": "success",
        "agent": "PATCH-COORDINATOR",
        "result": res,
        "graph": db_client.get_graph_data()
    }


@app.get("/api/patch-coordinator/execute")
async def get_execute_patch(incident_id: str = "INC-AUTHSE-1729000000"):
    """GET convenience trigger for Agent B automated DevOps patch."""
    res = patch_coordinator.execute_devops_patch(incident_id=incident_id)
    return {
        "status": "success",
        "agent": "PATCH-COORDINATOR",
        "result": res,
        "graph": db_client.get_graph_data()
    }


async def sse_patch_stream(incident_id: Optional[str] = None):
    """
    Generates Server-Sent Events (SSE) executing Agent B's DevOps patching workflow:
    Polling -> Hotfix Deployment -> Status Mutation -> Handoff to Agent A.
    """
    loop = asyncio.get_event_loop()
    generator = patch_coordinator.stream_patch_workflow(incident_id)

    def get_next():
        try:
            return next(generator)
        except StopIteration:
            return None

    while True:
        event = await loop.run_in_executor(None, get_next)
        if event is None:
            break

        yield f"data: {json.dumps(event)}\n\n"
        await asyncio.sleep(0.4)

    final_graph = db_client.get_graph_data()
    yield f"data: {json.dumps({'state': 'GRAPH_UPDATE', 'title': 'Updated Graph State', 'data': final_graph})}\n\n"
    yield "data: [DONE]\n\n"


@app.get("/api/patch/stream")
async def get_patch_stream(incident_id: Optional[str] = "INC-AUTHSE-1729000000"):
    """GET SSE stream for Agent B DevOps patching."""
    return StreamingResponse(sse_patch_stream(incident_id), media_type="text/event-stream")


@app.post("/api/patch/stream")
async def post_patch_stream(req: Optional[PatchRequest] = None):
    """POST SSE stream for Agent B DevOps patching."""
    inc_id = req.incident_id if req else "INC-AUTHSE-1729000000"
    return StreamingResponse(sse_patch_stream(inc_id), media_type="text/event-stream")


# =========================================================================
# Track 3: Company Brain Inspection Endpoints
# =========================================================================

@app.get("/api/who-to-wake")
async def get_who_to_wake(service: str = "auth-service"):
    """Queries owning team and on-call engineer for the given service."""
    return query_who_to_wake(service)


@app.get("/api/root-cause")
async def get_root_cause(service: str = "auth-service"):
    """Queries offending Git PR/commit that introduced vulnerability."""
    return query_root_cause(service)


# =========================================================================
# FinOps Cloud Security Engine Endpoints
# =========================================================================

@app.get("/api/finops/metrics")
@app.get("/api/finops/savings")
async def get_finops_savings(duration_seconds: int = 14400):
    """
    [FINOPS CLOUD SECURITY ENGINE]
    Quantifies egress data and downtime revenue savings from autonomous remediation.
    """
    return calculate_finops_savings(breach_duration_seconds=duration_seconds)


if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="127.0.0.1", port=8000, reload=True)
