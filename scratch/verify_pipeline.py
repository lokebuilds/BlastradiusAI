import json
import sys
import os

# Add workspace root to sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

# Windows UTF-8 console output
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8", line_buffering=True)

import tools
from tools import db_client, seed_database, query_shortest_attack_vector, simulate_sandbox_cut, execute_production_cut, verify_invariant, synthesize_iac_policy
from agent import agent

print("1. Testing seed_database...")
seed_res = seed_database()
print("   Seed status:", seed_res["status"], f"Nodes: {seed_res['nodes']}, Edges: {seed_res['edges']}")

print("2. Testing State 1: Discovery...")
disc = query_shortest_attack_vector("auth-service", "s3-customer-vault")
print("   Shortest path:", disc["shortest_path"])
print("   Toxic bridge:", disc["toxic_bridge"])
assert disc["has_path"] == True, "Failed: Should find path to s3-customer-vault"

print("3. Testing State 2: Simulation...")
sim = simulate_sandbox_cut("Role_AuthService", "Role_PaymentProcessor", "CAN_ASSUME")
print("   Ingress preserved:", sim["ingress_preserved"], "Downtime:", sim["collateral_downtime"])
assert sim["ingress_preserved"] == True, "Failed: Ingress must be preserved"

print("4. Testing State 3: Execution & Verification...")
cut = execute_production_cut("Role_AuthService", "Role_PaymentProcessor", "CAN_ASSUME")
print("   Production cut:", cut["status"], cut["severed_edge"])
inv = verify_invariant("auth-service", "s3-customer-vault")
print("   Invariant satisfied:", inv["invariant_satisfied"], inv["assertion"])
assert inv["invariant_satisfied"] == True, "Failed: Invariant remaining_paths == 0 must be satisfied"

print("5. Testing State 4: Policy Synthesis...")
pol = synthesize_iac_policy("Role_AuthService")
print("   Policy string:\n", pol["policy_str"])
assert "Allow" not in pol["policy_str"], "Violation: Allow statement should be omitted when allowed targets is empty!"
assert "Deny" in pol["policy_str"], "Violation: Deny statement must be present for severed target!"
print("   Assertion PASSED: 'Allow' statement is omitted, 'Deny' is enforced.")

print("6. Testing Agent Stream Generator...")
seed_database()  # Reset for stream run
alert = {"compromised_node": "auth-service", "cve": "CVE-2024-38077 Remote Code Execution", "target_node": "s3-customer-vault"}
events = list(agent.stream_tcot_workflow(alert))
print(f"   Agent stream yielded {len(events)} events across all DAG states.")
for ev in events:
    print(f"   [{ev.get('state')}] {ev.get('title')} ({ev.get('status')})")

print("7. Testing State 5: Canary Validation...")
from tools import simulate_canary_validation, execute_production_restoration

canary_vuln = simulate_canary_validation("INC-TEST", "Role_AuthService", "Role_PaymentProcessor", "CAN_ASSUME", simulate_patch=False)
print("   Unpatched Canary:", canary_vuln["status"], canary_vuln["verdict"])
assert canary_vuln["verdict"] == "VULNERABLE", "Unpatched canary must fail with VULNERABLE"

canary_safe = simulate_canary_validation("INC-TEST", "Role_AuthService", "Role_PaymentProcessor", "CAN_ASSUME", simulate_patch=True)
print("   Patched Canary:", canary_safe["status"], canary_safe["verdict"])
assert canary_safe["verdict"] == "PATCH_VERIFIED", "Patched canary must succeed with PATCH_VERIFIED"

print("8. Testing State 5: Production Restoration...")
rest_res = execute_production_restoration("Role_AuthService", "Role_PaymentProcessor", "CAN_ASSUME", "INC-TEST")
print("   Restoration:", rest_res["status"], rest_res["restored_edge"], rest_res["incident_status"])
assert rest_res["incident_status"] == "PERMANENTLY_RESOLVED"
assert rest_res["edge_status"] == "ACTIVE"

print("9. Testing Agent Reconvergence Stream...")
reconverge_events = list(agent.stream_reconvergence_workflow({
    "incident_id": "INC-TEST",
    "source": "Role_AuthService",
    "target": "Role_PaymentProcessor",
    "edge_type": "CAN_ASSUME",
    "simulate_patch": True
}))
print(f"   Agent reconvergence stream yielded {len(reconverge_events)} events.")
for ev in reconverge_events:
    print(f"   [{ev.get('state')}] [{ev.get('stage')}] {ev.get('title')} -> {ev.get('status')}")

assert any(ev.get("stage") == "CANARY_VERIFIED" for ev in reconverge_events), "Must yield CANARY_VERIFIED"

print("10. Testing FastAPI /api/reconverge/stream Endpoint...")
from fastapi.testclient import TestClient
from main import app
client = TestClient(app)

res = client.get("/api/reconverge/stream?source=Role_AuthService&target=Role_PaymentProcessor")
assert res.status_code == 200
assert "STATE_5_RECONVERGENCE_TEST" in res.text
assert "CANARY_VERIFIED" in res.text
print("   FastAPI /api/reconverge/stream GET status:", res.status_code, "Verified SSE payload.")

post_res = client.post("/api/reconverge/stream", json={"source": "Role_AuthService", "target": "Role_PaymentProcessor"})
assert post_res.status_code == 200
assert "CANARY_VERIFIED" in post_res.text
print("   FastAPI /api/reconverge/stream POST status:", post_res.status_code, "Verified SSE payload.")

print("11. Testing Toxic Combination Engine...")
from tools import analyze_toxic_combinations, calculate_blast_radius_metrics

seed_database() # reset
# auth-service already has has_cve: True, is_publicly_exposed: True, has_elevated_iam_path: True

toxic_res = analyze_toxic_combinations()
toxic_nodes = toxic_res["nodes"]
print(f"   Found {len(toxic_nodes)} Toxic Combination node(s): {[n['node_id'] for n in toxic_nodes]}")
assert len(toxic_nodes) >= 1, "Must find at least one toxic combination node"
auth_toxic = next(n for n in toxic_nodes if n["node_id"] == "auth-service")
assert auth_toxic["is_publicly_exposed"] == True
assert auth_toxic["has_cve"] == True
assert auth_toxic["has_elevated_iam_path"] == True
print("   Assertion PASSED: auth-service has 3-way intersection (Ingress + CVE + IAM).")

print("12. Testing Blast Radius Metrics (Uncontained vs Contained)...")
blast_uncontained = calculate_blast_radius_metrics("auth-service")
print("   Uncontained Blast Radius:", blast_uncontained["total_assets_exposed"], "assets exposed.")
assert blast_uncontained["total_assets_exposed"] == 14, f"Expected 14 exposed assets, got {blast_uncontained['total_assets_exposed']}"
assert blast_uncontained["is_contained"] == False
assert "s3-customer-vault" in blast_uncontained["critical_assets"]

# Sever toxic bridge
execute_production_cut("Role_AuthService", "Role_PaymentProcessor", "CAN_ASSUME")
blast_contained = calculate_blast_radius_metrics("auth-service")
print("   Contained Blast Radius:", blast_contained["total_assets_exposed"], "assets exposed.")
assert blast_contained["total_assets_exposed"] == 0, f"Expected 0 exposed assets, got {blast_contained['total_assets_exposed']}"
assert blast_contained["is_contained"] == True
print("   Assertion PASSED: Blast Radius contracts from 14 -> 0 upon bridge severance.")


print("13. Testing Agent SIEM Alert Filtering...")
noisy_alert = {
    "alert_id": "SIEM-1041",
    "rule": "Low Disk Space (/var/log > 85%)",
    "level": "LOW",
    "service": "marketing-portal"
}
eval_noisy = agent.evaluate_siem_alert(noisy_alert)
print("   Noisy alert evaluation:", eval_noisy["action"], "should_triage:", eval_noisy["should_triage"])
assert eval_noisy["should_triage"] == False, "Agent must filter out low-severity alerts"
assert eval_noisy["action"] == "IGNORED"

toxic_alert = {
    "alert_id": "SIEM-1045",
    "rule": "CRITICAL: Toxic Combination Detected - CVE + Ingress + Privileged IAM",
    "level": "CRITICAL",
    "is_toxic": True,
    "node_id": "auth-service",
    "target_node": "s3-customer-vault"
}
eval_toxic = agent.evaluate_siem_alert(toxic_alert)
print("   Toxic alert evaluation:", eval_toxic["action"], "should_triage:", eval_toxic["should_triage"])
assert eval_toxic["should_triage"] == True, "Agent must trigger triage for toxic combinations"
assert eval_toxic["action"] == "INTERCEPTED"
print("   Assertion PASSED: Agent filters noise and triggers on Toxic Combination.")


print("14. Testing FastAPI Toxic and SIEM Endpoints...")
res_toxic = client.get("/api/toxic-combinations")
assert res_toxic.status_code == 200
toxic_data = res_toxic.json()
print(f"   /api/toxic-combinations count: {toxic_data['toxic_combinations_found']}")
assert toxic_data["toxic_combinations_found"] >= 1

res_metrics = client.get("/api/metrics/blast-radius?node_id=auth-service")
assert res_metrics.status_code == 200
metrics_data = res_metrics.json()
print(f"   /api/metrics/blast-radius: {metrics_data['total_assets_exposed']} assets exposed.")

# Test SIEM stream response
with client.stream("GET", "/api/siem/stream?max_events=1") as siem_stream:
    assert siem_stream.status_code == 200
    found_data = False
    for line in siem_stream.iter_lines():
        if line and line.strip().startswith("data:"):
            print("   /api/siem/stream event line:", line[:70], "...")
            found_data = True
            break
    assert found_data, "Must receive at least one data event from /api/siem/stream"


print("\n========================================================")
print("ALL 14 TOXIC COMBINATION & BLAST RADIUS TESTS PASSED!")
print("========================================================")

print("\n15. Testing Entity Resolution (resolve_service)...")
from tools import resolve_service, calculate_load_bearing_nodes, calculate_criticality_score, log_incident
from agent import accepts

res_valid = resolve_service("auth-service")
print("   resolve_service('auth-service'):", res_valid)
assert res_valid is True, f"Expected True for auth-service, got {res_valid}"

res_invalid = resolve_service("unknown-phantom-service")
print("   resolve_service('unknown-phantom-service'):", res_invalid)
assert res_invalid == "Unknown service", f"Expected 'Unknown service', got {res_invalid}"
print("   Assertion PASSED: resolve_service correctly identifies valid and unknown services.")

print("\n16. Testing PageRank & Criticality Calculation...")
ranked_services = calculate_load_bearing_nodes(limit=5)
print("   Top Load-Bearing Services (PageRank):", [(r["service"], r["score"]) for r in ranked_services])
assert len(ranked_services) >= 1
assert any(r["service"] == "auth-service" for r in ranked_services)

crit_score = calculate_criticality_score("auth-service")
print("   Criticality Score for auth-service:", crit_score)
assert 0.0 <= crit_score <= 1.0
print("   Assertion PASSED: PageRank calculates load-bearing services and criticality score.")

print("\n17. Testing Incident Memory Schema...")
mem_res = log_incident(
    text="Test Finding: Zero-Trust edge severed",
    at="2026-10-17T16:00:00Z",
    session="sess-scoring-test",
    node_id="auth-service"
)
print("   Memory Query:", mem_res["query"])
expected_query = "CREATE (f:Finding {text: $text, at: $at, session: $session})-[:ABOUT]->(s:Service {name: $node_id})"
assert mem_res["query"] == expected_query, f"Schema mismatch: expected {expected_query}, got {mem_res['query']}"
print("   Assertion PASSED: Memory schema matches exact Cypher specification.")

print("\n18. Testing Hallucination Guardrail (accepts function)...")
ground_truth = "auth-service Role_AuthService Role_PaymentProcessor s3-customer-vault"
valid_llm_sentence = "The incident at auth-service was contained before reaching s3-customer-vault."
hallucinated_sentence = "The attacker laterally pivoted from auth-service to crypto-mining-service."

assert accepts(valid_llm_sentence, ground_truth) is True, "Valid grounded services must be accepted"
assert accepts(hallucinated_sentence, ground_truth) is False, "Hallucinated unverified services must be rejected"
print("   Assertion PASSED: accepts() correctly accepts grounded sentences and rejects hallucinations.")

print("\n19. Testing Empty Traversal Distinction...")
# notification-worker does not connect to s3-customer-vault
empty_disc = query_shortest_attack_vector("notification-worker", "s3-customer-vault")
print("   Empty path message:", empty_disc["message"])
expected_empty_msg = "Nothing in the graph connects to this service, which may mean the dependency is not modelled"
assert empty_disc["message"] == expected_empty_msg, f"Expected '{expected_empty_msg}', got '{empty_disc['message']}'"
assert empty_disc["has_path"] is False
print("   Assertion PASSED: Empty traversal explicitly distinguishes unmodelled dependencies.")

print("\n========================================================")
print("ALL 19 TESTS PASSED: HACKATHON SCORING CRITERIA FULLY VERIFIED!")
print("========================================================")

print("\n20. Testing Track 3 Company Brain: query_who_to_wake...")
from tools import query_who_to_wake, query_root_cause, simulate_external_patch
from agent import patch_coordinator

who_auth = query_who_to_wake("auth-service")
print("   who_to_wake('auth-service'):", who_auth.get("person_handle"), who_auth.get("team_name"), who_auth.get("paging_alert"))
assert who_auth["found"] is True
assert who_auth["person_handle"] == "@Sarah_Connor"
assert who_auth["team_name"] == "Identity Team"
assert "Paging @Sarah_Connor (Identity Team)" in who_auth["paging_alert"]
print("   Assertion PASSED: Service correctly resolves owning team and on-call engineer via (:Person)-[:ONCALL_FOR]->(:Team)-[:OWNS]->(:Service).")

print("\n21. Testing Track 3 Company Brain: query_root_cause...")
root_auth = query_root_cause("auth-service")
print("   query_root_cause('auth-service'): SHA:", root_auth.get("sha"), "Author:", root_auth.get("author"), "PR:", root_auth.get("pr"))
assert root_auth["found"] is True
assert root_auth["sha"] == "c8f93a1b"
assert root_auth["author"] == "alex.dev@corp.internal"
assert root_auth["pr"] == "#1042"
print("   Assertion PASSED: Service correctly resolves recent bad deployment via (:Change)-[:TOUCHED]->(:Service).")

print("\n22. Testing Track 2 Agent Memory: Incident AWAITING_PATCH & simulate_external_patch...")
seed_database()
cut_res = execute_production_cut("Role_AuthService", "Role_PaymentProcessor", "CAN_ASSUME")
inc_id = cut_res["incident_node_id"]
assert cut_res["incident_status"] == "AWAITING_PATCH"
patch_res = simulate_external_patch(inc_id)
print("   simulate_external_patch status:", patch_res["status"], "Incident:", patch_res["incident_id"])
assert patch_res["status"] == "PATCHED"
print("   Assertion PASSED: Incident initialized as AWAITING_PATCH and successfully transitioned to PATCHED.")

print("\n23. Testing Track 2 Multi-Agent Handoff Event...")
seed_database()
events = list(agent.stream_tcot_workflow({"compromised_node": "auth-service", "cve": "CVE-2024-38077"}))
handoff_ev = next((ev for ev in events if ev.get("state") == "STATE_HANDOFF"), None)
assert handoff_ev is not None, "Agent A must yield STATE_HANDOFF after State 4"
assert handoff_ev.get("agent") == "BLAST-COORDINATOR"
assert handoff_ev.get("next_agent") == "PATCH-COORDINATOR"
assert handoff_ev.get("status") == "AWAITING_PATCH"
assert "root_cause" in handoff_ev
assert "paging" in handoff_ev
print(f"   Handoff Event: {handoff_ev.get('agent')} -> {handoff_ev.get('next_agent')} ({handoff_ev.get('status')})")
print("   Assertion PASSED: Agent A successfully pauses and yields handoff event with metadata to Agent B.")

print("\n24. Testing Agent B PatchCoordinator & FastAPI Endpoints...")
unpatched = patch_coordinator.poll_unpatched_incidents()
print(f"   PatchCoordinator discovered {len(unpatched)} unpatched incident(s)")
assert len(unpatched) >= 1
b_patch = patch_coordinator.execute_devops_patch()
assert b_patch["status"] == "PATCHED"

res_who = client.get("/api/who-to-wake?service=auth-service")
assert res_who.status_code == 200
assert res_who.json()["person_handle"] == "@Sarah_Connor"

res_root = client.get("/api/root-cause?service=auth-service")
assert res_root.status_code == 200
assert res_root.json()["sha"] == "c8f93a1b"

res_patch = client.post("/api/patch-coordinator/execute", json={"incident_id": inc_id})
assert res_patch.status_code == 200
assert res_patch.json()["agent"] == "PATCH-COORDINATOR"
assert res_patch.json()["result"]["status"] == "PATCHED"
print("   FastAPI endpoints /api/who-to-wake, /api/root-cause, and /api/patch-coordinator/execute verified.")

print("\n25. Testing FinOps Cloud Security Engine (calculate_finops_savings & API endpoints)...")
from tools import calculate_finops_savings

finops_calc = calculate_finops_savings(breach_duration_seconds=14400)
print("   calculate_finops_savings(14400):", finops_calc)
assert finops_calc["egress_saved_usd"] == 9720.0, f"Expected 9720.0, got {finops_calc['egress_saved_usd']}"
assert finops_calc["downtime_revenue_saved_usd"] == 562500.0, f"Expected 562500.0, got {finops_calc['downtime_revenue_saved_usd']}"
assert finops_calc["total_finops_savings_usd"] == 572220.0, f"Expected 572220.0, got {finops_calc['total_finops_savings_usd']}"
assert finops_calc["formatted_total"] == "$572,220.00"
assert finops_calc["prevented_exfiltration_gb"] == 72000.0

# Verify State 3 and State 4 event yields from agent workflow
st3 = next((e for e in events if e.get("state") == "STATE_3_EXECUTION_AND_VERIFICATION" and e.get("status") == "COMPLETED"), None)
assert st3 is not None
assert "finops" in st3
assert st3["total_finops_savings_usd"] == 572220.0
assert st3["egress_saved_usd"] == 9720.0
assert st3["downtime_revenue_saved_usd"] == 562500.0
print("   State 3 FinOps Payload Verified: Total =", st3["total_finops_savings_usd"])

st4 = next((e for e in events if e.get("state") == "STATE_4_POLICY_SYNTHESIS" and e.get("status") == "COMPLETED"), None)
assert st4 is not None
assert "finops" in st4
assert "💰 FINOPS IMPACT ANALYSIS" in st4["final_report"]
assert "$572,220.00" in st4["final_report"]
print("   State 4 FinOps Markdown Report Verified: Section '💰 FINOPS IMPACT ANALYSIS' present.")

# Verify FastAPI FinOps Endpoint
res_finops = client.get("/api/finops/metrics?duration_seconds=14400")
assert res_finops.status_code == 200
finops_resp = res_finops.json()
assert finops_resp["total_finops_savings_usd"] == 572220.0
assert finops_resp["egress_saved_usd"] == 9720.0
assert finops_resp["downtime_revenue_saved_usd"] == 562500.0

res_finops_savings = client.get("/api/finops/savings")
assert res_finops_savings.status_code == 200
assert res_finops_savings.json()["total_finops_savings_usd"] == 572220.0
print("   FastAPI endpoints /api/finops/metrics and /api/finops/savings verified successfully.")

print("\n========================================================")
print("ALL 25 TESTS PASSED: FINOPS CLOUD SECURITY ENGINE VERIFIED!")
print("========================================================")

print("\n26. Testing Variable-Depth Cypher Traversal (query_variable_depth_topology)...")
from tools import query_variable_depth_topology, synthesize_terraform_remediation

vdepth_res = query_variable_depth_topology("auth-service", depth=4)
print(f"   query_variable_depth_topology status: {vdepth_res['status']}, Engine: {vdepth_res['engine']}")
print(f"   Cypher Query: {vdepth_res['cypher_query']}")
expected_cypher = "MATCH path = (upstream)-[*1..$depth]->(s {id: $node_id}) RETURN DISTINCT upstream.id AS service, length(path) AS hops, [n IN nodes(path) | n.id] AS via ORDER BY hops"
assert vdepth_res["cypher_query"] == expected_cypher, f"Query mismatch: expected '{expected_cypher}', got '{vdepth_res['cypher_query']}'"
assert len(vdepth_res["records"]) >= 1, "Must return distinct upstream traversal records"
assert "elements" in vdepth_res and len(vdepth_res["elements"]) > 0, "Must return Cytoscape elements"
assert "nodes" in vdepth_res and len(vdepth_res["nodes"]) > 0, "Must return Cytoscape nodes"
assert "edges" in vdepth_res and len(vdepth_res["edges"]) > 0, "Must return Cytoscape edges"

# Verify hops ordering (ORDER BY hops)
hops_list = [r["hops"] for r in vdepth_res["records"]]
assert hops_list == sorted(hops_list), f"Records must be ordered by hops ascending: {hops_list}"
print(f"   Found {len(vdepth_res['records'])} upstream records ordered by hops: {[(r['service'], r['hops']) for r in vdepth_res['records']]}")
print(f"   Topological sub-graph closure has {len(vdepth_res['nodes'])} nodes and {len(vdepth_res['edges'])} edges.")
print("   Assertion PASSED: query_variable_depth_topology executes parameterized statement with fallback.")

print("\n27. Testing FastAPI Dynamic Topology Endpoint (GET /api/topology/blast-radius)...")
res_topo_default = client.get("/api/topology/blast-radius")
assert res_topo_default.status_code == 200
data_default = res_topo_default.json()
assert data_default["depth"] == 4
assert data_default["node_id"] == "auth-service"
assert data_default["cypher_query"] == expected_cypher
assert len(data_default["elements"]) > 0

res_topo_d2 = client.get("/api/topology/blast-radius?node_id=auth-service&depth=2")
assert res_topo_d2.status_code == 200
data_d2 = res_topo_d2.json()
assert data_d2["depth"] == 2
assert len(data_d2["nodes"]) <= len(data_default["nodes"])
print(f"   /api/topology/blast-radius depth=2 returned {len(data_d2['nodes'])} nodes, {len(data_d2['edges'])} edges.")

# Test max depth clamping at 6
res_topo_clamped = client.get("/api/topology/blast-radius?node_id=auth-service&depth=10")
assert res_topo_clamped.status_code == 200
assert res_topo_clamped.json()["depth"] == 6
print("   FastAPI /api/topology/blast-radius verified with parameter depth and max=6 clamping.")

print("\n28. Testing Terraform IaC Synthesis (remediation.tf)...")
pol_tf = synthesize_iac_policy("Role_AuthService")
assert "terraform_hcl" in pol_tf
assert "remediation.tf" in pol_tf["terraform_hcl"]
assert 'resource "aws_iam_role_policy" "remediation_deny_toxic_bridge"' in pol_tf["terraform_hcl"]
assert 'role = "Role_AuthService"' in pol_tf["terraform_hcl"]
assert '"Deny"' in pol_tf["terraform_hcl"] or 'Effect   = "Deny"' in pol_tf["terraform_hcl"]
print("   Terraform HCL snippet:\n" + "\n".join(pol_tf["terraform_hcl"].splitlines()[:10]))
print("   Assertion PASSED: Synthesizes fully-formed remediation.tf using aws_iam_role_policy.")

print("\n29. Testing MITRE ATT&CK Mapping in State 1...")
from tools import get_mitre_mapping
mitre = get_mitre_mapping("CVE-2024-38077")
assert mitre["mitre_tactic"] == "TA0004 Privilege Escalation"
assert mitre["mitre_technique"] == "T1078 Valid Accounts"
print(f"   MITRE mapping: {mitre['mitre_tactic']} -> {mitre['mitre_technique']}")

seed_database()
agent.hitl_approval_event.set()
events = list(agent.stream_tcot_workflow({"compromised_node": "auth-service", "cve": "CVE-2024-38077"}))
s1_comp = next((e for e in events if e.get("state") == "STATE_1_DISCOVERY" and e.get("status") == "COMPLETED"), None)
assert s1_comp is not None
assert s1_comp.get("mitre_tactic") == "TA0004 Privilege Escalation"
assert s1_comp.get("mitre_technique") == "T1078 Valid Accounts"
print(f"   State 1 enriched with MITRE mapping: {s1_comp.get('mitre_tactic')} | {s1_comp.get('mitre_technique')}")
print("   Assertion PASSED: MITRE ATT&CK technique correctly mapped and enriched in State 1 payload.")

print("\n30. Testing Human-in-the-Loop (HITL) Governance & Approval Endpoint...")
# Check HITL event yielded in workflow
hitl_ev = next((e for e in events if e.get("state") == "HITL_APPROVAL_WAITING"), None)
assert hitl_ev is not None, "Workflow must yield HITL_APPROVAL_WAITING between State 3 and State 4"
assert hitl_ev.get("message") == "Awaiting manual authorization from On-Call Engineer."
assert hitl_ev.get("operator") == "Alex Mercer"
print(f"   HITL Event: state={hitl_ev.get('state')} message='{hitl_ev.get('message')}' operator='{hitl_ev.get('operator')}'")

# Test FastAPI approval endpoint
approve_res = client.post("/api/agent/approve-remediation")
assert approve_res.status_code == 200
approve_data = approve_res.json()
assert approve_data["status"] == "APPROVED"
assert approve_data["authorized_by"] == "Alex Mercer"
print(f"   POST /api/agent/approve-remediation returned: {approve_data}")
assert agent.hitl_approval_event.is_set(), "Lock must be released after approval call"
print("   Assertion PASSED: HITL Governance pause yielded and /api/agent/approve-remediation unblocks Agent A.")

print("\n========================================================")
print("ALL 30 TESTS PASSED: MITRE ATT&CK MAPPING & HITL GOVERNANCE FULLY VERIFIED!")
print("========================================================")







