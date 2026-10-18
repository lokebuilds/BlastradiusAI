import sys
import json

# Ensure Windows terminal can print unicode emojis like 🛡️
if sys.platform == "win32":
    sys.stdout.reconfigure(encoding="utf-8")

from seed_graph import seed_database
from agent import agent

# Prime graph topology first
seed_database()

alert = {
    "compromised_node": "auth-service",
    "cve": "CVE-2024-38077 Remote Code Execution",
    "symptom": "Anomalous process execution / remote command invocation"
}

def log_cb(event):
    step = event["step"]
    title = event["title"]
    print(f">>> [{step}] {title}")

res = agent.run_triage(alert, step_callback=log_cb)

print("\n" + "="*50)
print("FINAL REPORT:")
print("="*50)
print(res["report_markdown"])
print("\n" + "="*50)
print("STAGE 5 INVARIANT PROOF:")
print(json.dumps(res.get("stage_5_invariant_proof", {}), indent=2))
