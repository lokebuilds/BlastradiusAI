import sys

with open("index.html", "r", encoding="utf-8") as f:
    lines = f.readlines()

patterns = [
    "btn-guardrail-test", "guardrail", "btn-simulate", "btn-reset",
    "resetTopology", "resetStepperUI", "prepareGraphElements",
    "view-cypher", "cypher-results", "algo.SPpaths", "algo.pageRank",
    "view-slider", "REACHABLE DOWNSTREAM", "updateBlastRadiusUI",
    "Finding_", "INC-", "team-identity", "card-escalation", "toast",
    "guardrail-verifier-modal", "saas-tab", "nav-actions", "falkordb-telemetry-ribbon",
    "simulateBreach", "executeManualCypher", "setConsoleQuery",
    "hud-blast-metric", "hud-cost-saved", "executive-footer"
]

out = []
for idx, line in enumerate(lines, 1):
    for p in patterns:
        if p.lower() in line.lower():
            clean = line.strip().encode('ascii', 'replace').decode('ascii')[:100]
            out.append(f"{idx}: [{p}] {clean}")

with open("scratch/sections_found.txt", "w", encoding="utf-8") as f:
    f.write("\n".join(out))
print(f"Done, found {len(out)} matches")
