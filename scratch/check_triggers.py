with open("index.html", "r", encoding="utf-8") as f:
    lines = f.readlines()

keywords = [
    "simulateBreach", "startAutonomousTriage", "/api/simulate-incident",
    "/api/triage/stream", "/api/reconverge/stream", "triggerAgentBPatch",
    "startCanaryReconvergence", "initSiemStreamListener"
]

for idx, line in enumerate(lines, 1):
    for kw in keywords:
        if kw in line:
            print(f"{idx}: {line.strip()[:100]}")
