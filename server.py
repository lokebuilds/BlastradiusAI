"""
BlastradiusAI - One-Click Launcher & FastAPI Server Entrypoint
Starts the backend and automatically opens the browser at http://127.0.0.1:8000/
Supports FalkorDB Cloud (FALKORDB_HOST, FALKORDB_PORT, FALKORDB_PASSWORD) with resilient local fallbacks.
"""

import os
import socket
import threading
import time
import webbrowser
import uvicorn
from main import app

def report_falkordb_configuration():
    """Validates and logs FalkorDB Cloud / Local connection parameters."""
    host = os.getenv("FALKORDB_HOST", "localhost")
    port = int(os.getenv("FALKORDB_PORT", "6379"))
    graph = os.getenv("FALKORDB_GRAPH", "cloud_infra")
    has_pwd = bool(os.getenv("FALKORDB_PASSWORD"))
    is_cloud = host not in ("localhost", "127.0.0.1", "::1")
    
    if is_cloud:
        print(f"[i] FalkorDB Cloud Target: {host}:{port} [Graph: {graph}, Auth: {'Configured' if has_pwd else 'None'}]")
    else:
        print(f"[i] FalkorDB Local Target: {host}:{port} [Graph: {graph}, Fallback: In-Memory GraphBLAS Engine]")

def open_browser(host: str = "127.0.0.1", port: int = 8000):
    """Wait until server actively accepts TCP connections before launching default browser."""
    start_time = time.time()
    while time.time() - start_time < 10.0:
        try:
            with socket.create_connection((host, port), timeout=0.05):
                break
        except (socket.timeout, ConnectionRefusedError, OSError):
            time.sleep(0.02)

    print(f"\n[+] Opening BLAST-COORDINATOR in your browser: http://{host}:{port}/\n")
    webbrowser.open(f"http://{host}:{port}/")

if __name__ == "__main__":
    report_falkordb_configuration()
    threading.Thread(target=open_browser, daemon=True).start()
    uvicorn.run(app, host="127.0.0.1", port=8000, reload=False, log_level="info")



