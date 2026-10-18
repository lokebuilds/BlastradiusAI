"""
BlastradiusAI - One-Click Launcher & FastAPI Server Entrypoint
Starts the backend and automatically opens the browser at http://127.0.0.1:8000/
"""

import socket
import threading
import time
import webbrowser
import uvicorn
from main import app

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
    threading.Thread(target=open_browser, daemon=True).start()
    uvicorn.run(app, host="127.0.0.1", port=8000, reload=False, log_level="info")


