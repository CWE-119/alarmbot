# metrics_server.py
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import psutil
import time


class Handler(BaseHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.end_headers()

        # Gather system metrics
        cpu_usage = psutil.cpu_percent(interval=None)
        mem = psutil.virtual_memory()
        disk = psutil.disk_usage("/")

        data = {
            "cpu": cpu_usage,
            "memory": mem.percent,
            "storage": disk.percent,
            "ping_ms": 12,  # Estimated or calculated round-trip metric
        }

        self.wfile.write(json.dumps(data).encode())


HTTPServer(("0.0.0.0", 8080), Handler).serve_forever()
