"""Serve the read-only Traffic Explorer on a private loopback URL."""

import json
import secrets
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path


class LiveDashboard:
    def __init__(self):
        self.payload = b"{}"
        web = Path(__file__).resolve().parent.parent / "web"
        assets = {
            "": ("text/html; charset=utf-8", (web / "index.html").read_bytes()),
            "index.html": ("text/html; charset=utf-8", (web / "index.html").read_bytes()),
            "http-history.html": ("text/html; charset=utf-8", (web / "http-history.html").read_bytes()),
            "http-history.js": ("text/javascript; charset=utf-8", (web / "http-history.js").read_bytes()),
            "dashboard.js": ("text/javascript; charset=utf-8", (web / "dashboard.js").read_bytes()),
            "styles.css": ("text/css; charset=utf-8", (web / "styles.css").read_bytes()),
        }
        prefix = "/" + secrets.token_urlsafe(24) + "/"

        class Handler(BaseHTTPRequestHandler):
            def do_GET(handler):
                if handler.headers.get("Host") != host or not handler.path.startswith(prefix):
                    handler.send_error(404)
                    return
                path = handler.path[len(prefix):]
                if path == "live.json":
                    content_type, body = "application/json", self.payload
                elif path in assets:
                    content_type, body = assets[path]
                else:
                    handler.send_error(404)
                    return
                handler.send_response(200)
                handler.send_header("Content-Type", content_type)
                handler.send_header("Content-Length", str(len(body)))
                handler.send_header("Cache-Control", "no-store")
                handler.send_header("Referrer-Policy", "no-referrer")
                handler.send_header("X-Content-Type-Options", "nosniff")
                handler.send_header("Content-Security-Policy",
                                    "default-src 'self'; frame-ancestors 'none'; base-uri 'none'")
                handler.end_headers()
                handler.wfile.write(body)

            def log_message(handler, *_args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        host = f"127.0.0.1:{self.server.server_port}"
        self.url = f"http://{host}{prefix}"
        self.thread = threading.Thread(target=self.server.serve_forever, kwargs={"poll_interval": 0.1}, daemon=True)
        self.thread.start()

    def publish(self, payload):
        self.payload = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
