"""Receives openfraud webhooks and keeps the last one (headers and raw body)."""
import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer

OUT = sys.argv[1]


class H(BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers["content-length"])).decode()
        headers = {k.lower(): v for k, v in self.headers.items()}
        with open(OUT, "w", newline="") as f:
            json.dump({"headers": headers, "body": body}, f)
        self.send_response(200)
        self.end_headers()

    def log_message(self, *a):
        pass


HTTPServer(("127.0.0.1", 18099), H).serve_forever()
