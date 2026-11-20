#!/usr/bin/env python3
"""libsec MVP: заглушка hello world на 127.0.0.1:8795 (nginx -> https://libsec.alid.in)."""
import json, os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PORT = int(os.environ.get('LIBSEC_PORT', 8795))
PAGE = b"""<!doctype html><meta charset="utf-8"><title>libsec</title>
<body style="font-family:system-ui;max-width:40rem;margin:4rem auto;padding:0 1rem">
<h1>libsec</h1><p>Hello, world. MVP coming soon.</p></body>"""


class H(BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path == '/health':
            body, ctype = json.dumps({'ok': True}).encode(), 'application/json'
        elif self.path in ('/', '/index.html'):
            body, ctype = PAGE, 'text/html; charset=utf-8'
        else:
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header('Content-Type', ctype)
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


if __name__ == '__main__':
    ThreadingHTTPServer(('127.0.0.1', PORT), H).serve_forever()
