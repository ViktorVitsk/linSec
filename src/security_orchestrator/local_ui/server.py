"""Restricted local HTTP transport. This is not an Internet-facing web server."""

import hashlib
import hmac
from http.server import BaseHTTPRequestHandler, HTTPServer
from importlib.resources import files
import json
import re
import socket
import threading
import time
from urllib.parse import parse_qs, urlsplit

from ..investigation.contracts import require
from ..model import InvalidInput

MAX_RESPONSE = 256 * 1024
HEADERS = {
    "Content-Security-Policy": "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src data:; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Cross-Origin-Resource-Policy": "same-origin",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Permissions-Policy": "camera=(), microphone=(), geolocation=()",
}


def validate_bind(host: str, port: int) -> None:
    require(host == "127.0.0.1", "ui_requires_exact_IPv4_loopback")
    require(type(port) is int and 1024 <= port <= 65535, "invalid_ui_port")


class Access:
    def __init__(self, token: str, authority: str, clock=time.monotonic):
        require(
            isinstance(token, str) and bool(re.fullmatch(r"[A-Za-z0-9_-]{32,128}", token)),
            "ui_token_requires_32_to_128_random_ASCII_characters",
        )
        self.digest = hashlib.sha256(token.encode()).digest()
        self.authority, self.clock = authority, clock
        self.expires = clock() + 8 * 3600

    def authenticated(self, authorization: str) -> bool:
        if (
            self.clock() >= self.expires
            or not authorization.startswith("Bearer ")
            or len(authorization) > 135
            or not authorization.isascii()
        ):
            return False
        return hmac.compare_digest(self.digest, hashlib.sha256(authorization[7:].encode()).digest())


class Routes:
    def __init__(self, queries, access: Access):
        self.queries, self.access = queries, access

    def response(self, method: str, target: str, headers: dict[str, str]) -> tuple[int, str, bytes]:
        def error(code):
            return (
                code,
                "application/json; charset=utf-8",
                json.dumps(
                    {
                        "error": {
                            400: "invalid_request",
                            401: "authentication_required",
                            403: "origin_refused",
                            404: "not_found",
                            405: "read_only_methods",
                            413: "request_limit",
                            503: "storage_or_contract_failure",
                        }.get(code, "request_failed")
                    }
                ).encode(),
            )

        # No request value is reflected in diagnostics.
        if len(target) > 512 or sum(len(k) + len(v) for k, v in headers.items()) > 8192:
            return error(413)
        if headers.get("host") != self.access.authority:
            return error(403)
        origin = headers.get("origin")
        if origin is not None and origin != "http://" + self.access.authority:
            return error(403)
        if headers.get("sec-fetch-site") not in {None, "same-origin", "none"}:
            return error(403)
        if method != "GET":
            return error(405)
        if (
            headers.get("content-length", "0") != "0"
            or "transfer-encoding" in headers
            or "content-type" in headers
            or "expect" in headers
        ):
            return error(400)
        try:
            parsed = urlsplit(target)
        except ValueError:
            return error(400)
        if parsed.scheme or parsed.netloc or parsed.fragment or not target.startswith("/"):
            return error(400)
        assets = {
            "/": ("index.html", "text/html; charset=utf-8"),
            "/app.js": ("app.js", "text/javascript; charset=utf-8"),
            "/style.css": ("style.css", "text/css; charset=utf-8"),
        }
        if parsed.path in assets and not parsed.query:
            name, mime = assets[parsed.path]
            return 200, mime, files("security_orchestrator.local_ui").joinpath(name).read_bytes()
        if not self.access.authenticated(headers.get("authorization", "")):
            return error(401)
        if headers.get("x-sec-ui") != "1" or (
            origin is None and headers.get("sec-fetch-site") != "same-origin"
        ):
            return error(403)
        try:
            params = parse_qs(
                parsed.query, strict_parsing=True, keep_blank_values=True, max_num_fields=2
            )
            if any(len(v) != 1 or not re.fullmatch(r"[0-9]{1,19}", v[0]) for v in params.values()):
                return error(400)
            if parsed.path == "/api/overview" and not params:
                payload = self.queries.overview()
            elif parsed.path == "/api/alerts" and params.keys() <= {"limit", "before"}:
                payload = self.queries.alerts(
                    int(params.get("limit", ["25"])[0]),
                    int(params.get("before", [str(2**63 - 1)])[0]),
                )
            elif re.fullmatch(r"/api/alerts/[1-9][0-9]{0,9}", parsed.path) and not params:
                payload = self.queries.detail(int(parsed.path.rsplit("/", 1)[1]))
            else:
                return error(404)
            raw = json.dumps(payload, ensure_ascii=True, allow_nan=False).encode()
            if len(raw) > MAX_RESPONSE:
                return error(503)
            return 200, "application/json; charset=utf-8", raw
        except InvalidInput as exc:
            if str(exc) == "alert_not_found":
                return error(404)
            if str(exc) in {"invalid_page_limit", "invalid_page_cursor", "invalid_alert_id"}:
                return error(400)
            return error(503)
        except (ValueError, OverflowError):
            return error(400)
        except Exception:
            return error(503)


class Handler(BaseHTTPRequestHandler):
    server_version = "SecurityOrchestrator"
    sys_version = ""

    def log_message(self, format, *args):
        pass  # No URL, token, headers, client names, payloads or exception text in logs.

    def send_error(self, code, message=None, explain=None):
        self.reply(code, "application/json", b'{"error":"invalid_http_request"}')

    def reply(self, code, mime, body):
        self.send_response_only(code)
        self.send_header("Content-Type", mime)
        for key, value in HEADERS.items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)
        self.close_connection = True

    def do_GET(self):
        # Reject ambiguity before using stdlib's normalized path or email-style headers.
        words = self.requestline.split(" ")
        if (
            len(words) != 3
            or words[1] != self.path
            or words[2] not in {"HTTP/1.0", "HTTP/1.1"}
            or any(ord(c) < 33 or ord(c) > 126 for c in words[1])
            or self.headers.defects
        ):
            self.reply(400, "application/json", b'{"error":"invalid_http_request"}')
            return
        headers = {}
        for key in self.headers.keys():
            values = self.headers.get_all(key)
            if len(values) != 1 or any(ord(c) < 32 or ord(c) > 126 for c in values[0]):
                self.reply(400, "application/json", b'{"error":"duplicate_header"}')
                return
            headers[key.lower()] = values[0]
        self.reply(*self.server.routes.response(self.command, self.path, headers))

    do_HEAD = do_GET
    do_POST = do_GET
    do_PUT = do_GET
    do_PATCH = do_GET
    do_DELETE = do_GET
    do_OPTIONS = do_GET
    do_TRACE = do_GET
    do_CONNECT = do_GET

    def handle(self):
        self.connection.settimeout(2)

        def expire():
            try:
                self.connection.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass

        timer = threading.Timer(5, expire)
        timer.daemon = True
        timer.start()
        try:
            super().handle()
        except (OSError, ValueError):
            pass
        finally:
            timer.cancel()


class LocalServer(HTTPServer):
    allow_reuse_address = False
    request_queue_size = 4

    def __init__(self, host: str, port: int, queries, token: str):
        validate_bind(host, port)
        self.routes = Routes(queries, Access(token, f"{host}:{port}"))
        super().__init__((host, port), Handler)

    def handle_error(self, request, client_address):
        pass  # Fixed API errors; never traceback on hostile input.
