"""Serve northline.html and bridge its support chat to a JSON-based platform.

Run: CHAT_WEBHOOK_TOKEN=your-long-random-secret python3 northline_server.py
Open: http://127.0.0.1:8000

Set CHAT_PLATFORM_URL to the platform adapter's HTTPS endpoint. It receives
{"event":"visitor.message","session":"<id>","text":"<message>"} as a JSON POST.
Set CHAT_PLATFORM_TOKEN if that endpoint accepts bearer authentication.

Register POST /webhooks/chat with the platform adapter. To reply to a visitor,
POST {"session":"<id>","text":"<reply>","event_id":"<unique reply ID>"} with
Content-Type: application/json and Authorization: Bearer <CHAT_WEBHOOK_TOKEN>.
The adapter should retain the session from the visitor.message event. If the
platform uses a different payload or signature scheme, translate it there.

With no CHAT_PLATFORM_URL, the server echoes the session ID in a demo receipt
so you can test callbacks manually. A public integration needs an HTTPS
reverse proxy. The server binds to loopback by default, and chat sessions are
held in memory and expire after one hour without requests. This is a
demonstration server.
"""

import hmac
import json
import os
import re
import secrets
import time
from collections import deque
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Lock
from urllib.error import URLError
from urllib.parse import parse_qs, urlsplit
from urllib.request import HTTPRedirectHandler, Request, build_opener


PAGE = Path(__file__).with_name("northline.html")
SESSION_TTL = 3600
MAX_SESSIONS = 500
MAX_BODY = 16384
MAX_REPLIES = 100
SESSION_ID = re.compile(r"[A-Za-z0-9_-]{32}")
SESSIONS = {}
LOCK = Lock()


@dataclass
class Conversation:
    touched: float = field(default_factory=time.monotonic)
    replies: deque = field(default_factory=lambda: deque(maxlen=MAX_REPLIES))
    sequence: int = 0

    def reply(self, text, event_id=None):
        for entry in self.replies:
            if event_id is not None and entry["event_id"] == event_id:
                return entry["text"] == text

        self.sequence += 1
        self.replies.append({"sequence": self.sequence, "text": text, "event_id": event_id})
        return True


class NoRedirect(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def get_session(session_id):
    if not isinstance(session_id, str) or not SESSION_ID.fullmatch(session_id):
        return None

    conversation = SESSIONS.get(session_id)
    now = time.monotonic()
    if conversation and now - conversation.touched < SESSION_TTL:
        conversation.touched = now
        return conversation
    SESSIONS.pop(session_id, None)
    return None


def open_session():
    now = time.monotonic()
    expired = [key for key, value in SESSIONS.items() if now - value.touched >= SESSION_TTL]
    for key in expired:
        del SESSIONS[key]

    if len(SESSIONS) >= MAX_SESSIONS:
        return None

    session_id = secrets.token_urlsafe(24)
    SESSIONS[session_id] = Conversation()
    return session_id


class ChatHandler(BaseHTTPRequestHandler):
    def setup(self):
        self.request.settimeout(10)
        super().setup()

    def respond(self, status, body, content_type="application/json"):
        payload = json.dumps(body).encode() if content_type == "application/json" else body
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(payload)

    def log_request(self, code="-", size="-"):
        # Conversation IDs and message bodies are deliberately absent from logs.
        return

    def read_message(self):
        if self.headers.get_content_type() != "application/json":
            self.respond(415, {"error": "Expected application/json"})
            return None
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = 0
        if not 0 < length <= MAX_BODY:
            self.respond(413 if length > MAX_BODY else 400, {"error": "Invalid body size"})
            return None
        try:
            data = json.loads(self.rfile.read(length).decode("utf-8"))
        except (UnicodeDecodeError, ValueError, TimeoutError, RecursionError):
            self.respond(400, {"error": "Invalid JSON body"})
            return None
        text = data.get("text") if isinstance(data, dict) else None
        if not isinstance(text, str) or not 0 < len(text.strip()) <= 1000:
            self.respond(400, {"error": "Provide text between 1 and 1000 characters"})
            return None
        data["text"] = text.strip()
        return data

    def do_GET(self):
        route = urlsplit(self.path)
        if route.path in {"/", "/northline.html"}:
            self.respond(200, PAGE.read_bytes(), "text/html; charset=utf-8")
        elif route.path == "/api/config":
            self.respond(200, {"serverChat": True})
        elif route.path.startswith("/api/chat/"):
            self.read_replies(route.path.removeprefix("/api/chat/"), route.query)
        else:
            self.respond(404, {"error": "Unknown route"})

    def read_replies(self, session_id, query):
        try:
            after = int(parse_qs(query).get("after", ["0"])[0])
        except ValueError:
            self.respond(400, {"error": "Invalid message cursor"})
            return
        with LOCK:
            conversation = get_session(session_id)
            if conversation:
                replies = [
                    {"sequence": entry["sequence"], "text": entry["text"]}
                    for entry in conversation.replies if entry["sequence"] > after
                ]
        if not conversation:
            self.respond(404, {"error": "Unknown session"})
            return
        self.respond(200, {"messages": replies})

    def do_POST(self):
        path = urlsplit(self.path).path
        if path == "/webhooks/chat":
            expected = b"Bearer " + self.server.webhook_token.encode()
            supplied = self.headers.get("Authorization", "").encode()
            if not hmac.compare_digest(supplied, expected):
                self.respond(401, {"error": "Invalid webhook token"})
                return
            data = self.read_message()
            if data is not None:
                self.accept_reply(data)
        elif path == "/api/chat":
            data = self.read_message()
            if data is not None:
                self.send_to_platform(data)
        else:
            self.respond(404, {"error": "Unknown route"})

    def accept_reply(self, data):
        event_id = data.get("event_id")
        if not isinstance(event_id, str) or not 0 < len(event_id) <= 128:
            self.respond(400, {"error": "Provide an event_id up to 128 characters"})
            return
        with LOCK:
            conversation = get_session(data.get("session"))
            accepted = conversation and conversation.reply(data["text"], event_id)
        if not conversation:
            self.respond(404, {"error": "Unknown session"})
        elif not accepted:
            self.respond(409, {"error": "Event ID already used with different text"})
        else:
            self.respond(200, {"accepted": True})

    def send_to_platform(self, data):
        session_id = data.get("session")
        new_session = session_id is None
        with LOCK:
            if new_session:
                session_id = open_session()
                conversation = SESSIONS.get(session_id)
            else:
                conversation = get_session(session_id)
        if not conversation:
            status = 503 if session_id is None else 404
            self.respond(status, {"error": "Chat at capacity" if status == 503 else "Unknown session"})
            return

        if self.server.platform_url:
            event = {"event": "visitor.message", "session": session_id, "text": data["text"]}
            headers = {"Content-Type": "application/json"}
            if self.server.platform_token:
                headers["Authorization"] = "Bearer " + self.server.platform_token
            request = Request(self.server.platform_url, json.dumps(event).encode(), headers, method="POST")
            try:
                with build_opener(NoRedirect()).open(request, timeout=5):
                    pass
            except (URLError, TimeoutError, OSError):
                if new_session:
                    with LOCK:
                        SESSIONS.pop(session_id, None)
                self.respond(502, {"error": "Chat platform delivery could not be confirmed"})
                return
        else:
            with LOCK:
                if not conversation.replies:
                    conversation.reply("Demo message received. To test a webhook reply, use session " + session_id)
        self.respond(202, {"session": session_id})


def main():
    token = os.environ.get("CHAT_WEBHOOK_TOKEN")
    if not token:
        raise SystemExit("Set CHAT_WEBHOOK_TOKEN to a long random secret before starting.")
    platform_url = os.environ.get("CHAT_PLATFORM_URL")
    if platform_url:
        endpoint = urlsplit(platform_url)
        if endpoint.scheme != "https" or not endpoint.hostname or endpoint.username is not None:
            raise SystemExit("CHAT_PLATFORM_URL must be an HTTPS endpoint without credentials.")

    bind = os.environ.get("CHAT_BIND", "127.0.0.1")
    port = int(os.environ.get("CHAT_PORT", "8000"))
    with ThreadingHTTPServer((bind, port), ChatHandler) as server:
        server.webhook_token = token
        server.platform_url = platform_url
        server.platform_token = os.environ.get("CHAT_PLATFORM_TOKEN")
        print(f"Open http://{bind}:{server.server_port}", flush=True)
        try:
            server.serve_forever()
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
