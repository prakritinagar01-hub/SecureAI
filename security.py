"""Hardening helpers: secret key, CSRF, rate limiting, admin login, headers."""
import hmac
import os
import secrets
import threading
import time
from collections import defaultdict, deque
from functools import wraps

from flask import (
    jsonify, redirect, request, session, url_for
)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


# ---------------------------------------------------------------------------
# Secret key (persisted so sessions survive restarts)
# ---------------------------------------------------------------------------

def load_secret_key():
    env_key = os.environ.get("SECRET_KEY")
    if env_key:
        return env_key

    path = os.path.join(BASE_DIR, ".secret_key")
    try:
        with open(path, "r", encoding="utf-8") as handle:
            key = handle.read().strip()
            if key:
                return key
    except OSError:
        pass

    key = secrets.token_hex(32)
    try:
        # 0o600: only the owner can read the file
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            handle.write(key)
    except OSError:
        pass  # fall back to a per-process key
    return key


# ---------------------------------------------------------------------------
# CSRF protection (token in the session, sent back in a header)
# ---------------------------------------------------------------------------

def csrf_token():
    token = session.get("csrf")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf"] = token
    return token


def check_csrf():
    """Return an error response for unsafe methods without a valid token."""
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return None

    sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
    expected = session.get("csrf", "")
    if not expected or not hmac.compare_digest(sent, expected):
        return jsonify({"error": "Security check failed. Refresh the page and try again."}), 403
    return None


# ---------------------------------------------------------------------------
# Rate limiting (in-memory sliding window, per client IP and bucket)
# ---------------------------------------------------------------------------

_hits = defaultdict(deque)
_lock = threading.Lock()


def client_ip():
    # Behind a proxy, configure it to set REMOTE_ADDR (e.g. ProxyFix).
    return request.remote_addr or "unknown"


def hit(bucket, limit, window_seconds):
    """Record a call. Returns 0 if allowed, else seconds until retry."""
    if os.environ.get("SECUREAI_DISABLE_RATE_LIMIT") == "1":
        return 0

    key = (bucket, client_ip())
    now = time.monotonic()
    with _lock:
        hits = _hits[key]
        while hits and now - hits[0] > window_seconds:
            hits.popleft()
        if len(hits) >= limit:
            return int(window_seconds - (now - hits[0])) + 1
        hits.append(now)
    return 0


def rate_limit(bucket, limit, window_seconds):
    """Decorator: allow `limit` calls per `window_seconds` per IP."""
    def decorator(view):
        @wraps(view)
        def wrapper(*args, **kwargs):
            retry = hit(bucket, limit, window_seconds)
            if retry:
                response = jsonify({
                    "error": "Too many requests. Try again in "
                             + str(retry) + " seconds."
                })
                response.status_code = 429
                response.headers["Retry-After"] = str(retry)
                return response
            return view(*args, **kwargs)
        return wrapper
    return decorator


def reset_rate_limits():
    with _lock:
        _hits.clear()


# ---------------------------------------------------------------------------
# Admin login
# If SECUREAI_ADMIN_PASSWORD is set, the dashboard, history, downloads and
# the AI lab need a login. The scanner itself stays public.
# If it is not set, everything is open (development mode).
# ---------------------------------------------------------------------------

def auth_enabled():
    return bool(os.environ.get("SECUREAI_ADMIN_PASSWORD"))


def is_admin():
    return (not auth_enabled()) or session.get("admin") is True


def check_password(candidate):
    expected = os.environ.get("SECUREAI_ADMIN_PASSWORD", "")
    return bool(expected) and hmac.compare_digest(
        candidate.encode("utf-8"), expected.encode("utf-8")
    )


def admin_required(view):
    @wraps(view)
    def wrapper(*args, **kwargs):
        if is_admin():
            return view(*args, **kwargs)
        if request.path.startswith(("/api/", "/download/")):
            return jsonify({"error": "Login required."}), 401
        return redirect(url_for("login", next=request.path))
    return wrapper


def safe_next(target):
    """Only allow redirects to local paths."""
    if target and target.startswith("/") and not target.startswith("//"):
        return target
    return "/dashboard"


# ---------------------------------------------------------------------------
# Security headers
# ---------------------------------------------------------------------------

CSP = "; ".join([
    "default-src 'self'",
    "script-src 'self' https://cdn.jsdelivr.net",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com",
    "font-src https://fonts.gstatic.com",
    "img-src 'self' data:",
    "connect-src 'self'",
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'self'",
    "frame-ancestors 'none'",
])


def apply_headers(response):
    response.headers.setdefault("Content-Security-Policy", CSP)
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    if request.path.startswith(("/api/", "/analyse", "/download/", "/dashboard", "/lab")):
        response.headers["Cache-Control"] = "no-store"
    return response