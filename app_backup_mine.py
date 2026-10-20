import os
import time
from collections import Counter, deque

from flask import Flask, jsonify, request, send_from_directory



def _load_dotenv():
    """Tiny .env reader (no extra package). Lines like OPENAI_API_KEY=sk-..."""
    path = os.path.join(os.path.dirname(os.path.abspath(__file__)), ".env")
    if not os.path.exists(path):
        return
    with open(path, encoding="utf-8-sig") as fh:
        for line in fh:
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))


_load_dotenv()

import ai_scanner  # noqa: E402  (after .env is loaded)
import analyzer  # noqa: E402
import injection_lab as lab  # noqa: E402

app = Flask(__name__, static_folder="static")
app.config["MAX_CONTENT_LENGTH"] = 64 * 1024  # reject oversized bodies

HISTORY = deque(maxlen=200)       # in-memory only; swap for a DB to persist
LAB_RUNS = deque(maxlen=20)       # recent lab results for the dashboard
LAB_FAILS = Counter()             # category -> failed attacks (all runs)
RATE = {}                         # ip -> timestamps (AI calls cost money)
AI_LIMIT, AI_WINDOW = 30, 60      # 30 AI calls per minute per client (a lab run uses 12)


def _body():
    return request.get_json(silent=True) or {}


def _log(kind, summary, score, level):
    HISTORY.appendleft({"time": time.strftime("%H:%M:%S"), "kind": kind,
                        "summary": summary[:80], "score": score, "level": level})


def _ai_allowed(cost=1):
    q = RATE.setdefault(request.remote_addr, deque())
    now = time.time()
    while q and now - q[0] > AI_WINDOW:
        q.popleft()
    if len(q) + cost > AI_LIMIT:
        return False
    q.extend([now] * cost)
    return True


@app.after_request
def headers(r):
    r.headers["X-Content-Type-Options"] = "nosniff"
    r.headers["X-Frame-Options"] = "DENY"
    r.headers["Referrer-Policy"] = "no-referrer"
    r.headers["Content-Security-Policy"] = ("default-src 'self'; style-src 'self' 'unsafe-inline'; "
                                            "script-src 'self' 'unsafe-inline'; img-src 'self' data:")
    return r


@app.get("/")
def index():
    return send_from_directory("static", "index.html")


@app.get("/api/config")
def config():
    return jsonify(ai_available=ai_scanner.available(), provider=ai_scanner.provider(),
                   model=ai_scanner.model_name(), targets=lab.available_targets(),
                   labels=lab.LABELS,
                   payloads=[{k: p[k] for k in ("id", "category", "severity")} for p in lab.PAYLOADS])


def _is_local():
    return request.remote_addr in ("127.0.0.1", "::1")


@app.post("/api/settings")
def save_settings():
    """Set the AI key/model for this running server only (memory, never saved or returned)."""
    if not _is_local():
        return jsonify(error="Settings can only be changed from the machine running SecureAI."), 403
    data = _body()
    key = str(data.get("api_key", "")).strip()
    model = str(data.get("model", "")).strip()[:80]
    if key:
        if len(key) < 20 or any(c.isspace() for c in key):
            return jsonify(error="That doesn't look like a valid API key."), 400
        # Anthropic keys start with "sk-ant-"; anything else is treated as an OpenAI key.
        # The other provider's key is cleared so the one you just saved is the one used.
        if key.startswith("sk-ant-"):
            os.environ["ANTHROPIC_API_KEY"] = key
            os.environ.pop("OPENAI_API_KEY", None)
        else:
            os.environ["OPENAI_API_KEY"] = key
            os.environ.pop("ANTHROPIC_API_KEY", None)
    if model:
        os.environ["SECUREAI_MODEL"] = model
    return config()


@app.post("/api/ai/test")
def test_ai():
    if not ai_scanner.available():
        return jsonify(ok=False, message="No API key set yet. Paste your key above and save."), 200
    if not _ai_allowed():
        return jsonify(ok=False, message="Too many AI requests; wait a minute."), 200
    try:
        ai_scanner.complete("Reply with the single word: ok", "ping", max_tokens=5)
        return jsonify(ok=True, message=f"Connected. {ai_scanner.provider()} / {ai_scanner.model_name()} works.")
    except Exception as e:
        app.logger.warning("AI test failed: %s", type(e).__name__)
        return jsonify(ok=False, message=ai_scanner.friendly_error(e))


def _with_ai(kind, content, res):
    """Add the AI verdict if requested; any failure falls back to rule-based only."""
    if not _body().get("ai"):
        return res
    if not ai_scanner.available():
        res["ai_error"] = "AI scan is off: no API key set on the server. Rule-based result shown."
    elif not _ai_allowed():
        res["ai_error"] = "AI rate limit reached; try again in a minute. Rule-based result shown."
    else:
        try:
            ai = ai_scanner.scan(kind, content, res)
            res["heuristic_score"] = res["score"]
            res["ai"] = ai
            res["score"] = ai_scanner.blend(res["score"], ai)
            res["level"] = analyzer._level(res["score"])
        except Exception as e:  # never leak keys / stack traces
            app.logger.warning("AI scan failed: %s", type(e).__name__)
            res["ai_error"] = ai_scanner.friendly_error(e) + " Rule-based result shown."
    return res


@app.post("/api/analyze-message")
def api_message():
    text = str(_body().get("text", ""))[:5000]
    if not text.strip():
        return jsonify(error="Please paste a message first."), 400
    res = _with_ai("message", text, analyzer.analyze_message(text))
    _log("message" + (" +AI" if "ai" in res else ""), text, res["score"], res["level"])
    return jsonify(res)


@app.post("/api/analyze-url")
def api_url():
    url = str(_body().get("url", ""))[:2000]
    if not url.strip():
        return jsonify(error="Please enter a URL first."), 400
    res = _with_ai("url", url, analyzer.analyze_url(url))
    _log("url" + (" +AI" if "ai" in res else ""), url, res["score"], res["level"])
    return jsonify(res)


@app.post("/api/lab/run")
def lab_run():
    data = _body()
    target = data.get("target")
    if target not in lab.available_targets():
        return jsonify(error="That target isn't available (live AI needs an API key)."), 400
    if target == "live-ai" and not _ai_allowed(cost=len(lab.PAYLOADS)):
        return jsonify(error="AI rate limit reached; wait a minute and retry."), 429
    res = lab.run_suite(target, data.get("payload_ids"), str(data.get("system_prompt", ""))[:2000] or None)
    for r in res["results"]:
        if r["status"] == "fail":
            LAB_FAILS[r["category"]] += 1
    LAB_RUNS.appendleft({"time": time.strftime("%H:%M:%S"), "target": target,
                         "resilience": res["resilience"]})
    risk = 100 - (res["resilience"] if res["resilience"] is not None else 100)
    _log("lab", f"{target}: {res['passed']}/{res['total']} resisted", risk,
         analyzer._level(risk))
    return jsonify(res)


@app.get("/api/stats")
def stats():
    h = list(HISTORY)
    scans = [x for x in h if x["kind"].startswith(("message", "url"))]
    return jsonify(
        total=len(h), scans=len(scans),
        high=sum(x["level"] == "high" for x in scans),
        medium=sum(x["level"] == "medium" for x in scans),
        low=sum(x["level"] == "low" for x in scans),
        ai_scans=sum("+AI" in x["kind"] for x in h),
        recent_scores=[x["score"] for x in reversed(scans[:20])],
        lab_runs=list(LAB_RUNS),
        lab_fail_categories=dict(LAB_FAILS.most_common()),
        history=h[:15])


if __name__ == "__main__":
    app.run(debug=False, port=5000)