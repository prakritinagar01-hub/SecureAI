import csv
import io
import ipaddress
import json
import os
import sqlite3
from collections import Counter
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from flask import (
    Flask, Response, g, jsonify, redirect, render_template, request, session,
    url_for
)

import ai
import lab_tests
import security

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.environ.get("SECUREAI_DB", os.path.join(BASE_DIR, "secureai.db"))

app.config.update(
    SECRET_KEY=security.load_secret_key(),
    MAX_CONTENT_LENGTH=64 * 1024,                  # reject huge request bodies
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("SECUREAI_HTTPS") == "1",
)


@app.before_request
def csrf_protect():
    return security.check_csrf()


@app.after_request
def add_security_headers(response):
    return security.apply_headers(response)


@app.context_processor
def inject_globals():
    return {
        "csrf_token": security.csrf_token(),
        "auth_enabled": security.auth_enabled(),
        "is_admin": security.is_admin(),
        "ai_on": ai.ai_configured(),
    }


@app.errorhandler(413)
def too_large(_error):
    return jsonify({"error": "Request is too large."}), 413


# ---------------------------------------------------------------------------
# Scanners (logic unchanged from the original project)
# ---------------------------------------------------------------------------

def analyse_message(message):
    message = message.lower().strip()
    score = 0
    warnings = []

    if not message:
        return {
            "score": 0,
            "risk": "Unknown",
            "warnings": ["Please enter a message to analyse."]
        }

    # 1. Urgent or threatening language
    urgent_phrases = [
        "urgent", "immediately", "act now",
        "within 24 hours", "account will be blocked",
        "account will be suspended"
    ]

    if any(phrase in message for phrase in urgent_phrases):
        score += 20
        warnings.append("Urgent or threatening language detected")

    # 2. Requests to reveal sensitive information
    sensitive_requests = [
        "give me otp", "send me otp", "share otp",
        "send otp", "tell me your otp", "enter your otp",
        "share your otp", "provide otp",
        "send me your password", "share your password",
        "tell me your password"
    ]

    if any(phrase in message for phrase in sensitive_requests):
        score += 45
        warnings.append("Possible request for sensitive information detected")

    # 3. OTP or password combined with account verification
    has_sensitive_term = any(
        term in message for term in ["otp", "password", "pin", "passcode"]
    )

    verification_terms = [
        "verify", "verification", "bank account",
        "account blocked", "account suspended",
        "confirm your identity", "unlock your account"
    ]

    if has_sensitive_term and any(
        term in message for term in verification_terms
    ):
        score += 30
        warnings.append(
            "Sensitive information combined with an account verification request"
        )

    # 4. Suspicious links and login requests
    link_phrases = [
        "click here", "verify your account",
        "login here", "open this link",
        "click this link", "confirm your account"
    ]

    if any(phrase in message for phrase in link_phrases):
        score += 25
        warnings.append("Suspicious link or verification request detected")

    # 5. Prize and reward scams
    prize_phrases = [
        "won a prize", "claim reward",
        "you have won", "claim your prize",
        "free money", "lottery winner"
    ]

    if any(phrase in message for phrase in prize_phrases):
        score += 25
        warnings.append("Possible prize or reward scam detected")

    # 6. Money transfer or payment pressure
    payment_phrases = [
        "send money immediately", "transfer money now",
        "pay processing fee", "pay to receive your prize"
    ]

    if any(phrase in message for phrase in payment_phrases):
        score += 25
        warnings.append("Suspicious payment request detected")

    # Keep the score within the valid range
    score = min(score, 100)

    if score >= 50:
        risk = "High"
    elif score >= 25:
        risk = "Medium"
    else:
        risk = "Low"

    if not warnings:
        warnings.append("No known warning signs detected")

    return {
        "score": score,
        "risk": risk,
        "warnings": warnings
    }


def analyse_url(url):
    url = url.strip()
    score = 0
    warnings = []

    if not url:
        return {
            "score": 0,
            "risk": "Unknown",
            "warnings": ["Please enter a URL."]
        }

    if len(url) > 2048:
        return {
            "score": 0,
            "risk": "Unknown",
            "warnings": ["URL is too long to analyse."]
        }

    # URL format check
    try:
        parsed = urlparse(url if "://" in url else "https://" + url)
        hostname = parsed.hostname

        if not hostname:
            raise ValueError("Missing hostname")

    except ValueError:
        return {
            "score": 0,
            "risk": "Unknown",
            "warnings": ["Invalid URL format."]
        }

    host = hostname.lower()

    # HTTP instead of HTTPS
    if parsed.scheme.lower() == "http":
        score += 20
        warnings.append("URL uses HTTP instead of HTTPS")

    # IP address used as hostname
    try:
        ipaddress.ip_address(host)
        score += 30
        warnings.append("URL uses an IP address instead of a domain")
    except ValueError:
        pass

    # Suspicious words
    suspicious_words = [
        "login", "verify", "password", "secure",
        "account", "prize", "claim", "update"
    ]

    found_words = [word for word in suspicious_words if word in url.lower()]

    if found_words:
        score += 15
        warnings.append("Suspicious words found: " + ", ".join(found_words))

    # Excessive subdomains
    if len(host.split(".")) > 4:
        score += 15
        warnings.append("Unusually many domain sections")

    # URL contains @ symbol
    if "@" in parsed.netloc:
        score += 25
        warnings.append("URL contains an unusual @ symbol")

    score = min(score, 100)

    if score >= 50:
        risk = "High"
    elif score >= 25:
        risk = "Medium"
    else:
        risk = "Low"

    if not warnings:
        warnings.append("No common URL warning signs detected")

    return {
        "score": score,
        "risk": risk,
        "warnings": warnings
    }


# ---------------------------------------------------------------------------
# SQLite helpers
# ---------------------------------------------------------------------------

def get_db():
    if "db" not in g:
        g.db = sqlite3.connect(DATABASE)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_error=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


NEW_SCAN_COLUMNS = {
    "rule_score": "INTEGER",
    "rule_risk": "TEXT",
    "ai_score": "INTEGER",
    "ai_risk": "TEXT",
    "ai_summary": "TEXT",
    "categories": "TEXT",
}


def init_db():
    with sqlite3.connect(DATABASE) as db:
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                scan_type TEXT NOT NULL,
                input_text TEXT NOT NULL,
                score INTEGER NOT NULL,
                risk TEXT NOT NULL,
                warnings TEXT NOT NULL,
                created_at TEXT NOT NULL
            )
            """
        )
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_scans_created ON scans (created_at)"
        )

        # Upgrade databases created by the earlier version of the app.
        existing = {row[1] for row in db.execute("PRAGMA table_info(scans)")}
        for column, kind in NEW_SCAN_COLUMNS.items():
            if column not in existing:
                db.execute("ALTER TABLE scans ADD COLUMN " + column + " " + kind)
        db.execute("UPDATE scans SET rule_score = score WHERE rule_score IS NULL")
        db.execute("UPDATE scans SET rule_risk = risk WHERE rule_risk IS NULL")
        db.execute("UPDATE scans SET categories = '[]' WHERE categories IS NULL")

        db.execute(
            """
            CREATE TABLE IF NOT EXISTS lab_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                created_at TEXT NOT NULL,
                backend TEXT NOT NULL,
                preset TEXT NOT NULL,
                model TEXT,
                total INTEGER NOT NULL,
                passed INTEGER NOT NULL,
                errors INTEGER NOT NULL
            )
            """
        )
        db.execute(
            """
            CREATE TABLE IF NOT EXISTS lab_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                run_id INTEGER NOT NULL,
                test_id TEXT NOT NULL,
                category TEXT NOT NULL,
                title TEXT NOT NULL,
                passed INTEGER,
                reason TEXT NOT NULL,
                response TEXT NOT NULL
            )
            """
        )
        db.execute(
            "CREATE INDEX IF NOT EXISTS idx_lab_results_run ON lab_results (run_id)"
        )


def now_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def save_scan(scan_type, input_text, rule, ai_result, categories, score, risk):
    db = get_db()
    cursor = db.execute(
        "INSERT INTO scans (scan_type, input_text, score, risk, warnings,"
        " created_at, rule_score, rule_risk, ai_score, ai_risk, ai_summary,"
        " categories) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (
            scan_type,
            input_text,
            score,
            risk,
            json.dumps(rule["warnings"]),
            now_utc(),
            rule["score"],
            rule["risk"],
            ai_result.get("score") if ai_result.get("available") else None,
            ai_result.get("risk") if ai_result.get("available") else None,
            ai_result.get("summary") if ai_result.get("available") else None,
            json.dumps(categories),
        ),
    )
    db.commit()
    return cursor.lastrowid


def row_to_dict(row):
    ai_block = None
    if row["ai_score"] is not None:
        ai_block = {
            "score": row["ai_score"],
            "risk": row["ai_risk"],
            "summary": row["ai_summary"] or "",
        }
    return {
        "id": row["id"],
        "type": row["scan_type"],
        "input": row["input_text"],
        "score": row["score"],
        "risk": row["risk"],
        "rule_score": row["rule_score"],
        "rule_risk": row["rule_risk"],
        "ai": ai_block,
        "categories": json.loads(row["categories"] or "[]"),
        "warnings": json.loads(row["warnings"]),
        "created_at": row["created_at"],  # UTC, "YYYY-MM-DD HH:MM:SS"
    }


def escape_like(value):
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def build_filters(args):
    """Turn query-string filters into a WHERE clause + parameters."""
    clauses = []
    params = []

    search = (args.get("q") or "").strip()[:200]
    if search:
        clauses.append("input_text LIKE ? ESCAPE '\\'")
        params.append("%" + escape_like(search) + "%")

    scan_type = (args.get("type") or "").strip()
    if scan_type in ("Message", "URL"):
        clauses.append("scan_type = ?")
        params.append(scan_type)

    risk = (args.get("risk") or "").strip()
    if risk in ("Low", "Medium", "High"):
        clauses.append("risk = ?")
        params.append(risk)

    category = (args.get("category") or "").strip()
    if category in ai.CATEGORIES:
        clauses.append("categories LIKE ? ESCAPE '\\'")
        params.append('%"' + escape_like(category) + '"%')

    where = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    return where, params


def fetch_history(args, limit=None):
    where, params = build_filters(args)
    sql = "SELECT * FROM scans" + where + " ORDER BY id DESC"
    if limit:
        sql += " LIMIT ?"
        params = params + [limit]
    rows = get_db().execute(sql, params).fetchall()
    return [row_to_dict(r) for r in rows]


# ---------------------------------------------------------------------------
# Pages
# ---------------------------------------------------------------------------

@app.route("/")
def home():
    return render_template("index.html", active="home")


@app.route("/dashboard")
@security.admin_required
def dashboard():
    return render_template(
        "dashboard.html", active="dashboard", categories=ai.CATEGORIES
    )


@app.route("/lab")
@security.admin_required
def lab():
    return render_template("lab.html", active="lab")


@app.route("/awareness")
def awareness():
    return render_template("awareness.html", active="awareness")


@app.route("/login", methods=["GET", "POST"])
def login():
    if not security.auth_enabled():
        return redirect(url_for("dashboard"))

    error = None
    next_url = security.safe_next(request.values.get("next"))

    if request.method == "POST":
        retry = security.hit("login", 5, 300)
        if retry:
            error = "Too many attempts. Try again in " + str(retry) + " seconds."
        elif security.check_password(request.form.get("password", "")):
            session.clear()                       # new session after login
            session["admin"] = True
            return redirect(next_url)
        else:
            error = "Incorrect password."

    return render_template("login.html", active="login", error=error, next_url=next_url)


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("home"))


# ---------------------------------------------------------------------------
# Scanner routes (same URLs and request shape as before). The response keeps
# score / risk / warnings and adds: id, rule_score, rule_risk, ai, categories.
# score / risk are the FINAL verdict: the more cautious of rules and AI.
# Without an API key they are identical to the rule-based result.
# ---------------------------------------------------------------------------

def wants_ai(data):
    return data.get("use_ai", True) is not False


def run_scan(scan_type, text, rule, use_ai, categories_from_rules):
    if rule["risk"] == "Unknown":
        rule["id"] = None
        rule["ai"] = {"available": False, "note": "Nothing to analyse."}
        rule["categories"] = []
        return rule

    if use_ai:
        ai_result = ai.ai_analyse(scan_type, text)
    else:
        ai_result = {"available": False, "note": "AI analysis was skipped."}

    categories = list(dict.fromkeys(
        categories_from_rules + (ai_result.get("categories") or [])
    ))
    score, risk = ai.combine(rule, ai_result)
    scan_id = save_scan(scan_type, text, rule, ai_result, categories, score, risk)

    return {
        "id": scan_id,
        "score": score,
        "risk": risk,
        "warnings": rule["warnings"],
        "rule_score": rule["score"],
        "rule_risk": rule["risk"],
        "ai": ai_result,
        "categories": categories,
    }


@app.route("/analyse", methods=["POST"])
@security.rate_limit("scan", 20, 60)
def analyse():
    data = request.get_json(silent=True) or {}
    message = str(data.get("message", ""))[:5000]
    rule = analyse_message(message)
    cats = ai.categorise_message(message) if rule["risk"] != "Unknown" else []
    return jsonify(run_scan("Message", message.strip(), rule, wants_ai(data), cats))


@app.route("/analyse-url", methods=["POST"])
@security.rate_limit("scan", 20, 60)
def analyse_url_route():
    data = request.get_json(silent=True) or {}
    url = str(data.get("url", ""))[:2048]
    rule = analyse_url(url)
    cats = ai.categorise_url(url, rule)
    return jsonify(run_scan("URL", url.strip(), rule, wants_ai(data), cats))


# ---------------------------------------------------------------------------
# History / dashboard API (admin only when a password is configured)
# ---------------------------------------------------------------------------

@app.route("/api/history")
@security.admin_required
def api_history():
    return jsonify({"reports": fetch_history(request.args, limit=500)})


@app.route("/api/stats")
@security.admin_required
def api_stats():
    db = get_db()

    total = db.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    avg = db.execute("SELECT AVG(score) FROM scans").fetchone()[0]

    by_risk = {"High": 0, "Medium": 0, "Low": 0}
    for row in db.execute("SELECT risk, COUNT(*) AS n FROM scans GROUP BY risk"):
        if row["risk"] in by_risk:
            by_risk[row["risk"]] = row["n"]

    by_type = {"Message": 0, "URL": 0}
    for row in db.execute(
        "SELECT scan_type, COUNT(*) AS n FROM scans GROUP BY scan_type"
    ):
        if row["scan_type"] in by_type:
            by_type[row["scan_type"]] = row["n"]

    counter = Counter()
    for row in db.execute("SELECT categories FROM scans WHERE categories != '[]'"):
        try:
            counter.update(c for c in json.loads(row["categories"]) if c in ai.CATEGORIES)
        except ValueError:
            continue
    by_category = [
        {"category": name, "count": count}
        for name, count in sorted(counter.items(), key=lambda kv: -kv[1])
    ]

    # Last 7 days (UTC), including days with zero scans
    today = datetime.now(timezone.utc).date()
    days = [today - timedelta(days=i) for i in range(6, -1, -1)]
    counts = {d.isoformat(): 0 for d in days}
    since = days[0].isoformat()
    for row in db.execute(
        "SELECT substr(created_at, 1, 10) AS day, COUNT(*) AS n"
        " FROM scans WHERE created_at >= ? GROUP BY day",
        (since,),
    ):
        if row["day"] in counts:
            counts[row["day"]] = row["n"]

    return jsonify({
        "total": total,
        "average_score": round(avg, 1) if avg is not None else 0,
        "by_risk": by_risk,
        "by_type": by_type,
        "by_category": by_category,
        "injection_attempts": counter.get("Prompt injection attempt", 0),
        "daily": [{"day": d, "count": c} for d, c in counts.items()],
    })


@app.route("/api/history/<int:report_id>", methods=["DELETE"])
@security.admin_required
@security.rate_limit("delete", 60, 60)
def api_delete_report(report_id):
    db = get_db()
    cursor = db.execute("DELETE FROM scans WHERE id = ?", (report_id,))
    db.commit()
    if cursor.rowcount == 0:
        return jsonify({"error": "Report not found."}), 404
    return jsonify({"deleted": report_id})


@app.route("/api/history/clear", methods=["POST"])
@security.admin_required
@security.rate_limit("delete", 60, 60)
def api_clear_history():
    db = get_db()
    db.execute("DELETE FROM scans")
    db.commit()
    return jsonify({"cleared": True})


# ---------------------------------------------------------------------------
# Downloads (respect the dashboard's current search / filters)
# ---------------------------------------------------------------------------

def csv_safe(value):
    """Stop spreadsheet apps from running scanned text as a formula."""
    text = str(value)
    if text and text[0] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + text
    return text


def file_stamp():
    return datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")


@app.route("/download/csv")
@security.admin_required
def download_csv():
    reports = fetch_history(request.args)

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        ["ID", "Type", "Scanned item", "Final score", "Final risk",
         "Rule score", "AI score", "Attack categories", "Warnings",
         "AI summary", "Scanned at (UTC)"]
    )
    for r in reports:
        writer.writerow([
            r["id"], r["type"], csv_safe(r["input"]), r["score"], r["risk"],
            r["rule_score"], r["ai"]["score"] if r["ai"] else "",
            csv_safe(" | ".join(r["categories"])),
            csv_safe(" | ".join(r["warnings"])),
            csv_safe(r["ai"]["summary"]) if r["ai"] else "",
            r["created_at"],
        ])

    return Response(
        "﻿" + buffer.getvalue(),  # BOM so Excel reads UTF-8 correctly
        mimetype="text/csv; charset=utf-8",
        headers={
            "Content-Disposition":
                f'attachment; filename="secureai-reports-{file_stamp()}.csv"'
        },
    )


@app.route("/download/txt")
@security.admin_required
def download_txt():
    reports = fetch_history(request.args)

    lines = [
        "SecureAI - Security Scan Reports",
        "Generated: " + now_utc() + " UTC",
        "Reports included: " + str(len(reports)),
        "=" * 60,
        "",
    ]

    if not reports:
        lines.append("No reports match the selected filters.")

    for r in reports:
        lines += [
            f"Report #{r['id']} - {r['type']} scan",
            f"Scanned at : {r['created_at']} UTC",
            f"Risk score : {r['score']}/100 (final)",
            f"Risk level : {r['risk']}",
            f"Rule score : {r['rule_score']}/100",
        ]
        if r["ai"]:
            lines.append(f"AI score   : {r['ai']['score']}/100")
        lines.append("Categories : " + (", ".join(r["categories"]) or "none"))
        lines += [
            "Scanned item:",
            "  " + r["input"].replace("\n", "\n  "),
            "Warnings:",
        ]
        lines += ["  - " + w for w in r["warnings"]]
        if r["ai"] and r["ai"]["summary"]:
            lines += ["AI summary:", "  " + r["ai"]["summary"]]
        lines += ["", "-" * 60, ""]

    lines.append(
        "Note: results are indicators, not a guarantee that a message "
        "or website is safe."
    )

    return Response(
        "\n".join(lines),
        mimetype="text/plain; charset=utf-8",
        headers={
            "Content-Disposition":
                f'attachment; filename="secureai-reports-{file_stamp()}.txt"'
        },
    )


# ---------------------------------------------------------------------------
# AI Agent Safety Lab
# ---------------------------------------------------------------------------

def summarise_results(results):
    scored = [r for r in results if r["passed"] is not None]
    passed = sum(1 for r in scored if r["passed"])
    errors = len(results) - len(scored)

    categories = []
    for name in lab_tests.CATEGORY_ORDER:
        in_cat = [r for r in scored if r["category"] == name]
        if in_cat:
            categories.append({
                "category": name,
                "total": len(in_cat),
                "passed": sum(1 for r in in_cat if r["passed"]),
            })
    return {"total": len(scored), "passed": passed, "errors": errors,
            "categories": categories}


@app.route("/api/lab/meta")
@security.admin_required
def api_lab_meta():
    return jsonify({
        "tests": len(lab_tests.TESTS),
        "categories": lab_tests.CATEGORY_ORDER,
        "presets": {
            "weak": lab_tests.PRESETS["weak"],
            "hardened": lab_tests.PRESETS["hardened"],
            "custom": lab_tests.DEFAULT_CUSTOM,
        },
        "backends": {
            key: {"label": value["label"],
                  "available": key == "demo" or ai.ai_configured()}
            for key, value in lab_tests.BACKENDS.items()
        },
        "model": ai.current_model(),
        "provider": ai.provider(),
    })


@app.route("/api/lab/run", methods=["POST"])
@security.admin_required
@security.rate_limit("lab", 10, 3600)
def api_lab_run():
    data = request.get_json(silent=True) or {}
    backend = str(data.get("backend", "demo"))
    preset = str(data.get("preset", "hardened"))
    custom = str(data.get("system_prompt", ""))[:4000]

    if backend not in lab_tests.BACKENDS:
        return jsonify({"error": "Unknown agent backend."}), 400
    if preset not in ("weak", "hardened", "custom"):
        return jsonify({"error": "Unknown prompt preset."}), 400
    if backend == "llm" and not ai.ai_configured():
        return jsonify({"error": "Set an API key (ANTHROPIC_API_KEY or OPENAI_API_KEY) to test a real AI agent."}), 400

    system_prompt = lab_tests.build_system_prompt(preset, custom)
    results = lab_tests.run_suite(backend, system_prompt)
    summary = summarise_results(results)

    if summary["total"] == 0:
        message = next((r["reason"] for r in results if r["passed"] is None), "")
        return jsonify({"error": "No tests could be run. " + message}), 502

    db = get_db()
    cursor = db.execute(
        "INSERT INTO lab_runs (created_at, backend, preset, model, total,"
        " passed, errors) VALUES (?, ?, ?, ?, ?, ?, ?)",
        (now_utc(), backend, preset, ai.current_model() if backend == "llm" else None,
         summary["total"], summary["passed"], summary["errors"]),
    )
    run_id = cursor.lastrowid
    db.executemany(
        "INSERT INTO lab_results (run_id, test_id, category, title, passed,"
        " reason, response) VALUES (?, ?, ?, ?, ?, ?, ?)",
        [(run_id, r["id"], r["category"], r["title"],
          None if r["passed"] is None else int(r["passed"]),
          r["reason"], r["response"]) for r in results],
    )
    db.commit()

    return jsonify({"run_id": run_id, "backend": backend, "preset": preset,
                    "summary": summary, "results": results})


def lab_run_dict(row):
    return {
        "id": row["id"], "created_at": row["created_at"],
        "backend": row["backend"], "preset": row["preset"],
        "model": row["model"], "total": row["total"],
        "passed": row["passed"], "errors": row["errors"],
    }


@app.route("/api/lab/runs")
@security.admin_required
def api_lab_runs():
    rows = get_db().execute(
        "SELECT * FROM lab_runs ORDER BY id DESC LIMIT 50"
    ).fetchall()
    return jsonify({"runs": [lab_run_dict(r) for r in rows]})


@app.route("/api/lab/runs/<int:run_id>")
@security.admin_required
def api_lab_run_detail(run_id):
    db = get_db()
    run = db.execute("SELECT * FROM lab_runs WHERE id = ?", (run_id,)).fetchone()
    if run is None:
        return jsonify({"error": "Run not found."}), 404
    rows = db.execute(
        "SELECT * FROM lab_results WHERE run_id = ? ORDER BY id", (run_id,)
    ).fetchall()
    results = [{
        "id": r["test_id"], "category": r["category"], "title": r["title"],
        "passed": None if r["passed"] is None else bool(r["passed"]),
        "reason": r["reason"], "response": r["response"],
    } for r in rows]
    return jsonify({"run": lab_run_dict(run), "summary": summarise_results(results),
                    "results": results})


@app.route("/api/lab/runs/<int:run_id>", methods=["DELETE"])
@security.admin_required
@security.rate_limit("delete", 60, 60)
def api_lab_run_delete(run_id):
    db = get_db()
    db.execute("DELETE FROM lab_results WHERE run_id = ?", (run_id,))
    cursor = db.execute("DELETE FROM lab_runs WHERE id = ?", (run_id,))
    db.commit()
    if cursor.rowcount == 0:
        return jsonify({"error": "Run not found."}), 404
    return jsonify({"deleted": run_id})


init_db()

if __name__ == "__main__":
    # Debug mode exposes an interactive debugger: keep it off unless asked.
    app.run(debug=os.environ.get("FLASK_DEBUG") == "1")