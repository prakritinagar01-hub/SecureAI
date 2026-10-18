import csv
import io
import ipaddress
import json
import os
import sqlite3
from datetime import datetime, timedelta, timezone
from urllib.parse import urlparse

from flask import (
    Flask, Response, g, jsonify, render_template, request
)

app = Flask(__name__)

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.environ.get("SECUREAI_DB", os.path.join(BASE_DIR, "secureai.db"))


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


def now_utc():
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def save_scan(scan_type, input_text, result):
    """Store a finished scan. Empty / invalid inputs are not saved."""
    if result["risk"] == "Unknown":
        return None

    db = get_db()
    cursor = db.execute(
        "INSERT INTO scans (scan_type, input_text, score, risk, warnings, created_at)"
        " VALUES (?, ?, ?, ?, ?, ?)",
        (
            scan_type,
            input_text,
            result["score"],
            result["risk"],
            json.dumps(result["warnings"]),
            now_utc(),
        ),
    )
    db.commit()
    return cursor.lastrowid


def row_to_dict(row):
    return {
        "id": row["id"],
        "type": row["scan_type"],
        "input": row["input_text"],
        "score": row["score"],
        "risk": row["risk"],
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
def dashboard():
    return render_template("dashboard.html", active="dashboard")


@app.route("/awareness")
def awareness():
    return render_template("awareness.html", active="awareness")


# ---------------------------------------------------------------------------
# Scanner routes (same URLs and request/response shape as before;
# the response now also includes the saved report "id")
# ---------------------------------------------------------------------------

@app.route("/analyse", methods=["POST"])
def analyse():
    data = request.get_json(silent=True) or {}
    message = str(data.get("message", ""))[:5000]
    result = analyse_message(message)
    result["id"] = save_scan("Message", message.strip(), result)
    return jsonify(result)


@app.route("/analyse-url", methods=["POST"])
def analyse_url_route():
    data = request.get_json(silent=True) or {}
    url = str(data.get("url", ""))[:2048]
    result = analyse_url(url)
    result["id"] = save_scan("URL", url.strip(), result)
    return jsonify(result)


# ---------------------------------------------------------------------------
# History / dashboard API
# ---------------------------------------------------------------------------

@app.route("/api/history")
def api_history():
    return jsonify({"reports": fetch_history(request.args, limit=500)})


@app.route("/api/stats")
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
        "daily": [{"day": d, "count": c} for d, c in counts.items()],
    })


@app.route("/api/history/<int:report_id>", methods=["DELETE"])
def api_delete_report(report_id):
    db = get_db()
    cursor = db.execute("DELETE FROM scans WHERE id = ?", (report_id,))
    db.commit()
    if cursor.rowcount == 0:
        return jsonify({"error": "Report not found."}), 404
    return jsonify({"deleted": report_id})


@app.route("/api/history/clear", methods=["POST"])
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
def download_csv():
    reports = fetch_history(request.args)

    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(
        ["ID", "Type", "Scanned item", "Risk score", "Risk level",
         "Warnings", "Scanned at (UTC)"]
    )
    for r in reports:
        writer.writerow([
            r["id"], r["type"], csv_safe(r["input"]), r["score"], r["risk"],
            csv_safe(" | ".join(r["warnings"])), r["created_at"],
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
            f"Risk score : {r['score']}/100",
            f"Risk level : {r['risk']}",
            "Scanned item:",
            "  " + r["input"].replace("\n", "\n  "),
            "Warnings:",
        ]
        lines += ["  - " + w for w in r["warnings"]]
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


init_db()

if __name__ == "__main__":
    app.run(debug=True)