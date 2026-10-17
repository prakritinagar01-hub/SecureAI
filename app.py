

from flask import Flask, request, jsonify, render_template

app = Flask(__name__)

def analyse_message(message):
    message = message.lower()
    score = 0
    warnings = []

    if "urgent" in message or "immediately" in message:
        score += 20
        warnings.append("Urgent language detected")

    if "password" in message or "otp" in message:
        score += 20
        warnings.append("Sensitive information mentioned")

    if "click here" in message or "verify your account" in message:
        score += 25
        warnings.append("Suspicious link or verification request")

    if "won a prize" in message or "claim reward" in message:
        score += 20
        warnings.append("Possible fake prize message")

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



from urllib.parse import urlparse
import ipaddress

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


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyse", methods=["POST"])
def analyse():
    data = request.get_json(silent=True) or {}
    message = str(data.get("message", ""))[:5000]
    result = analyse_message(message)
    return jsonify(result)



@app.route("/analyse-url", methods=["POST"])
def analyse_url_route():
    data = request.get_json(silent=True) or {}
    url = str(data.get("url", ""))[:2048]
    return jsonify(analyse_url(url))

if __name__ == "__main__":
    app.run(debug=True)
