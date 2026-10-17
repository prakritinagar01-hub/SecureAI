

from flask import Flask, request, jsonify, render_template

app = Flask(__name__)


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
