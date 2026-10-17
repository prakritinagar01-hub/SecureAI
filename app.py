

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


@app.route("/")
def home():
    return render_template("index.html")


@app.route("/analyse", methods=["POST"])
def analyse():
    data = request.get_json(silent=True) or {}
    message = str(data.get("message", ""))[:5000]
    result = analyse_message(message)
    return jsonify(result)


if __name__ == "__main__":
    app.run(debug=True)
