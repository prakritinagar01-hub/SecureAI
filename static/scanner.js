// Landing page: message + URL scanners and the small stats strip.

function displayResult(prefix, data) {
    const result = document.getElementById(prefix + "Result");
    const scoreElement = document.getElementById(prefix + "Score");
    const meter = document.getElementById(prefix + "Meter");
    const riskElement = document.getElementById(prefix + "Risk");
    const warningsElement = document.getElementById(prefix + "Warnings");

    const score = Number(data.score ?? 0);
    const risk = String(data.risk ?? "Unknown");
    const warnings = normalizeWarnings(data.warnings);
    const riskClass = getRiskClass(risk);

    scoreElement.textContent = "Risk Score: " + score + "/100";
    scoreElement.className = "score " + riskClass;

    meter.style.width = Math.max(0, Math.min(100, score)) + "%";
    meter.className = "meter-fill" +
        (riskClass === "high" ? " high-bg" : riskClass === "medium" ? " medium-bg" : "");

    riskElement.textContent = "Risk Level: " + risk;

    warningsElement.replaceChildren();
    (warnings.length ? warnings : ["No warnings returned by the scanner."]).forEach(function (text) {
        const li = document.createElement("li");
        li.textContent = text;
        warningsElement.appendChild(li);
    });

    result.style.display = "block";
    loadHeroStats();
}

async function loadHeroStats() {
    try {
        const stats = await fetchJSON("/api/stats");
        document.getElementById("heroTotal").textContent = stats.total;
        document.getElementById("heroHigh").textContent = stats.by_risk.High;
        document.getElementById("heroAvg").textContent = stats.average_score;
    } catch (e) {
        // The stats strip is optional; ignore failures.
    }
}

document.getElementById("messageForm").addEventListener("submit", async function (event) {
    event.preventDefault();

    const message = document.getElementById("message").value.trim();
    const button = document.getElementById("messageButton");
    const error = document.getElementById("messageError");

    error.textContent = "";

    if (!message) {
        error.textContent = "Please enter a message first.";
        return;
    }

    button.disabled = true;
    button.textContent = "Analysing...";

    try {
        const data = await fetchJSON("/analyse", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ message: message })
        });
        displayResult("message", data);
    } catch (errorObject) {
        error.textContent = errorObject.message ||
            "Could not analyse the message. Please try again.";
    } finally {
        button.disabled = false;
        button.textContent = "Analyse Message";
    }
});

document.getElementById("urlForm").addEventListener("submit", async function (event) {
    event.preventDefault();

    let url = document.getElementById("url").value.trim();
    const button = document.getElementById("urlButton");
    const error = document.getElementById("urlError");

    error.textContent = "";

    if (!url) {
        error.textContent = "Please enter a URL.";
        return;
    }

    if (!/^https?:\/\//i.test(url)) {
        url = "https://" + url;
    }

    let parsedURL;
    try {
        parsedURL = new URL(url);
    } catch {
        error.textContent = "Please enter a valid website URL.";
        return;
    }

    if (!["http:", "https:"].includes(parsedURL.protocol)) {
        error.textContent = "Only HTTP and HTTPS URLs are supported.";
        return;
    }

    button.disabled = true;
    button.textContent = "Checking...";

    try {
        const data = await fetchJSON("/analyse-url", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ url: url })
        });
        displayResult("url", data);
    } catch (errorObject) {
        error.textContent = errorObject.message ||
            "Could not check the URL. Please try again.";
    } finally {
        button.disabled = false;
        button.textContent = "Check URL";
    }
});

loadHeroStats();