
async function analyzeMessage() {
    const message = document.getElementById("message").value.trim();
    const result = document.getElementById("result");
    const loading = document.getElementById("loading");
    const button = document.getElementById("analyzeBtn");

    if (!message) {
        alert("Please enter a message first!");
        return;
    }

    loading.classList.remove("hidden");
    result.classList.add("hidden");
    button.disabled = true;

    try {
        const response = await fetch("/api/analyze", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ message })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Analysis failed");
        }

        result.textContent = data.analysis;
        const riskMatch = data.analysis.match(/Risk Level:\s*(High|Medium|Low)/i);
if (riskMatch) updateDashboard(riskMatch[1], "Message Scan");
        result.classList.remove("hidden");

    } catch (error) {
        result.textContent = "Error: " + error.message;
        result.classList.remove("hidden");

    } finally {
        loading.classList.add("hidden");
        button.disabled = false;
    }
}


// =====================================
// URL SECURITY SCANNER
// =====================================

async function scanURL() {

    const url = document.getElementById("urlInput").value.trim();

    const result = document.getElementById("urlResult");
    const loading = document.getElementById("urlLoading");
    const button = document.getElementById("urlBtn");

    if (!url) {
        alert("Please enter a URL!");
        return;
    }

    loading.classList.remove("hidden");
    result.classList.add("hidden");
    button.disabled = true;

    try {

        const response = await fetch("/api/scan-url", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ url: url })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "URL scan failed");
        }

        result.textContent =
            "URL: " + data.url + "\n\n" + data.analysis;
            const riskMatch = data.analysis.match(/Risk Level:\s*(High|Medium|Low)/i);

if (riskMatch) {
    updateDashboard(riskMatch[1], "URL Scan");
}

        result.classList.remove("hidden");

    } catch (error) {

        result.textContent = "Error: " + error.message;
        result.classList.remove("hidden");

    } finally {

        loading.classList.add("hidden");
        button.disabled = false;
    }
}


// =====================================
// AI SECURITY LAB
// =====================================

async function testAISecurity() {

    const prompt = document.getElementById("securityPrompt").value.trim();

    const result = document.getElementById("securityResult");
    const loading = document.getElementById("securityLoading");
    const button = document.getElementById("securityBtn");

    if (!prompt) {
        alert("Enter a prompt to test!");
        return;
    }

    loading.classList.remove("hidden");
    result.classList.add("hidden");
    button.disabled = true;

    try {

        const response = await fetch("/api/security-lab", {
            method: "POST",
            headers: {
                "Content-Type": "application/json"
            },
            body: JSON.stringify({ prompt: prompt })
        });

        const data = await response.json();

        if (!response.ok) {
            throw new Error(data.error || "Security test failed");
        }

        result.textContent = data.analysis;
        const riskMatch = data.analysis.match(/Risk Level:\s*(High|Medium|Low)/i);
        if (riskMatch) updateDashboard(riskMatch[1], "AI Security Test");
        result.classList.remove("hidden");

    } catch (error) {

        result.textContent = "Error: " + error.message;
        result.classList.remove("hidden");

    } finally {

        loading.classList.add("hidden");
        button.disabled = false;
    }
}

// =====================================
// SECUREAI DASHBOARD
// =====================================

let dashboardStats = {
    total: 0,
    high: 0,
    medium: 0,
    low: 0
};

function updateDashboard(riskLevel, scanType) {
    const risk = riskLevel.toLowerCase();

    dashboardStats.total++;

    if (risk.includes("high")) {
        dashboardStats.high++;
    } else if (risk.includes("medium")) {
        dashboardStats.medium++;
    } else {
        dashboardStats.low++;
    }

    document.getElementById("totalScans").textContent =
        dashboardStats.total;

    document.getElementById("highScans").textContent =
        dashboardStats.high;

    document.getElementById("mediumScans").textContent =
        dashboardStats.medium;

    document.getElementById("lowScans").textContent =
        dashboardStats.low;

    const activityList = document.getElementById("activityList");

    const activity = document.createElement("div");
    activity.className = "activity-item";

    activity.innerHTML = `
        <strong>${scanType}</strong>
        <span> — ${riskLevel} Risk</span>
        <small>${new Date().toLocaleTimeString()}</small>
    `;

    activityList.prepend(activity);
}

// =====================================
// SCAN HISTORY
// =====================================

async function loadScanHistory() {
    const historyList = document.getElementById("historyList");

    historyList.innerHTML = "<p>Loading scan history...</p>";

    try {
        const response = await fetch("/api/history");
        const data = await response.json();

        if (!response.ok || !data.success) {
            throw new Error("Unable to load scan history");
        }

        if (data.history.length === 0) {
            historyList.innerHTML =
                '<p class="history-empty">No scans found yet.</p>';
            return;
        }

        const rows = data.history.map(scan => {
            const risk = (scan.risk_level || "Unknown").toLowerCase();

            const riskClass = ["high", "medium", "low"].includes(risk)
                ? `risk-${risk}`
                : "";

            const safeInput = escapeHTML(scan.scanned_input || "");
            const safeType = escapeHTML(scan.scan_type || "");
            const safeDate = escapeHTML(scan.created_at || "");
            const safeRisk = escapeHTML(scan.risk_level || "Unknown");

            return `
                <tr>
                    <td>${scan.id}</td>
                    <td>${safeType}</td>
                    <td title="${safeInput}">${safeInput.slice(0, 35)}${safeInput.length > 35 ? "..." : ""}</td>
                    <td><span class="risk-badge ${riskClass}">${safeRisk}</span></td>
                    <td>${Number(scan.risk_score) || 0}</td>
                    <td>${safeDate}</td>
                </tr>
            `;
        }).join("");

        historyList.innerHTML = `
            <div class="history-table-wrapper">
                <table class="history-table">
                    <thead>
                        <tr>
                            <th>ID</th>
                            <th>Type</th>
                            <th>Input</th>
                            <th>Risk</th>
                            <th>Score</th>
                            <th>Date</th>
                        </tr>
                    </thead>
                    <tbody>${rows}</tbody>
                </table>
            </div>
        `;

    } catch (error) {
        historyList.innerHTML =
            `<p class="history-empty">${escapeHTML(error.message)}</p>`;
    }
}

// Safely display untrusted database text
function escapeHTML(value) {
    return String(value).replace(/[&<>"']/g, character => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
    })[character]);
}

// Load history when page opens
document.addEventListener("DOMContentLoaded", loadScanHistory);

// =====================================
// LOAD PERSISTENT DASHBOARD STATISTICS
// =====================================

async function loadDashboardStats() {
    try {
        const response = await fetch("/api/dashboard-stats");
        const data = await response.json();

        if (!response.ok || !data.success) {
            throw new Error("Unable to load dashboard statistics");
        }

        document.getElementById("totalScans").textContent = data.total;
        document.getElementById("highScans").textContent = data.high;
        document.getElementById("mediumScans").textContent = data.medium;
        document.getElementById("lowScans").textContent = data.low;

    } catch (error) {
        console.error("Dashboard statistics error:", error);
    }
}

document.addEventListener("DOMContentLoaded", loadDashboardStats);