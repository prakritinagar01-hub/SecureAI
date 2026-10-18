// Dashboard: stats, charts, searchable history, downloads.

const COLORS = { High: "#fb7185", Medium: "#fbbf24", Low: "#4ade80" };

let riskChart = null;
let dailyChart = null;
let categoryChart = null;
let searchTimer = null;

function currentFilters() {
    const params = new URLSearchParams();
    const q = document.getElementById("searchInput").value.trim();
    const type = document.getElementById("typeFilter").value;
    const risk = document.getElementById("riskFilter").value;
    const category = document.getElementById("categoryFilter").value;
    if (category) params.set("category", category);
    if (q) params.set("q", q);
    if (type) params.set("type", type);
    if (risk) params.set("risk", risk);
    return params;
}

function updateDownloadLinks() {
    const query = currentFilters().toString();
    const suffix = query ? "?" + query : "";
    document.getElementById("downloadCsv").href = "/download/csv" + suffix;
    document.getElementById("downloadTxt").href = "/download/txt" + suffix;
}

/* ---------- Stats and charts ---------- */

function drawCharts(stats) {
    const risk = stats.by_risk;
    const total = risk.High + risk.Medium + risk.Low;
    document.getElementById("riskEmpty").hidden = total > 0;

    if (riskChart) riskChart.destroy();
    riskChart = new Chart(document.getElementById("riskChart"), {
        type: "doughnut",
        data: {
            labels: ["High", "Medium", "Low"],
            datasets: [{
                data: [risk.High, risk.Medium, risk.Low],
                backgroundColor: [COLORS.High, COLORS.Medium, COLORS.Low],
                borderColor: "#101827",
                borderWidth: 3
            }]
        },
        options: {
            maintainAspectRatio: false,
            cutout: "62%",
            plugins: { legend: { position: "bottom", labels: { color: "#cbd5e1" } } }
        }
    });

    const cats = stats.by_category || [];
    document.getElementById("categoryEmpty").hidden = cats.length > 0;
    if (categoryChart) categoryChart.destroy();
    categoryChart = new Chart(document.getElementById("categoryChart"), {
        type: "bar",
        data: {
            labels: cats.map(function (c) { return c.category; }),
            datasets: [{
                label: "Scans",
                data: cats.map(function (c) { return c.count; }),
                backgroundColor: cats.map(function (c) {
                    return c.category === "Prompt injection attempt" ? "#fbbf24" : "#67e8f9";
                }),
                borderRadius: 6
            }]
        },
        options: {
            indexAxis: "y",
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { beginAtZero: true, ticks: { color: "#94a3b8", precision: 0 }, grid: { color: "#1e293b" } },
                y: { ticks: { color: "#cbd5e1" }, grid: { display: false } }
            }
        }
    });

    if (dailyChart) dailyChart.destroy();
    dailyChart = new Chart(document.getElementById("dailyChart"), {
        type: "bar",
        data: {
            labels: stats.daily.map(function (d) { return d.day.slice(5); }),
            datasets: [{
                label: "Scans",
                data: stats.daily.map(function (d) { return d.count; }),
                backgroundColor: "#67e8f9",
                borderRadius: 6
            }]
        },
        options: {
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { ticks: { color: "#94a3b8" }, grid: { display: false } },
                y: {
                    beginAtZero: true,
                    ticks: { color: "#94a3b8", precision: 0 },
                    grid: { color: "#1e293b" }
                }
            }
        }
    });
}

async function loadStats() {
    const stats = await fetchJSON("/api/stats");
    document.getElementById("statTotal").textContent = stats.total;
    document.getElementById("statHigh").textContent = stats.by_risk.High;
    document.getElementById("statInjection").textContent = stats.injection_attempts;
    document.getElementById("statAvg").textContent = stats.average_score;
    drawCharts(stats);
}

/* ---------- History ---------- */

function buildReport(report) {
    const riskClass = getRiskClass(report.risk);

    const article = document.createElement("article");
    article.className = "report-item risk-" + (riskClass === "safe" ? "low" : riskClass);

    const head = document.createElement("div");
    head.className = "report-head";

    const title = document.createElement("h3");
    title.textContent = "#" + report.id + " · " + report.type + " scan";

    const right = document.createElement("div");
    const badge = document.createElement("span");
    badge.className = "badge " + riskClass;
    badge.textContent = report.risk + " · " + report.score + "/100";

    const del = document.createElement("button");
    del.type = "button";
    del.className = "danger-btn small-btn";
    del.style.marginLeft = "10px";
    del.textContent = "Delete";
    del.addEventListener("click", function () { deleteReport(report.id); });

    right.append(badge, del);
    head.append(title, right);

    const scanned = document.createElement("p");
    scanned.className = "report-input";
    scanned.textContent = report.input;

    const chips = document.createElement("div");
    chips.className = "chips";
    report.categories.forEach(function (name) { chips.appendChild(makeChip(name)); });

    const warnings = document.createElement("p");
    warnings.textContent = "Warnings: " + report.warnings.join(", ");

    const aiLine = document.createElement("p");
    if (report.ai) {
        aiLine.textContent = "AI (" + report.ai.score + "/100): " + (report.ai.summary || report.ai.risk) +
            " · rules: " + report.rule_score + "/100";
    }

    const time = document.createElement("p");
    time.className = "report-meta";
    time.textContent = "Scanned: " + formatServerTime(report.created_at);

    article.append(head, scanned);
    if (report.categories.length) article.appendChild(chips);
    article.appendChild(warnings);
    if (report.ai) article.appendChild(aiLine);
    article.appendChild(time);
    return article;
}

async function loadHistory() {
    updateDownloadLinks();

    const list = document.getElementById("reportList");
    const count = document.getElementById("reportCount");
    const filtered = currentFilters().toString() !== "";

    const data = await fetchJSON("/api/history?" + currentFilters().toString());
    const reports = data.reports;

    count.textContent = reports.length +
        (reports.length === 1 ? " report" : " reports") +
        (filtered ? " match your filters" : " saved");

    list.replaceChildren();

    if (reports.length === 0) {
        const empty = document.createElement("div");
        empty.className = "empty-state";
        empty.textContent = filtered
            ? "No reports match these filters."
            : "No reports yet. Scan a message or URL first.";
        list.appendChild(empty);
        return;
    }

    reports.forEach(function (report) { list.appendChild(buildReport(report)); });
}

async function refreshAll() {
    try {
        await Promise.all([loadStats(), loadHistory()]);
    } catch (error) {
        document.getElementById("reportCount").textContent =
            "Could not load reports: " + error.message;
    }
}

async function deleteReport(id) {
    if (!confirm("Delete report #" + id + "?")) return;
    try {
        await fetchJSON("/api/history/" + id, { method: "DELETE" });
        refreshAll();
    } catch (error) {
        alert(error.message);
    }
}

document.getElementById("clearButton").addEventListener("click", async function () {
    if (!confirm("Delete ALL saved reports? This cannot be undone.")) return;
    try {
        await fetchJSON("/api/history/clear", { method: "POST" });
        refreshAll();
    } catch (error) {
        alert(error.message);
    }
});

document.getElementById("searchInput").addEventListener("input", function () {
    clearTimeout(searchTimer);
    searchTimer = setTimeout(loadHistory, 250);
});

["typeFilter", "riskFilter", "categoryFilter"].forEach(function (id) {
    document.getElementById(id).addEventListener("change", loadHistory);
});

document.getElementById("resetFilters").addEventListener("click", function () {
    document.getElementById("searchInput").value = "";
    document.getElementById("typeFilter").value = "";
    document.getElementById("riskFilter").value = "";
    document.getElementById("categoryFilter").value = "";
    loadHistory();
});

refreshAll();