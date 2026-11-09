
function extractRiskLevel(analysis) {
    const riskLine = String(analysis || "")
        .split(/\r?\n/)
        .find(line => /Risk Level/i.test(line));

    const match = riskLine
        ? riskLine.match(/\b(High|Medium|Low)\b/i)
        : null;

    return match
        ? match[1].charAt(0).toUpperCase() +
          match[1].slice(1).toLowerCase()
        : "Unknown";
}

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
        latestScanReports.message = {
    type: "Message Scan",
    input: message,
    analysis: data.analysis
};

document.getElementById("messagePdfBtn").classList.remove("hidden");
        const riskLevel = extractRiskLevel(data.analysis);
if (riskLevel !== "Unknown") {
    updateDashboard(riskLevel, "Message Scan");
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

latestScanReports.url = {
    type: "URL Scan",
    input: url,
    analysis: data.analysis
};

document.getElementById("urlPdfBtn").classList.remove("hidden");
            const riskLevel = extractRiskLevel(data.analysis);

if (riskLevel !== "Unknown") {
    updateDashboard(riskLevel, "URL Scan");
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
        latestScanReports.security = {
    type: "AI Security Test",
    input: prompt,
    analysis: data.analysis
};

document.getElementById("securityPdfBtn").classList.remove("hidden");


        const riskLevel = extractRiskLevel(data.analysis);

if (riskLevel !== "Unknown") {
    updateDashboard(riskLevel, "AI Security Test");
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
// SECUREAI DASHBOARD
// =====================================

let dashboardStats = {
    total: 0,
    high: 0,
    medium: 0,
    low: 0
};
function updateDashboard(riskLevel, scanType) {

    const activityList = document.getElementById("activityList");

    const activity = document.createElement("div");
    activity.className = "activity-item";

    activity.innerHTML = `
        <strong>${scanType}</strong>
        <span> — ${riskLevel} Risk</span>
        <small>${new Date().toLocaleTimeString()}</small>
    `;

    activityList.prepend(activity);

    // Refresh actual database statistics and chart
    loadDashboardStats();

    // Refresh scan history
    loadScanHistory();
}
// =====================================
// SCAN HISTORY — SEARCH, FILTER & EXPORT
// =====================================

let allHistoryScans = [];

async function loadScanHistory() {
    const historyList = document.getElementById("historyList");

    historyList.innerHTML = "<p>Loading scan history...</p>";

    try {
        const response = await fetch("/api/history");
        const data = await response.json();

        if (!response.ok || !data.success) {
            throw new Error("Unable to load scan history");
        }

        allHistoryScans = data.history || [];
        renderRecentActivity();
        renderScanHistory();

    } catch (error) {
        historyList.innerHTML =
            `<p class="history-empty">${escapeHTML(error.message)}</p>`;
    }
}

// =====================================
// RECENT SECURITY ACTIVITY
// =====================================

function renderRecentActivity() {

    const activityList = document.getElementById("activityList");

    const recentScans = allHistoryScans.slice(0, 5);

    if (recentScans.length === 0) {
        activityList.innerHTML = "<p>No scans performed yet.</p>";
        return;
    }

    activityList.innerHTML = recentScans.map(scan => {

        const type = escapeHTML(scan.scan_type || "Security Scan");
        const risk = escapeHTML(scan.risk_level || "Unknown");
        const date = escapeHTML(scan.created_at || "");

        return `
            <div class="activity-item">
                <strong>${type}</strong>
                <span> — ${risk} Risk</span>
                <small>${date}</small>
            </div>
        `;

    }).join("");
}

// DISPLAY HISTORY
function renderScanHistory() {
    const historyList = document.getElementById("historyList");

    const searchValue =
        (document.getElementById("historySearch")?.value || "")
        .toLowerCase()
        .trim();

    const riskValue =
        document.getElementById("riskFilter")?.value || "all";

    const typeValue =
        document.getElementById("typeFilter")?.value || "all";

    const filteredScans = allHistoryScans.filter(scan => {

        const input = String(scan.scanned_input || "").toLowerCase();
        const type = String(scan.scan_type || "").toLowerCase();
        const risk = String(scan.risk_level || "Unknown").toLowerCase();

        const matchesSearch =
            input.includes(searchValue) || type.includes(searchValue);

        const matchesRisk =
            riskValue === "all" || risk === riskValue.toLowerCase();

        const matchesType =
            typeValue === "all" || type === typeValue.toLowerCase();
           return matchesSearch && matchesRisk && matchesType;
    });

    if (filteredScans.length === 0) {
        historyList.innerHTML =
            '<p class="history-empty">No matching scans found.</p>';
        return;
    }

    
const rows = filteredScans.map(scan => {
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
        <td>
            <input type="checkbox"
                   class="scan-select-checkbox"
                   value="${Number(scan.id) || 0}">
        </td>
        <td>${Number(scan.id) || 0}</td>
            <td>${safeType}</td>
            <td title="${safeInput}">
                ${safeInput.slice(0, 35)}${safeInput.length > 35 ? "..." : ""}
            </td>
            <td>
                <span class="risk-badge ${riskClass}">${safeRisk}</span>
            </td>
            <td>${Number(scan.risk_score) || 0}</td>
            <td>${safeDate}</td>
            <td>
                <button class="view-scan-btn"
        data-scan-id="${Number(scan.id) || 0}">
    View Details
</button>


<button class="old-scan-pdf-btn"
        data-scan-id="${Number(scan.id) || 0}">
    Download PDF
</button>
<button class="delete-scan-btn"
        data-scan-id="${Number(scan.id) || 0}">
    Delete
</button>
            </td>
        </tr>
    `;
}).join("");

   

    historyList.innerHTML = `
        <div class="history-table-wrapper">
            <table class="history-table">
                <thead>
                    <tr>
                        <th>
    <input type="checkbox" id="selectAllScans">
</th>
<th>ID</th>
                        <th>Type</th>
                        <th>Input</th>
                        <th>Risk</th>
                        <th>Score</th>
                        <th>Date</th>
                        <th>Action</th>
                    </tr>
                </thead>
                <tbody>${rows}</tbody>
            </table>
        </div>
        <p class="history-empty">
            Showing ${filteredScans.length} of ${allHistoryScans.length} scans
        </p>
    `;
}


// SAFELY DISPLAY UNTRUSTED DATABASE TEXT
function escapeHTML(value) {
    return String(value).replace(/[&<>"']/g, character => ({
        "&": "&amp;",
        "<": "&lt;",
        ">": "&gt;",
        '"': "&quot;",
        "'": "&#39;"
    })[character]);
}


// SEARCH AND FILTER EVENTS
document.addEventListener("DOMContentLoaded", () => {

    loadScanHistory();

    document.getElementById("historySearch")
        ?.addEventListener("input", renderScanHistory);

    document.getElementById("riskFilter")
        ?.addEventListener("change", renderScanHistory);

    document.getElementById("typeFilter")
        ?.addEventListener("change", renderScanHistory);

    document.getElementById("exportHistory")
        ?.addEventListener("click", exportScanHistory);
});


// EXPORT FILTERED HISTORY TO CSV
function exportScanHistory() {

    const searchValue =
        (document.getElementById("historySearch")?.value || "")
        .toLowerCase()
        .trim();

    const riskValue =
        document.getElementById("riskFilter")?.value || "all";

    const typeValue =
        document.getElementById("typeFilter")?.value || "all";

    const filteredScans = allHistoryScans.filter(scan => {

        const input = String(scan.scanned_input || "").toLowerCase();
        const type = String(scan.scan_type || "").toLowerCase();
        const risk = String(scan.risk_level || "Unknown").toLowerCase();

        return (
            (input.includes(searchValue) || type.includes(searchValue)) &&
            (riskValue === "all" || risk === riskValue.toLowerCase()) &&
            (typeValue === "all" || type === typeValue.toLowerCase())
        );
    });

    if (filteredScans.length === 0) {
        alert("No scan records available to export.");
        return;
    }

    const csvEscape = value => {
        let text = String(value ?? "");

        // Prevent spreadsheet formula injection
        if (/^[=+\-@\t\r]/.test(text)) {
            text = "'" + text;
        }

        return `"${text.replace(/"/g, '""')}"`;
    };

    const headers = [
        "ID",
        "Scan Type",
        "Scanned Input",
        "Risk Level",
        "Risk Score",
        "Date"
    ];

    const csvRows = filteredScans.map(scan => [
        scan.id,
        scan.scan_type,
        scan.scanned_input,
        scan.risk_level,
        scan.risk_score,
        scan.created_at
    ]);

    const csvContent = [
        headers,
        ...csvRows
    ].map(row => row.map(csvEscape).join(",")).join("\n");

    const blob = new Blob(["\uFEFF" + csvContent], {
        type: "text/csv;charset=utf-8;"
    });

    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");

    link.href = url;
    link.download = "SecureAI_Scan_History.csv";
    link.click();

    URL.revokeObjectURL(url);
}


// =====================================
// LOAD PERSISTENT DASHBOARD STATISTICS
// =====================================

// =====================================
// DASHBOARD ANALYTICS
// =====================================

let riskChart = null;

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
        
        console.log("Dashboard Data:", data);
        updateRiskChart(data);

    } catch (error) {
        console.error("Dashboard statistics error:", error);
    }
}



// CREATE RISK DISTRIBUTION CHART
function updateRiskChart(data) {

    const canvas = document.getElementById("riskChart");

    if (!canvas || typeof Chart === "undefined") {
        console.error("Chart.js or chart canvas not found.");
        return;
    }

    if (riskChart) {
        riskChart.destroy();
    }

    // CENTER TEXT PLUGIN
    const centerText = {
        id: "centerText",

        afterDraw(chart) {
            const { ctx, chartArea } = chart;

            if (!chartArea) return;

            const centerX = (chartArea.left + chartArea.right) / 2;
            const centerY = (chartArea.top + chartArea.bottom) / 2;

            ctx.save();

            ctx.textAlign = "center";
            ctx.textBaseline = "middle";

            ctx.font = "bold 28px Arial";
            ctx.fillStyle = "#182235";
            ctx.fillText(data.total, centerX, centerY - 10);

            ctx.font = "13px Arial";
            ctx.fillStyle = "#64748b";
            ctx.fillText("Total Scans", centerX, centerY + 18);

            ctx.restore();
        }
    };

    riskChart = new Chart(canvas, {
        type: "doughnut",

        data: {
            labels: ["High Risk", "Medium Risk", "Low Risk"],

            datasets: [{
                data: [
                    data.high,
                    data.medium,
                    data.low
                ],

                backgroundColor: [
                    "#ef4444",
                    "#f59e0b",
                    "#10b981"
                ],

                borderWidth: 0,
                hoverOffset: 10
            }]
        },

        options: {
            responsive: true,
            maintainAspectRatio: false,

            plugins: {
                legend: {
                    position: "bottom"
                }
            },

            cutout: "70%"
        },

        plugins: [centerText]
    });
}
// Load dashboard statistics when the page opens
loadDashboardStats();

// =====================================
// MOBILE SIDEBAR TOGGLE
// =====================================

const mobileMenuBtn = document.getElementById("mobileMenuBtn");
const sidebar = document.querySelector(".sidebar");

if (mobileMenuBtn && sidebar) {

    mobileMenuBtn.addEventListener("click", function () {

        sidebar.classList.toggle("active");

        mobileMenuBtn.textContent =
            sidebar.classList.contains("active") ? "✕" : "☰";

    });

    // Close sidebar after clicking a navigation link
    document.querySelectorAll(".sidebar-nav .nav-link").forEach(link => {

        link.addEventListener("click", function () {

            sidebar.classList.remove("active");
            mobileMenuBtn.textContent = "☰";

        });

    });

}

// =====================================
// DARK / LIGHT MODE TOGGLE
// =====================================

const themeToggleBtn = document.getElementById("themeToggle");

// Load previously saved theme
const savedTheme = localStorage.getItem("secureai-theme");

if (savedTheme === "dark") {
    document.body.classList.add("dark-mode");
}

// Set correct toggle icon
function updateThemeIcon() {
    if (document.body.classList.contains("dark-mode")) {
        themeToggleBtn.textContent = "☀️";
    } else {
        themeToggleBtn.textContent = "🌙";
    }
}

if (themeToggleBtn) {

    updateThemeIcon();

    themeToggleBtn.addEventListener("click", function () {

        document.body.classList.toggle("dark-mode");

        const isDark =
            document.body.classList.contains("dark-mode");

        localStorage.setItem(
            "secureai-theme",
            isDark ? "dark" : "light"
        );

        updateThemeIcon();

    });

}

// =====================================
// EXPORT SCAN HISTORY AS CSV
// =====================================

const exportHistoryBtn = document.getElementById("exportHistory");

if (exportHistoryBtn) {

    exportHistoryBtn.addEventListener("click", function () {

        if (!allHistoryScans || allHistoryScans.length === 0) {
            alert("No scan history available to export!");
            return;
        }

        const headers = [
            "ID",
            "Scan Type",
            "Scanned Input",
            "Risk Level",
            "Risk Score",
            "Analysis",
            "Date"
        ];

        const rows = allHistoryScans.map(scan => [
            scan.id,
            scan.scan_type,
            scan.scanned_input,
            scan.risk_level,
            scan.risk_score,
            scan.analysis,
            scan.created_at
        ]);

        function escapeCSV(value) {
            const text = String(value ?? "").replace(/"/g, '""');
            return `"${text}"`;
        }

        const csvContent = [
            headers,
            ...rows
        ].map(row => row.map(escapeCSV).join(",")).join("\n");

        const blob = new Blob(
            ["\uFEFF" + csvContent],
            { type: "text/csv;charset=utf-8;" }
        );

        const link = document.createElement("a");
        const url = URL.createObjectURL(blob);

        link.href = url;
        link.download = "SecureAI_Scan_History.csv";

        document.body.appendChild(link);
        link.click();

        document.body.removeChild(link);
        URL.revokeObjectURL(url);

    });

}

// =====================================
// SECUREAI PDF REPORT GENERATOR
// =====================================

const latestScanReports = {
    message: null,
    url: null,
    security: null
};

function downloadScanPDF(scanType) {

    const report = latestScanReports[scanType];

    if (!report) {
        alert("Please perform a scan before downloading the report.");
        return;
    }

    if (!window.jspdf) {
        alert("PDF library not loaded. Please refresh the page.");
        return;
    }

    const { jsPDF } = window.jspdf;
    const doc = new jsPDF();

    const pageWidth = doc.internal.pageSize.getWidth();
    const pageHeight = doc.internal.pageSize.getHeight();

    const margin = 18;
    const contentWidth = pageWidth - margin * 2;

    // Clean unsupported special characters
    function cleanText(value) {
        return String(value ?? "")
            .replace(/[^\x20-\x7E\n\r\t]/g, " ");
    }

    // Header
    doc.setFillColor(17, 24, 39);
    doc.rect(0, 0, pageWidth, 42, "F");

    doc.setTextColor(255, 255, 255);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(22);
    doc.text("SecureAI", margin, 19);

    doc.setFontSize(10);
    doc.setFont("helvetica", "normal");
    doc.text("SECURITY INTELLIGENCE REPORT", margin, 29);

    // Report information
    let y = 56;

    doc.setTextColor(30, 41, 59);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(15);
    doc.text("Scan Report", margin, y);

    y += 12;

    const details = [
        ["Scan Type", report.type],
        ["Scanned Input", report.input],
        ["Scan Date", new Date().toLocaleString()]
    ];

    doc.setFontSize(10);

    details.forEach(([label, value]) => {

        doc.setFont("helvetica", "bold");
        doc.text(label + ":", margin, y);

        doc.setFont("helvetica", "normal");

        const lines = doc.splitTextToSize(
            cleanText(value),
            contentWidth - 35
        );

        doc.text(lines, margin + 35, y);

        y += Math.max(8, lines.length * 5) + 3;
    });

   // RISK LEVEL

// RISK LEVEL

// RISK LEVEL
const riskLine = report.analysis
    .split(/\r?\n/)
    .find(line => /Risk Level/i.test(line));

const riskMatch = riskLine
    ? riskLine.match(/\b(High|Medium|Low)\b/i)
    : null;

const riskLevel = riskMatch
    ? riskMatch[1].charAt(0).toUpperCase() +
      riskMatch[1].slice(1).toLowerCase()
    : "Unknown";

const riskColors = {
    High: [239, 68, 68],
    Medium: [245, 158, 11],
    Low: [16, 185, 129],
    Unknown: [100, 116, 139]
};

// RISK SCORE
const scoreLine = report.analysis
    .split(/\r?\n/)
    .find(line => /Risk Score/i.test(line));

const scoreMatch = scoreLine
    ? scoreLine.match(/\b(\d+)\s*\/\s*100\b/i)
    : null;

const riskScore = scoreMatch
    ? Number(scoreMatch[1])
    : null;



// RISK BADGE
y += 5;

doc.setFillColor(...riskColors[riskLevel]);
doc.roundedRect(margin, y - 5, 48, 11, 3, 3, "F");

doc.setTextColor(255, 255, 255);
doc.setFont("helvetica", "bold");
doc.setFontSize(10);
doc.text(riskLevel.toUpperCase() + " RISK", margin + 5, y + 2);

// SCORE DISPLAY
if (riskScore !== null) {
    doc.setTextColor(30, 41, 59);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(11);
    doc.text(`Risk Score: ${riskScore}/100`, margin + 58, y + 2);
}

y += 15;

// EXECUTIVE SUMMARY
doc.setTextColor(30, 41, 59);
doc.setFont("helvetica", "bold");
doc.setFontSize(13);
doc.text("Executive Summary", margin, y);

y += 8;

doc.setFont("helvetica", "normal");
doc.setFontSize(10);
doc.setTextColor(71, 85, 105);

const summaryText =
    riskLevel === "High"
        ? "High-risk indicators detected. Avoid interacting with this content until it has been verified."
        : riskLevel === "Medium"
        ? "Some suspicious indicators were detected. Review the analysis carefully before taking action."
        : riskLevel === "Low"
        ? "No major risk indicators were detected. Continue following standard security precautions."
        : "Risk level could not be determined. Review the detailed analysis.";

const summaryLines = doc.splitTextToSize(summaryText, contentWidth);

doc.text(summaryLines, margin, y);

y += summaryLines.length * 5 + 8;
    

    y += 5;

    doc.setFont("helvetica", "bold");
    doc.setFontSize(13);
    doc.text("Security Analysis", margin, y);

    y += 9;

    doc.setDrawColor(115, 87, 237);
    doc.line(margin, y - 4, pageWidth - margin, y - 4);

    doc.setFont("helvetica", "normal");
    doc.setFontSize(10);
    doc.setTextColor(55, 65, 81);

    const analysisLines = doc.splitTextToSize(
        cleanText(report.analysis),
        contentWidth
    );

    analysisLines.forEach(line => {

        if (y > pageHeight - 22) {
            doc.addPage();
            y = 20;
        }

        doc.text(line, margin, y);
        y += 5;

    });

    // Footer
    const pageCount = doc.internal.getNumberOfPages();

    for (let i = 1; i <= pageCount; i++) {

        doc.setPage(i);

        doc.setFontSize(8);
        doc.setTextColor(130, 140, 155);

        doc.text(
            "Generated by SecureAI | AI Security Assistant",
            margin,
            pageHeight - 10
        );

        doc.text(
            `Page ${i} of ${pageCount}`,
            pageWidth - margin,
            pageHeight - 10,
            { align: "right" }
        );
    }

    doc.save(`SecureAI_${scanType}_Report.pdf`);
}

// VIEW OLD SCAN DETAILS
document.addEventListener("click", function (event) {

    const button = event.target.closest(".view-scan-btn");

if (!button) return;

    const scanId = Number(button.dataset.scanId);

    const scan = allHistoryScans.find(
        item => Number(item.id) === scanId
    );

    if (!scan) {
        alert("Scan details not found!");
        return;
    }

    document.getElementById("detailId").textContent = scan.id;
    document.getElementById("detailType").textContent = scan.scan_type || "Unknown";
    document.getElementById("detailRisk").textContent = scan.risk_level || "Unknown";
    document.getElementById("detailScore").textContent = (scan.risk_score || 0) + "/100";
    document.getElementById("detailDate").textContent = scan.created_at || "Unknown";

    document.getElementById("detailInput").textContent =
        scan.scanned_input || "No input available";

    document.getElementById("detailAnalysis").textContent =
        scan.analysis || "No analysis available";

    document.getElementById("scanDetailsModal").classList.remove("hidden");
});

// CLOSE SCAN DETAILS MODAL
document.addEventListener("click", function (event) {
    const closeButton = event.target.closest("#closeScanModal");
    const modal = document.getElementById("scanDetailsModal");

    if (!modal) return;

    if (closeButton || event.target === modal) {
        modal.classList.add("hidden");
    }
});

document.addEventListener("keydown", function (event) {
    if (event.key === "Escape") {
        const modal = document.getElementById("scanDetailsModal");

        if (modal) {
            modal.classList.add("hidden");
        }
    }
});

// =====================================
// DELETE INDIVIDUAL SCAN
// =====================================

document.addEventListener("click", async function (event) {

    const button = event.target.closest(
    ".delete-scan-btn:not(#bulkDeleteBtn)"
);

if (!button) return;

    const scanId = button.dataset.scanId;

    if (!confirm("Are you sure you want to delete this scan?")) {
        return;
    }

    button.disabled = true;
    button.textContent = "Deleting...";

    try {

        const response = await fetch(`/api/delete-scan/${scanId}`, {
            method: "DELETE"
        });

        const contentType = response.headers.get("content-type") || "";

if (!contentType.includes("application/json")) {
    const errorText = await response.text();
    console.error("Non-JSON response:", response.status, errorText);
    throw new Error(`Server returned HTML instead of JSON (Status: ${response.status})`);
}

const data = await response.json();

        if (!response.ok || !data.success) {
            throw new Error(data.error || "Unable to delete scan");
        }

        alert("Scan deleted successfully!");

        await loadScanHistory();
        await loadDashboardStats();

    } catch (error) {

        alert("Delete failed: " + error.message);

        button.disabled = false;
        button.textContent = "Delete";
    }

});

// =====================================
// BULK DELETE SCANS
// =====================================

document.addEventListener("change", function (event) {

    // SELECT ALL CHECKBOX
    if (event.target.id === "selectAllScans") {

        document.querySelectorAll(".scan-select-checkbox")
            .forEach(checkbox => {
                checkbox.checked = event.target.checked;
            });
    }

    // UPDATE SELECT ALL STATUS
    if (event.target.classList.contains("scan-select-checkbox")) {

        const checkboxes = document.querySelectorAll(".scan-select-checkbox");
        const checked = document.querySelectorAll(".scan-select-checkbox:checked");

        const selectAll = document.getElementById("selectAllScans");

        if (selectAll) {
            selectAll.checked =
                checkboxes.length > 0 &&
                checkboxes.length === checked.length;
        }
    }
});

// =====================================
// DELETE SELECTED SCANS
// =====================================

document.addEventListener("click", async function (event) {

    if (event.target.id !== "bulkDeleteBtn") return;

    const selectedCheckboxes = document.querySelectorAll(
        ".scan-select-checkbox:checked"
    );

    const selectedIds = Array.from(selectedCheckboxes)
        .map(checkbox => checkbox.value);

    if (selectedIds.length === 0) {
        alert("Please select at least one scan!");
        return;
    }

    const confirmed = confirm(
        `Are you sure you want to delete ${selectedIds.length} scans?`
    );

    if (!confirmed) return;

    const button = event.target;
    button.disabled = true;
    button.textContent = "Deleting...";

    try {

        const results = await Promise.all(
            selectedIds.map(id =>
                fetch(`/api/delete-scan/${id}`, {
                    method: "DELETE"
                }).then(async response => {
                    const data = await response.json();

                    if (!response.ok || !data.success) {
                        throw new Error(data.error || `Failed to delete scan ${id}`);
                    }

                    return data;
                })
            )
        );

        alert(`${results.length} scans deleted successfully!`);

        await loadScanHistory();
        await loadDashboardStats();

    } catch (error) {

        alert("Some scans could not be deleted: " + error.message);

        await loadScanHistory();

    } finally {

        button.disabled = false;
        button.textContent = "Delete Selected";

    }

});