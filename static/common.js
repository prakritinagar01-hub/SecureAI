// Helpers shared by the landing page and the dashboard.

function getRiskClass(risk) {
    const value = String(risk || "").toLowerCase();
    if (value.includes("high") || value.includes("critical")) return "high";
    if (value.includes("medium") || value.includes("moderate")) return "medium";
    return "safe";
}

function normalizeWarnings(warnings) {
    if (Array.isArray(warnings)) return warnings.map(String);
    if (warnings === null || warnings === undefined || warnings === "") return [];
    return [String(warnings)];
}

// Server times are stored in UTC as "YYYY-MM-DD HH:MM:SS".
function formatServerTime(value) {
    const date = new Date(String(value).replace(" ", "T") + "Z");
    return isNaN(date) ? String(value) : date.toLocaleString();
}

async function fetchJSON(url, options) {
    const response = await fetch(url, options);
    const data = await response.json();
    if (!response.ok) {
        throw new Error(data.error || "Request failed.");
    }
    return data;
}