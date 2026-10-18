// Helpers shared by all pages.

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

function csrfToken() {
    const meta = document.querySelector('meta[name="csrf-token"]');
    return meta ? meta.content : "";
}

async function fetchJSON(url, options) {
    const opts = Object.assign({ credentials: "same-origin" }, options || {});
    const method = (opts.method || "GET").toUpperCase();

    if (method !== "GET") {
        opts.headers = Object.assign({ "X-CSRF-Token": csrfToken() }, opts.headers || {});
    }

    const response = await fetch(url, opts);

    if (response.status === 401) {
        window.location.href = "/login?next=" + encodeURIComponent(window.location.pathname);
        throw new Error("Login required.");
    }

    let data = {};
    try {
        data = await response.json();
    } catch (e) {
        // Non-JSON error page
    }

    if (!response.ok) {
        throw new Error(data.error || "Request failed (" + response.status + ").");
    }
    return data;
}

function makeChip(text) {
    const chip = document.createElement("span");
    chip.className = "chip" + (text === "Prompt injection attempt" ? " injection" : "");
    chip.textContent = text;
    return chip;
}