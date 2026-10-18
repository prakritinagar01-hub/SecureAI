// AI Agent Safety Lab page.

let meta = null;
let labChart = null;

const PRESET_NOTE = "\n\n[Added automatically: an internal reference and a fake secret code the agent must protect]";

function selectedPrompt() {
    const preset = document.getElementById("presetSelect").value;
    if (preset === "custom") {
        return document.getElementById("customPrompt").value || meta.presets.custom;
    }
    return meta.presets[preset];
}

function updatePreview() {
    const preset = document.getElementById("presetSelect").value;
    document.getElementById("customWrap").hidden = preset !== "custom";
    document.getElementById("promptPreview").textContent = selectedPrompt() + PRESET_NOTE;
}

function drawLabChart(summary) {
    const cats = summary.categories;
    if (labChart) labChart.destroy();

    labChart = new Chart(document.getElementById("labChart"), {
        type: "bar",
        data: {
            labels: cats.map(function (c) { return c.category + " (" + c.passed + "/" + c.total + ")"; }),
            datasets: [{
                label: "Pass rate %",
                data: cats.map(function (c) { return Math.round((c.passed / c.total) * 100); }),
                backgroundColor: cats.map(function (c) {
                    const rate = c.passed / c.total;
                    return rate >= 0.8 ? "#4ade80" : rate >= 0.5 ? "#fbbf24" : "#fb7185";
                }),
                borderRadius: 6
            }]
        },
        options: {
            indexAxis: "y",
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { min: 0, max: 100, ticks: { color: "#94a3b8" }, grid: { color: "#1e293b" } },
                y: { ticks: { color: "#cbd5e1" }, grid: { display: false } }
            }
        }
    });
}

function buildResult(r) {
    const article = document.createElement("article");
    const state = r.passed === null ? "skip" : r.passed ? "pass" : "fail";
    article.className = "report-item " + state;

    const head = document.createElement("div");
    head.className = "report-head";

    const title = document.createElement("h3");
    title.textContent = r.id + " · " + r.title;

    const badge = document.createElement("span");
    badge.className = "badge " + (state === "pass" ? "safe" : state === "fail" ? "high" : "");
    badge.textContent = state === "pass" ? "Passed" : state === "fail" ? "Failed" : "Not run";
    head.append(title, badge);

    const category = document.createElement("p");
    category.className = "report-meta";
    category.textContent = r.category;

    const reason = document.createElement("p");
    reason.textContent = r.reason;

    article.append(head, category, reason);

    if (r.response) {
        const reply = document.createElement("div");
        reply.className = "reply";
        reply.textContent = r.response;
        article.appendChild(reply);
    }
    return article;
}

function showResults(data, label) {
    const summary = data.summary;
    const rate = summary.total ? Math.round((summary.passed / summary.total) * 100) : 0;

    document.getElementById("resultSection").hidden = false;
    document.getElementById("resPassed").textContent = summary.passed + " / " + summary.total;
    document.getElementById("resRate").textContent = rate + "%";
    document.getElementById("resFailed").textContent = summary.total - summary.passed;
    document.getElementById("resMeta").textContent = label +
        (summary.errors ? " · " + summary.errors + " test(s) could not run" : "");

    drawLabChart(summary);

    const list = document.getElementById("resultList");
    list.replaceChildren();
    // Show failures first: they are what needs attention.
    data.results.slice().sort(function (a, b) {
        const rank = function (x) { return x.passed === false ? 0 : x.passed === null ? 1 : 2; };
        return rank(a) - rank(b);
    }).forEach(function (r) { list.appendChild(buildResult(r)); });
}

function describeRun(run) {
    const agent = (run.backend === "llm" || run.backend === "claude") ? "AI model (" + (run.model || "unknown") + ")" : "Simulated demo agent";
    return "Run #" + run.id + " · " + agent + " · " + run.preset + " prompt";
}

async function loadRuns() {
    const data = await fetchJSON("/api/lab/runs");
    const list = document.getElementById("runList");
    list.replaceChildren();

    if (!data.runs.length) {
        const empty = document.createElement("div");
        empty.className = "empty-state";
        empty.textContent = "No runs yet. Run the tests above.";
        list.appendChild(empty);
        return;
    }

    data.runs.forEach(function (run) {
        const rate = run.total ? Math.round((run.passed / run.total) * 100) : 0;

        const article = document.createElement("article");
        article.className = "report-item " + (rate >= 80 ? "pass" : rate >= 50 ? "" : "fail");

        const row = document.createElement("div");
        row.className = "run-row";

        const text = document.createElement("div");
        const title = document.createElement("h3");
        title.textContent = describeRun(run);
        const meta2 = document.createElement("p");
        meta2.className = "report-meta";
        meta2.textContent = run.passed + "/" + run.total + " passed (" + rate + "%) · " +
            formatServerTime(run.created_at);
        text.append(title, meta2);

        const buttons = document.createElement("div");
        const view = document.createElement("button");
        view.type = "button";
        view.className = "secondary-btn small-btn";
        view.textContent = "View";
        view.addEventListener("click", async function () {
            try {
                const detail = await fetchJSON("/api/lab/runs/" + run.id);
                showResults(detail, describeRun(run));
                document.getElementById("resultSection").scrollIntoView({ behavior: "smooth" });
            } catch (e) {
                document.getElementById("labError").textContent = e.message;
            }
        });

        const del = document.createElement("button");
        del.type = "button";
        del.className = "danger-btn small-btn";
        del.style.marginLeft = "8px";
        del.textContent = "Delete";
        del.addEventListener("click", async function () {
            if (!confirm("Delete run #" + run.id + "?")) return;
            try {
                await fetchJSON("/api/lab/runs/" + run.id, { method: "DELETE" });
                loadRuns();
            } catch (e) {
                document.getElementById("labError").textContent = e.message;
            }
        });

        buttons.append(view, del);
        row.append(text, buttons);
        article.appendChild(row);
        list.appendChild(article);
    });
}

async function runTests() {
    const button = document.getElementById("runButton");
    const error = document.getElementById("labError");
    const status = document.getElementById("labStatus");

    error.textContent = "";
    button.disabled = true;
    button.textContent = "Running tests...";
    status.textContent = "Sending " + meta.tests + " attacks to the agent. This can take up to a minute.";

    try {
        const preset = document.getElementById("presetSelect").value;
        const data = await fetchJSON("/api/lab/run", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                backend: document.getElementById("backendSelect").value,
                preset: preset,
                system_prompt: preset === "custom" ? document.getElementById("customPrompt").value : ""
            })
        });
        showResults(data, describeRun({
            id: data.run_id, backend: data.backend, preset: data.preset, model: meta.model
        }));
        loadRuns();
    } catch (e) {
        error.textContent = e.message;
    } finally {
        button.disabled = false;
        button.textContent = "Run all tests";
        status.textContent = "";
    }
}

async function init() {
    try {
        meta = await fetchJSON("/api/lab/meta");
    } catch (e) {
        document.getElementById("labError").textContent = e.message;
        return;
    }

    const select = document.getElementById("backendSelect");
    Object.keys(meta.backends).forEach(function (key) {
        const option = document.createElement("option");
        option.value = key;
        option.disabled = !meta.backends[key].available;
        option.textContent = meta.backends[key].label +
            (meta.backends[key].available ? "" : " (not available)");
        select.appendChild(option);
    });

    document.getElementById("customPrompt").value = meta.presets.custom;
    document.getElementById("presetSelect").addEventListener("change", updatePreview);
    document.getElementById("customPrompt").addEventListener("input", updatePreview);
    document.getElementById("runButton").addEventListener("click", runTests);

    updatePreview();
    loadRuns().catch(function () {});
}

init();