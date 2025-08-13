const API_KEY = "022d22f6ec1e133bcef1a890b563714f141aae6597f660ec654fe51d22572948";

const scanBtn = document.getElementById("scanBtn");
const urlInput = document.getElementById("urlInput");
const statusEl = document.getElementById("status");
const loader = document.getElementById("loader");
const resultsCard = document.getElementById("resultsCard");
const resultsTbody = document.querySelector("#resultsTable tbody");
const rawCard = document.getElementById("rawCard");
const rawJson = document.getElementById("rawJson");
const summary = document.getElementById("summary");
const statsEl = document.getElementById("stats");

function setStatus(text, color) {
    statusEl.textContent = text;
    statusEl.style.color = color || "";
}

function show(el, show = true) {
    if (show) el.classList.remove("hidden");
    else el.classList.add("hidden");
}

async function submitUrlForScan(url, key) {
    const body = new URLSearchParams({ url });
    const res = await fetch("https://www.virustotal.com/api/v3/urls", {
        method: "POST",
        headers: {
            "x-apikey": key,
            "Content-Type": "application/x-www-form-urlencoded"
        },
        body: body.toString()
    });
    if (!res.ok) {
        const txt = await res.text();
        throw new Error(`POST /urls failed: ${res.status} ${txt}`);
    }
    return res.json();
}

async function getAnalysis(analysisId, key) {
    const res = await fetch(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, {
        headers: { "x-apikey": key }
    });
    if (!res.ok) {
        const txt = await res.text();
        throw new Error(`GET /analyses failed: ${res.status} ${txt}`);
    }
    return res.json();
}

function renderStats(stats) {
    const parts = [];
    for (const k of ["malicious", "suspicious", "harmless", "undetected"]) {
        if (stats[k] !== undefined) parts.push(`<strong>${k}:</strong> ${stats[k]}`);
    }
    statsEl.innerHTML = parts.join(" • ");
    show(summary, true);
}

function renderEngineResults(resultObj) {
    resultsTbody.innerHTML = "";
    const entries = Object.entries(resultObj || {});
    if (entries.length === 0) {
        resultsTbody.innerHTML = `<tr><td colspan="3" style="color:gray">No engine results available yet.</td></tr>`;
    } else {
        for (const [engine, data] of entries) {
            const category = data.category || "undetected";
            const result = data.result || "";
            const version = data.engine_version || "";

            let cssClass = category;
            if (!["malicious", "suspicious", "harmless"].includes(cssClass)) {
                cssClass = "";
            }

            const row = document.createElement("tr");
            row.innerHTML = `
                <td>${engine}</td>
                <td class="${cssClass}">${result || category} <small style="color:gray">(${category})</small></td>
                <td>${version}</td>
            `;
            resultsTbody.appendChild(row);
        }
    }
    show(resultsCard, true);
}

scanBtn.addEventListener("click", async () => {
    const key = API_KEY;
    if (!key) {
        alert("API key is required for scanning.");
        return;
    }

    const url = urlInput.value.trim();
    if (!url) {
        alert("Enter a URL first.");
        return;
    }

    setStatus("Submitting URL...", "gray");
    loader.classList.remove("hidden");
    show(resultsCard, false);
    show(rawCard, false);
    show(summary, false);
    resultsTbody.innerHTML = "";
    rawJson.textContent = "";

    try {
        const postResp = await submitUrlForScan(url, key);
        const analysisId = postResp.data && postResp.data.id;
        if (!analysisId) throw new Error("No analysis id returned from POST /urls");

        setStatus("Scan submitted. Polling for results...", "gray");

        let attempt = 0, analysisJson = null;
        while (attempt < 20) {
            attempt++;
            setStatus(`Polling results (attempt ${attempt}/20)...`, "gray");
            try {
                analysisJson = await getAnalysis(analysisId, key);
            } catch (e) {
                console.warn("analysis fetch error", e);
            }
            if (analysisJson?.data?.attributes?.status === "completed" || analysisJson?.data?.attributes?.stats) {
                break;
            }
            await new Promise(r => setTimeout(r, 3000));
        }

        if (!analysisJson) throw new Error("No analysis returned. Try again later.");

        const attrs = analysisJson.data.attributes;
        if (attrs.stats) renderStats(attrs.stats);
        if (attrs.results) renderEngineResults(attrs.results);
        else {
            resultsTbody.innerHTML = `<tr><td colspan="3" style="color:gray">No per-engine results returned.</td></tr>`;
            show(resultsCard, true);
        }

        rawJson.textContent = JSON.stringify(analysisJson, null, 2);
        show(rawCard, true);

        setStatus("✅ Scan complete.", "green");
    } catch (err) {
        console.error(err);
        setStatus("❌ Error: " + (err.message || err), "red");
        alert("Scan error: " + (err.message || err));
    } finally {
        loader.classList.add("hidden");
    }
});
