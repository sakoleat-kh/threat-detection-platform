const $ = (id) => document.getElementById(id);

// ----- Appearance -----
function showTheme() {
    const theme = window.TDPTheme ? window.TDPTheme.get() : "light";
    $("themeLight").checked = theme === "light";
    $("themeDark").checked = theme === "dark";
}

for (const id of ["themeLight", "themeDark"]) {
    $(id).addEventListener("change", () => {
        if ($(id).checked) window.TDPTheme.set($(id).value);
    });
}

// ----- System status (GET /health and GET /stats/) -----
async function loadStatus() {
    $("statusApi").textContent = "Checking...";
    $("statusError").classList.add("d-none");
    try {
        const health = await fetch("/health");
        if (!health.ok) throw new Error(`HTTP ${health.status}`);
        const body = await health.json();
        $("statusApi").textContent = body.status === "ok" ? "Running (ok)" : String(body.status);

        const response = await fetch("/stats/");
        if (!response.ok) throw new Error(`HTTP ${response.status}`);
        const stats = await response.json();
        const byRule = stats.by_rule ?? {};
        $("statusAlerts").textContent = Object.values(byRule).reduce((sum, n) => sum + n, 0);
        $("statusRules").textContent = Object.keys(byRule).length;
    } catch (error) {
        console.error("Failed to load status:", error);
        $("statusApi").textContent = "Not reachable";
        $("statusError").textContent = "Failed to load system status. Check that the API is running.";
        $("statusError").classList.remove("d-none");
    }
}

$("statusRefresh").addEventListener("click", loadStatus);
showTheme();
loadStatus();