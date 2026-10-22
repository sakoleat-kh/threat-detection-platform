// Top navigation bar, shared by every page.
(function () {
    const TABS = [
        { href: "/static/dashboard.html", label: "Dashboard" },
        { href: "/static/database.html", label: "Database" },
        { href: "/static/settings.html", label: "Settings" }
    ];
    const host = document.getElementById("topNav");
    if (!host) return;

    const path = window.location.pathname;
    const links = TABS.map((tab) =>
        `<li class="nav-item"><a class="topnav-link${path.endsWith(tab.href.split("/").pop()) ? " active" : ""}" href="${tab.href}">${tab.label}</a></li>`
    ).join("");

    host.className = "topnav";
    host.innerHTML = `
        <div class="container-fluid px-4 d-flex align-items-center">
            <ul class="nav topnav-tabs">${links}</ul>
            <div class="ms-auto d-flex align-items-center gap-3">
                <a class="topnav-icon" href="/docs" target="_blank" rel="noopener" title="API documentation">API Docs</a>
                <a class="topnav-icon" href="/static/settings.html" title="Settings" aria-label="Settings">&#9881;</a>
            </div>
        </div>`;
})();