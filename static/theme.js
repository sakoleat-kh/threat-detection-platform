// Dark / light theme. The choice is remembered in the browser.
// The Settings page changes it with window.TDPTheme.set("dark" | "light").
(function () {
    const KEY = "tdp-theme";

    function stored() {
        try { return localStorage.getItem(KEY); } catch { return null; }
    }
    function save(theme) {
        try { localStorage.setItem(KEY, theme); } catch { /* storage unavailable */ }
    }
    function current() {
        return document.documentElement.getAttribute("data-bs-theme") === "dark" ? "dark" : "light";
    }
    function apply(theme, notify) {
        document.documentElement.setAttribute("data-bs-theme", theme);
        if (notify) document.dispatchEvent(new CustomEvent("themechange", { detail: theme }));
    }

    apply(stored() === "dark" ? "dark" : "light", false);    // before the page is drawn

    window.TDPTheme = {
        get: current,
        set(theme) {
            const next = theme === "dark" ? "dark" : "light";
            save(next);
            apply(next, true);
        }
    };
})();