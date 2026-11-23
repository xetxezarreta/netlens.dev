/* Port registry page: static data, client-side filter. */
(function () {
  "use strict";

  const PH = window.PH;

  function rangeOf(port) {
    if (port <= 1023) return "well";
    if (port <= 49151) return "registered";
    return "dynamic";
  }

  function render() {
    const host = document.getElementById("ports-result");
    if (!host) return;
    const query = document.getElementById("ports-search").value.trim().toLowerCase();
    const proto = document.getElementById("ports-proto").value;
    const range = document.getElementById("ports-range").value;
    const data = (window.PH_PORTS || []).filter((entry) => {
      if (proto !== "all" && !entry.proto.split("/").includes(proto)) return false;
      if (range !== "all" && rangeOf(entry.port) !== range) return false;
      if (!query) return true;
      return String(entry.port).includes(query) ||
        entry.service.toLowerCase().includes(query) ||
        entry.proto.toLowerCase().includes(query) ||
        entry.desc.toLowerCase().includes(query);
    }).sort((a, b) => a.port - b.port || a.service.localeCompare(b.service));
    const count = document.getElementById("ports-count");
    if (count) count.textContent = data.length + " of " + (window.PH_PORTS || []).length + " entries";
    if (!data.length) {
      host.innerHTML = '<div class="glossary-empty">No port matches that filter. Examples: “443”, “dns” or “udp”.</div>';
      return;
    }
    host.innerHTML = '<div class="table-wrap"><table class="data-table registry-table"><thead><tr><th class="num">Port</th><th>Service</th><th>Protocol</th><th>Range</th><th>Description</th></tr></thead><tbody>' +
      data.map((entry) => {
        const service = entry.page
          ? `<a href="${PH.esc(entry.page)}"><b>${PH.esc(entry.service)}</b></a>`
          : `<b>${PH.esc(entry.service)}</b>`;
        return `<tr><td class="num"><code>${entry.port}</code></td><td>${service}</td><td><code>${PH.esc(entry.proto)}</code></td><td><span class="tag-pill">${rangeOf(entry.port)}</span></td><td>${PH.esc(entry.desc)}${entry.page ? ' <a href="' + PH.esc(entry.page) + '" class="small">open page →</a>' : ""}</td></tr>`;
      }).join("") + "</tbody></table></div>";
  }

  function init() {
    const search = document.getElementById("ports-search");
    if (!search) return;
    ["input", "change"].forEach((event) => {
      search.addEventListener(event, render);
      document.getElementById("ports-proto").addEventListener(event, render);
      document.getElementById("ports-range").addEventListener(event, render);
    });
    search.addEventListener("keydown", (event) => {
      if (event.key === "Escape") { search.value = ""; render(); }
    });
    render();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
