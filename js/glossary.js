/* Glossary page: search, topic filter and links to protocol pages. */
(function () {
  "use strict";

  const PH = window.PH;

  function protocolLink(term) {
    const protocols = window.PH_PROTOCOLS || {};
    const lower = term.toLowerCase();
    const key = Object.keys(protocols).find((k) => {
      const name = (protocols[k].name || "").toLowerCase();
      return name === lower || name.replace(/[^a-z0-9]/g, "") === lower.replace(/[^a-z0-9]/g, "");
    });
    return key ? key + ".html" : null;
  }

  function render() {
    const host = document.getElementById("glossary-result");
    if (!host) return;
    const query = document.getElementById("glossary-search").value.trim().toLowerCase();
    const tag = document.getElementById("glossary-tag").value;
    const all = (window.PH_GLOSSARY || []).slice().sort((a, b) => a.term.localeCompare(b.term));
    const data = all.filter((entry) => {
      if (tag !== "all" && !entry.tags.includes(tag)) return false;
      if (!query) return true;
      return entry.term.toLowerCase().includes(query) ||
        entry.def.toLowerCase().includes(query) ||
        entry.tags.some((t) => t.includes(query));
    });
    const count = document.getElementById("glossary-count");
    if (count) count.textContent = data.length + " of " + all.length + " terms";
    if (!data.length) {
      host.innerHTML = '<div class="glossary-empty">No term matches. Examples: “SACK”, “VNI”, “DUID” or “PMTUD”.</div>';
      return;
    }
    host.innerHTML = data.map((entry) => {
      const link = protocolLink(entry.term);
      return `<article class="glossary-entry"><h3>${PH.esc(entry.term)}</h3><p>${PH.esc(entry.def)}</p>` +
        `<div class="g-tags">${entry.tags.map((t) => `<span>${PH.esc(t)}</span>`).join("")}${link ? ` <a class="small" href="${link}">open page →</a>` : ""}</div></article>`;
    }).join("");
  }

  function init() {
    const search = document.getElementById("glossary-search");
    if (!search) return;
    const tags = new Set();
    (window.PH_GLOSSARY || []).forEach((entry) => entry.tags.forEach((tag) => tags.add(tag)));
    const select = document.getElementById("glossary-tag");
    Array.from(tags).sort().forEach((tag) => {
      const option = document.createElement("option");
      option.value = tag;
      option.textContent = tag;
      select.appendChild(option);
    });
    ["input", "change"].forEach((event) => {
      search.addEventListener(event, render);
      select.addEventListener(event, render);
    });
    search.addEventListener("keydown", (event) => {
      if (event.key === "Escape") { search.value = ""; render(); }
    });
    render();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
