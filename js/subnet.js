/* Subnet calculator page: IPv4/IPv6 prefix math, splitting and VLSM. */
(function () {
  "use strict";

  const PH = window.PH;
  const S = window.SubnetCodec;

  function fact(value, label) {
    return `<div class="fact"><b>${PH.esc(value)}</b><span>${PH.esc(label)}</span></div>`;
  }

  function bitsView(info) {
    if (info.version !== 4) return "";
    let html = '<div class="subnet-bits" aria-label="32-bit subnet mask view">';
    for (let i = 0; i < 32; i++) html += `<span class="${i < info.prefix ? "net" : "host"}" title="bit ${i}"></span>`;
    html += "</div>";
    return '<div class="mt-8"><div class="row-between"><span class="small dim">network bits ' + info.prefix + '</span><span class="small dim">host bits ' + info.hostBits + "</span></div>" + html + "</div>";
  }

  function renderResult(info) {
    const host = document.getElementById("subnet-result");
    const facts = [
      fact(info.cidr, "network / CIDR"),
      fact(info.addressText + "/" + info.prefix, "input address"),
      fact(info.networkText, "network address"),
      fact(info.broadcastText || "—", info.version === 4 ? "broadcast" : "last address"),
      fact(info.firstText, "first address"),
      fact(info.lastText, "last address"),
      fact(info.version === 4 ? info.maskText : "/" + info.prefix, "mask"),
      fact(info.version === 4 ? info.wildcardText : "—", "wildcard"),
      fact(String(info.usableHosts), "usable hosts"),
      fact(String(info.totalHosts), "addresses"),
      fact(info.type || "—", "address type")
    ];
    if (info.version === 4) facts.push(fact(info.class, "classful class"));
    let extra = "";
    if (info.version === 4) {
      extra = '<div class="table-wrap"><table class="data-table"><thead><tr><th>Representation</th><th>Value</th></tr></thead><tbody>' +
        `<tr><td>Address binary</td><td><code>${PH.esc(info.binary)}</code></td></tr>` +
        `<tr><td>Network binary</td><td><code>${PH.esc(info.networkBinary)}</code></td></tr>` +
        `<tr><td>Mask binary</td><td><code>${PH.esc(S.binary32(info.mask))}</code></td></tr>` +
        "</tbody></table></div>";
    } else {
      extra = '<div class="table-wrap"><table class="data-table"><thead><tr><th>Representation</th><th>Value</th></tr></thead><tbody>' +
        `<tr><td>Expanded address</td><td><code>${PH.esc(info.expanded)}</code></td></tr>` +
        `<tr><td>Network expanded</td><td><code>${PH.esc(info.networkExpanded)}</code></td></tr>` +
        `<tr><td>Zone</td><td><code>${PH.esc(info.zone || "—")}</code></td></tr>` +
        "</tbody></table></div>";
    }
    host.innerHTML = `<div class="subnet-range">${facts.join("")}</div>` + bitsView(info) + extra;
  }

  function calc(showErrors) {
    const status = document.getElementById("subnet-status");
    const input = document.getElementById("subnet-input");
    try {
      const info = S.parseCidr(input.value);
      renderResult(info);
      PH.setStatus(status, `${info.version === 4 ? "IPv4" : "IPv6"} · ${info.cidr} · ${info.usableHosts} usable · ${info.type}`, "ok");
      return info;
    } catch (err) {
      if (showErrors !== false) PH.setStatus(status, "error: " + err.message, "bad");
      document.getElementById("subnet-result").innerHTML = "";
      return null;
    }
  }

  function initCalc() {
    const input = document.getElementById("subnet-input");
    if (!input) return;
    document.getElementById("subnet-calc").addEventListener("click", () => calc(true));
    input.addEventListener("keydown", (event) => { if (event.key === "Enter") calc(true); });
    document.querySelectorAll("[data-subnet]").forEach((btn) => btn.addEventListener("click", () => {
      input.value = btn.getAttribute("data-subnet");
      document.getElementById("subnet-split-input").value = btn.getAttribute("data-subnet");
      calc(true);
    }));
    calc(false);
  }

  function initSplit() {
    const input = document.getElementById("subnet-split-input");
    if (!input) return;
    function run(showErrors) {
      const status = document.getElementById("subnet-split-status");
      const host = document.getElementById("subnet-split-result");
      try {
        const base = S.parseCidr(input.value);
        const target = Number(document.getElementById("subnet-split-prefix").value);
        if (target < base.prefix) throw new Error("New prefix must be longer than the parent (" + base.prefix + ")");
        const list = S.splitCidr(input.value, target);
        host.innerHTML = '<div class="subnet-list">' + list.map((item, i) =>
          `<li><span class="n">${i + 1}</span><b>${PH.esc(item.cidr)}</b><span>${PH.esc(item.firstText)} – ${PH.esc(item.lastText)} · ${item.usableHosts} usable</span></li>`
        ).join("") + "</div>";
        if (list.length > 0) {
          document.getElementById("subnet-split-result").insertAdjacentHTML("afterbegin",
            `<div class="subnet-range"><div><b>${list.length}</b><span>prefixes</span></div><div><b>${PH.esc(list[0].cidr)}</b><span>first</span></div><div><b>${PH.esc(list[list.length - 1].cidr)}</b><span>last</span></div></div>`);
        }
        PH.setStatus(status, `${list.length} × /${target} from ${base.cidr}`, "ok");
      } catch (err) {
        if (showErrors !== false) PH.setStatus(status, "error: " + err.message, "bad");
        host.innerHTML = "";
      }
    }
    document.getElementById("subnet-split").addEventListener("click", () => run(true));
    document.getElementById("subnet-split-prefix").addEventListener("change", () => run(false));
    input.addEventListener("keydown", (event) => { if (event.key === "Enter") run(true); });
    run(false);
  }

  function parseRequirements(text) {
    return String(text || "").split(/\n/).map((line) => line.trim()).filter(Boolean).map((line) => {
      const match = /^(.+?)\s*[=:,]\s*(\d+)$/.exec(line);
      if (!match) throw new Error("Use 'name = hosts' on each line: " + line);
      return { name: match[1].trim(), hosts: Number(match[2]) };
    });
  }

  function initVlsm() {
    const parent = document.getElementById("vlsm-parent");
    if (!parent) return;
    function run(showErrors) {
      const status = document.getElementById("vlsm-status");
      const host = document.getElementById("vlsm-result");
      try {
        const result = S.vlsmPlan(parent.value, parseRequirements(document.getElementById("vlsm-requirements").value));
        const rows = result.plan.map((item) => `<tr><td><b>${PH.esc(item.name)}</b></td><td><code>${PH.esc(item.cidr)}</code></td><td>${PH.esc(item.firstText)} – ${PH.esc(item.lastText)}</td><td class="num">${item.usableHosts}</td><td class="num">${item.hosts}</td></tr>`).join("");
        host.innerHTML = '<div class="table-wrap"><table class="data-table"><thead><tr><th>Name</th><th>Prefix</th><th>Range</th><th class="num">Usable</th><th class="num">Requested</th></tr></thead><tbody>' + rows + "</tbody></table></div>";
        if (result.warnings.length) {
          host.innerHTML += '<div class="callout callout--warn" style="margin-top:12px"><div class="callout__title">not placed</div><ul class="dashed" style="margin:0">' + result.warnings.map((w) => `<li>${PH.esc(w)}</li>`).join("") + "</ul></div>";
        }
        PH.setStatus(status, `${result.plan.length} prefix(es) placed · ${result.free} address(es) free${result.warnings.length ? " · " + result.warnings.length + " warning(s)" : ""}`, result.warnings.length ? "warn" : "ok");
      } catch (err) {
        if (showErrors !== false) PH.setStatus(status, "error: " + err.message, "bad");
        host.innerHTML = "";
      }
    }
    document.getElementById("vlsm-plan").addEventListener("click", () => run(true));
    document.getElementById("vlsm-example").addEventListener("click", () => {
      parent.value = "192.168.0.0/23";
      document.getElementById("vlsm-requirements").value = "core = 100\nstaff = 50\nguest = 10\npoint-to-point = 2";
      run(true);
    });
    run(false);
  }

  function restoreState() {
    const state = PH.readHashState();
    if (!state || state.page !== "subnet") return;
    if (state.input) document.getElementById("subnet-input").value = state.input;
    if (state.split) document.getElementById("subnet-split-input").value = state.split;
    if (state.splitPrefix) document.getElementById("subnet-split-prefix").value = state.splitPrefix;
    if (state.vlsmParent) document.getElementById("vlsm-parent").value = state.vlsmParent;
    if (state.vlsmReq) document.getElementById("vlsm-requirements").value = state.vlsmReq;
    calc(true);
  }

  function init() {
    if (!document.getElementById("subnet-input")) return;
    initCalc();
    initSplit();
    initVlsm();
    restoreState();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
