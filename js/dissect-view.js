/* Shared packet-detail renderer: layer tree, offset-linked hexdump, field table
 * and warnings. Used by the workbench for the selected capture frame.
 */
(function (global) {
  "use strict";

  const PH = global.PH;

  function resolve(target) {
    if (!target) return null;
    return typeof target === "string" ? document.getElementById(target) : target;
  }

  function create(options) {
    const opts = options || {};
    const hosts = {
      tree: resolve(opts.tree),
      hex: resolve(opts.hex),
      detail: resolve(opts.detail),
      warnings: resolve(opts.warnings),
      summary: resolve(opts.summary),
      tag: resolve(opts.tag),
      status: resolve(opts.status)
    };
    let result = null;
    let selected = 0;
    let fieldRange = null;

    function layerNode(item, index) {
      const depth = Math.min(item.depth || 0, 6);
      const tone = ["ethernet", "vlan", "fcs", "ipv4", "ipv6", "arp", "tcp", "udp", "icmp", "dns", "dhcp", "tls", "http", "payload", "link"]
        .indexOf(item.proto);
      return `<button type="button" class="layer-node${index === selected ? " is-active" : ""}${item.error ? " has-error" : ""}" ` +
        `data-layer="${index}" style="--depth:${depth};--node-tone:var(--tone-${"abcdefghij"[(tone + 10) % 10]})" ` +
        `aria-pressed="${index === selected ? "true" : "false"}">` +
        `<span class="layer-node__marker" aria-hidden="true"></span>` +
        `<span class="layer-node__body"><span class="layer-node__name">${PH.esc(item.name)}</span>` +
        `<span class="layer-node__summary">${PH.esc(item.summary || "")}</span></span>` +
        `<span class="layer-node__len">${item.length} B</span>` +
        `</button>`;
    }

    function renderTree() {
      if (!hosts.tree) return;
      if (!result) { hosts.tree.innerHTML = ""; return; }
      hosts.tree.innerHTML = result.layers.map(layerNode).join("");
      hosts.tree.querySelectorAll("[data-layer]").forEach((node) => {
        node.addEventListener("click", () => select(Number(node.dataset.layer)));
      });
    }

    function renderHexdump() {
      if (!hosts.hex) return;
      if (!result) { hosts.hex.innerHTML = ""; return; }
      const item = result.layers[selected];
      if (!item) { hosts.hex.innerHTML = PH.hexdump(result.bytes); return; }
      const start = Math.max(0, Math.min(fieldRange ? fieldRange.start : item.offset, result.bytes.length));
      const end = Math.max(start, Math.min(fieldRange ? fieldRange.end : item.offset + item.length, result.bytes.length));
      hosts.hex.innerHTML = '<div class="hexdump-wrap"><div class="hexdump-head"><span>frame bytes</span><span>' +
        result.bytes.length + " B · highlight +" + start + "…+" + end + "</span></div>" +
        PH.hexdump(result.bytes, { highlight: [{ start, end }] }) + "</div>";
    }

    function renderDetail() {
      if (!hosts.detail) return;
      const item = result && result.layers[selected];
      if (!item) { hosts.detail.innerHTML = ""; return; }
      const link = item.href
        ? `<a class="badge" href="${PH.esc(item.href)}">open ${PH.esc(item.name)} explorer →</a>`
        : "";
      const actions = typeof opts.detailActions === "function" ? (opts.detailActions(item, result) || "") : "";
      const fields = item.fields && item.fields.length
        ? '<div class="table-wrap"><table class="data-table"><thead><tr><th>Field</th><th>Value</th><th>Note</th></tr></thead><tbody>' +
          item.fields.map((field) => {
            const hasRange = field.offset != null && field.length != null;
            const attrs = hasRange
              ? ` class="field-row" data-field-offset="${field.offset}" data-field-length="${field.length}" tabindex="0"`
              : "";
            const abbrev = field.abbrev ? `<span class="field-abbrev">${PH.esc(field.abbrev)}</span> ` : "";
            const severity = field.severity ? ` field-value--${field.severity}` : "";
            return `<tr${attrs}><td><b>${PH.esc(field.name)}</b>${abbrev ? "<br>" + abbrev : ""}</td>` +
              `<td><code class="${severity.trim()}">${PH.esc(field.value)}</code></td>` +
              `<td class="small">${PH.esc(field.note || "")}${field.rfc ? " · " + PH.esc(field.rfc) : ""}</td></tr>`;
          }).join("") +
          "</tbody></table></div>"
        : '<p class="dim">No field breakdown for this layer.</p>';
      const warnings = item.warnings && item.warnings.length
        ? '<div class="callout callout--warn" style="margin-top:10px"><div class="callout__title">layer warnings</div><ul class="dashed" style="margin:0">' +
          item.warnings.map((warning) => `<li>${PH.esc(warning)}</li>`).join("") + "</ul></div>"
        : "";
      const bytes = result.bytes.subarray(item.offset, Math.min(result.bytes.length, item.offset + item.length));
      const preview = bytes.length
        ? '<div class="output" style="margin-top:10px"><div class="output__label">layer bytes · ' + bytes.length + ' B</div><pre>' +
          PH.esc(bytes.length > 160 ? PH.bytesToHex(bytes.subarray(0, 160)) + " …" : PH.bytesToHex(bytes)) + "</pre></div>"
        : "";
      hosts.detail.innerHTML = `<div class="dissect-detail__head"><div><h3>${PH.esc(item.name)}</h3>` +
        `<p class="dim">offset +${item.offset} · length ${item.length} B · depth ${item.depth}${item.error ? " · decode error" : ""}</p></div>` +
        `<div class="dissect-detail__actions">${actions}${link}</div></div>` +
        fields + warnings + preview;
      hosts.detail.querySelectorAll(".field-row").forEach((row) => {
        const start = Number(row.dataset.fieldOffset);
        const length = Number(row.dataset.fieldLength);
        if (!Number.isFinite(start) || !Number.isFinite(length)) return;
        const show = () => {
          fieldRange = { start, end: start + length };
          renderHexdump();
          row.classList.add("is-hot");
        };
        const hide = () => {
          fieldRange = null;
          renderHexdump();
          row.classList.remove("is-hot");
        };
        row.addEventListener("mouseenter", show);
        row.addEventListener("mouseleave", hide);
        row.addEventListener("focus", show);
        row.addEventListener("blur", hide);
        row.addEventListener("click", show);
      });
    }

    function renderWarnings() {
      if (!hosts.warnings) return;
      if (!result) { hosts.warnings.innerHTML = ""; return; }
      const warnings = result.warnings || [];
      if (!warnings.length) {
        hosts.warnings.innerHTML = '<div class="callout"><div class="callout__title">clean walk</div><p>Every length and selector agreed, and each layer’s decoder consumed the bytes it expected. Clean parsing is not a security guarantee.</p></div>';
        return;
      }
      hosts.warnings.innerHTML = '<div class="callout callout--warn"><div class="callout__title">' + warnings.length + ' parser note(s)</div><ul class="dashed" style="margin:0">' +
        warnings.map((warning) => `<li>${PH.esc(warning)}</li>`).join("") + "</ul></div>";
    }

    function renderSummary() {
      if (hosts.summary) {
        hosts.summary.innerHTML = result.layers.map((item) =>
          `<span class="pill${item.error ? " pill--bad" : ""}">${PH.esc(item.name)} · ${item.length} B</span>`
        ).join("");
      }
      if (hosts.tag) hosts.tag.textContent = result.totalBytes + " B";
      if (hosts.status) {
        PH.setStatus(hosts.status,
          `${result.summary} · ${result.layers.length} layer(s) · ${result.totalBytes} B${result.warnings.length ? " · " + result.warnings.length + " note(s)" : ""}`,
          result.warnings.length ? "warn" : "ok");
      }
    }

    function select(index) {
      if (!result) return;
      selected = Math.max(0, Math.min(Number(index) || 0, result.layers.length - 1));
      fieldRange = null;
      renderTree();
      renderHexdump();
      renderDetail();
      if (typeof opts.onSelect === "function") opts.onSelect(result.layers[selected], selected, result);
    }

    function render(next) {
      result = next || null;
      selected = 0;
      if (!result) { clear(); return null; }
      renderSummary();
      renderTree();
      renderHexdump();
      renderDetail();
      renderWarnings();
      if (typeof opts.onRender === "function") opts.onRender(result);
      return result;
    }

    function clear(message) {
      result = null;
      selected = 0;
      Object.keys(hosts).forEach((key) => {
        if (key === "status" || !hosts[key]) return;
        if (key === "tag") hosts[key].textContent = "waiting";
        else hosts[key].innerHTML = "";
      });
      if (hosts.status) PH.setStatus(hosts.status, message || "No frame dissected yet.", "");
    }

    return {
      render,
      select,
      clear,
      get result() { return result; },
      get selected() { return selected; },
      get selectedItem() { return result ? result.layers[selected] : null; }
    };
  }

  global.DissectView = { create };
})(typeof window !== "undefined" ? window : globalThis);
