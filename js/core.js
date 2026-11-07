/* netlens.dev — shared core. No dependencies, no tracking. */
(function () {
  "use strict";

  const PH = (window.PH = window.PH || {});
  const $ = (sel, root = document) => root.querySelector(sel);
  const $$ = (sel, root = document) => Array.from(root.querySelectorAll(sel));

  const TONES = ["a", "b", "c", "d", "e", "f", "g", "h", "i", "j"];

  /* ---------- tiny utilities ---------- */
  function esc(value) {
    return String(value == null ? "" : value)
      .replace(/&/g, "&amp;")
      .replace(/</g, "&lt;")
      .replace(/>/g, "&gt;")
      .replace(/"/g, "&quot;")
      .replace(/'/g, "&#39;");
  }

  function hex(n, width = 2) {
    if (!Number.isFinite(Number(n))) return "?";
    return Math.max(0, Number(n)).toString(16).toUpperCase().padStart(width, "0");
  }

  function bin(n, width = 8) {
    if (!Number.isFinite(Number(n))) return "?";
    return Math.max(0, Number(n)).toString(2).padStart(width, "0");
  }

  // Home links should land on the site root (https://netlens.dev/), not
  // index.html. Keep file:// working by resolving to the local file there.
  function homeHref() {
    return location.protocol === "file:" ? "index.html" : "/";
  }

  function parseNumber(raw) {
    if (typeof raw === "number") return Number.isFinite(raw) ? raw : null;
    if (raw == null) return null;
    let s = String(raw).trim().replace(/_/g, "");
    if (!s) return null;
    let sign = 1;
    if (s.startsWith("-")) { sign = -1; s = s.slice(1); }
    let n;
    if (/^0x/i.test(s)) n = parseInt(s.slice(2), 16);
    else if (/^0b/i.test(s)) n = parseInt(s.slice(2), 2);
    else if (/^[0-9a-f]+$/i.test(s) && /[a-f]/i.test(s) && !/^\d+$/.test(s)) n = parseInt(s, 16);
    else n = Number(s);
    return Number.isFinite(n) ? sign * n : null;
  }

  function parseHex(raw) {
    if (raw instanceof Uint8Array) return raw;
    if (Array.isArray(raw)) return Uint8Array.from(raw);
    if (raw == null) throw new Error("No bytes given");
    let s = String(raw)
      .replace(/\r/g, " ")
      .replace(/\n/g, " ")
      .replace(/0x/gi, " ")
      .replace(/([0-9a-f]{2})[:\-_.]/gi, "$1 ")
      .replace(/[^0-9a-fA-F]/g, "");
    if (s.length % 2) throw new Error("Hex has an odd number of nibbles (" + s.length + ")");
    if (!s.length) throw new Error("No hex bytes found");
    const out = new Uint8Array(s.length / 2);
    for (let i = 0; i < out.length; i++) out[i] = parseInt(s.slice(i * 2, i * 2 + 2), 16);
    return out;
  }

  function bytesToHex(bytes, sep = " ") {
    return Array.from(bytes, (b) => hex(b, 2)).join(sep);
  }

  function bytesToAscii(bytes) {
    return Array.from(bytes, (b) => (b >= 32 && b <= 126 ? String.fromCharCode(b) : ".")).join("");
  }

  function concatBytes(...parts) {
    const arrays = parts.map((p) => (p instanceof Uint8Array ? p : Uint8Array.from(p)));
    const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
    let off = 0;
    for (const a of arrays) { out.set(a, off); off += a.length; }
    return out;
  }

  function u8(bytes, off) { return bytes[off] >>> 0; }
  function u16be(bytes, off) { return ((bytes[off] << 8) | bytes[off + 1]) >>> 0; }
  function u16le(bytes, off) { return ((bytes[off + 1] << 8) | bytes[off]) >>> 0; }
  function u32be(bytes, off) { return (((bytes[off] << 24) >>> 0) + (bytes[off + 1] << 16) + (bytes[off + 2] << 8) + bytes[off + 3]) >>> 0; }
  function u32le(bytes, off) { return (((bytes[off + 3] << 24) >>> 0) + (bytes[off + 2] << 16) + (bytes[off + 1] << 8) + bytes[off]) >>> 0; }
  function u64le(bytes, off) {
    let v = 0n;
    for (let i = 7; i >= 0; i--) v = (v << 8n) | BigInt(bytes[off + i]);
    return v;
  }

  function put16be(arr, off, v) { arr[off] = (v >>> 8) & 255; arr[off + 1] = v & 255; }
  function put16le(arr, off, v) { arr[off] = v & 255; arr[off + 1] = (v >>> 8) & 255; }
  function put32be(arr, off, v) {
    arr[off] = (v >>> 24) & 255; arr[off + 1] = (v >>> 16) & 255;
    arr[off + 2] = (v >>> 8) & 255; arr[off + 3] = v & 255;
  }
  function put32le(arr, off, v) {
    arr[off] = v & 255; arr[off + 1] = (v >>> 8) & 255;
    arr[off + 2] = (v >>> 16) & 255; arr[off + 3] = (v >>> 24) & 255;
  }
  function put64le(arr, off, v) {
    let n = BigInt(v);
    for (let i = 0; i < 8; i++) { arr[off + i] = Number(n & 255n); n >>= 8n; }
  }

  /* RFC 1071 Internet checksum over a byte array. */
  function checksum16(bytes) {
    let sum = 0;
    for (let i = 0; i < bytes.length; i += 2) {
      const word = (bytes[i] << 8) + (i + 1 < bytes.length ? bytes[i + 1] : 0);
      sum += word;
      sum = (sum & 0xffff) + (sum >>> 16);
    }
    while (sum >>> 16) sum = (sum & 0xffff) + (sum >>> 16);
    return (~sum) & 0xffff;
  }

  function checksumValid(bytes) {
    let sum = 0;
    for (let i = 0; i < bytes.length; i += 2) {
      sum += (bytes[i] << 8) + (i + 1 < bytes.length ? bytes[i + 1] : 0);
      sum = (sum & 0xffff) + (sum >>> 16);
    }
    while (sum >>> 16) sum = (sum & 0xffff) + (sum >>> 16);
    return sum === 0xffff;
  }

  function parseIPv4(text) {
    const parts = String(text).trim().split(".");
    if (parts.length !== 4) throw new Error("IPv4 address needs four octets");
    const out = new Uint8Array(4);
    parts.forEach((p, i) => {
      if (!/^\d{1,3}$/.test(p)) throw new Error("Invalid IPv4 octet: " + p);
      const n = Number(p);
      if (n > 255) throw new Error("IPv4 octet out of range: " + p);
      out[i] = n;
    });
    return out;
  }

  function ipv4String(bytes, off = 0) {
    if (!bytes || bytes.length < off + 4) return "?";
    return [bytes[off], bytes[off + 1], bytes[off + 2], bytes[off + 3]].join(".");
  }

  function toast(message) {
    let el = $(".toast");
    if (!el) {
      el = document.createElement("div");
      el.className = "toast";
      el.setAttribute("role", "status");
      el.setAttribute("aria-live", "polite");
      document.body.appendChild(el);
    }
    el.textContent = message;
    el.classList.add("is-on");
    clearTimeout(el._timer);
    el._timer = setTimeout(() => el.classList.remove("is-on"), 1600);
  }

  function copyText(text) {
    if (navigator.clipboard && window.isSecureContext) {
      return navigator.clipboard.writeText(text).then(() => true).catch(() => fallbackCopy(text));
    }
    return Promise.resolve(fallbackCopy(text));
  }

  function fallbackCopy(text) {
    const ta = document.createElement("textarea");
    ta.value = text;
    ta.setAttribute("readonly", "");
    ta.style.position = "fixed";
    ta.style.opacity = "0";
    document.body.appendChild(ta);
    ta.select();
    let ok = false;
    try { ok = document.execCommand("copy"); } catch (_) { /* noop */ }
    ta.remove();
    return ok;
  }

  function setStatus(el, text, kind) {
    if (!el) return;
    el.textContent = text;
    el.classList.remove("is-ok", "is-warn", "is-bad");
    if (kind) el.classList.add("is-" + kind);
  }

  function hexdump(bytes, opts = {}) {
    if (!bytes || !bytes.length) return '<div class="hexdump"><span class="dim">no bytes</span></div>';
    const highlight = opts.highlight || [];
    const lines = [];
    for (let off = 0; off < bytes.length; off += 16) {
      const slice = bytes.subarray(off, Math.min(off + 16, bytes.length));
      const hexParts = [];
      for (let i = 0; i < 16; i++) {
        if (i === 8) hexParts.push('<span class="sp"> </span>');
        if (i < slice.length) {
          const globalOff = off + i;
          const hot = highlight.some((r) => globalOff >= r.start && globalOff < r.end);
          const cls = slice[i] === 0 ? "z" : "";
          hexParts.push(`<${hot ? "b" : "span"} class="${cls}">${hex(slice[i], 2)}</${hot ? "b" : "span"}>`);
        } else {
          hexParts.push('<span class="sp">--</span>');
        }
        hexParts.push(" ");
      }
      const ascii = Array.from(slice, (b) => {
        if (b >= 32 && b <= 126) return esc(String.fromCharCode(b));
        return ".";
      }).join("");
      lines.push(
        `<div class="hd-row"><span class="hd-off">${hex(off, 4)}</span>` +
        `<span class="hd-bytes">${hexParts.join("")}</span>` +
        `<span class="hd-ascii">${ascii}</span></div>`
      );
    }
    return `<div class="hexdump">${lines.join("")}</div>`;
  }

  /* ---------- bit diagram engine ---------- */
  function renderInspector(el, field, meta) {
    if (!el) return;
    const byteMode = Boolean(meta && meta.byteMode);
    if (!field) {
      el.innerHTML =
        '<div><div class="field-detail__eyebrow">field inspector</div>' +
        '<p class="field-detail__name">Select a field</p>' +
        '<p class="field-detail__desc">Hover or click any block in the diagram, or a row in the field table. ' +
        'The inspector shows the exact bit range, allowed values and the RFC that defines it.</p></div>' +
        '<div class="field-detail__side"><span class="field-detail__hint">click to pin · esc to clear</span></div>';
      return;
    }
    const start = meta.start;
    const end = meta.end;
    const units = byteMode ? "byte" : "bit";
    const bitLabel = byteMode
      ? ((field.variable || field.bytes === "var") ? "variable width" : `${end - start} byte${end - start === 1 ? "" : "s"}`)
      : (field.bits === "var" ? "variable width" : `${field.bits} bit${field.bits === 1 ? "" : "s"}`);
    const range = field.range ? `<span class="field-detail__range">range <b>${esc(field.range)}</b></span>` : "";
    const rfc = field.rfc
      ? (field.rfcUrl
        ? `<a class="field-detail__rfc" href="${esc(field.rfcUrl)}" target="_blank" rel="noopener">${esc(field.rfc)} ↗</a>`
        : `<span class="field-detail__rfc">${esc(field.rfc)}</span>`)
      : "";
    const value = field.value != null
      ? `<span class="field-detail__range">value <b>${esc(field.value)}</b></span>`
      : "";
    const bitRange = byteMode
      ? `<span class="field-detail__range">bits ${start * 8}–${end * 8 - 1}${field.variable ? " (nominal)" : ""}</span>`
      : "";
    el.innerHTML =
      '<div><div class="field-detail__eyebrow">field inspector · ' + esc(field.name) + "</div>" +
      `<p class="field-detail__name">${esc(field.name)}</p>` +
      `<p class="field-detail__desc">${field.desc || "No description."}</p>` +
      '<span class="field-detail__hint">click to pin · esc to clear</span></div>' +
      '<div class="field-detail__side">' +
      `<div class="field-detail__bits">${units}s ${start}–${end - 1}<small>${bitLabel}${(field.variable || field.bits === "var") ? " · variable offset" : ""}</small></div>` +
      bitRange + range + value + rfc +
      "</div>";
  }

  function diagram(target, spec) {
    const el = typeof target === "string" ? $(target) : target;
    if (!el) throw new Error("Diagram target not found");
    const bitsPerRow = spec.bitsPerRow || 32;
    const varWidth = spec.varWidth || 32;
    const groupCount = Math.max(1, Math.ceil(bitsPerRow / 8));
    const gridStyle = `grid-template-columns:repeat(${bitsPerRow},minmax(0,1fr));--cell:calc(100% / ${bitsPerRow});--group:calc(100% / ${groupCount})`;
    el.classList.toggle("diagram--byte-rows", bitsPerRow <= 8);
    const fields = [];
    let cursor = 0;
    (spec.fields || []).forEach((raw, index) => {
      const f = Object.assign({}, raw);
      f.id = f.id || "f" + index;
      f.tone = f.tone || TONES[index % TONES.length];
      f._start = cursor;
      f._displayBits = f.bits === "var" ? (f.varWidth || varWidth) : Number(f.bits);
      if (!Number.isFinite(f._displayBits) || f._displayBits <= 0) {
        throw new Error("Field " + f.name + " has no valid bit width");
      }
      f._end = cursor + f._displayBits;
      f._variable = f.bits === "var";
      cursor = f._end;
      fields.push(f);
    });
    const totalBits = cursor;
    const rows = Math.max(1, Math.ceil(totalBits / bitsPerRow));
    const inspector = spec.inspector ? (typeof spec.inspector === "string" ? $(spec.inspector) : spec.inspector) : null;
    const table = spec.table ? (typeof spec.table === "string" ? $(spec.table) : spec.table) : null;

    let html = '<div class="diagram' + (spec.compact ? " diagram--compact" : "") + '">';
    html += '<div class="diagram__head"><div class="diagram__title">' +
      (spec.title ? spec.title : "bit layout") +
      (spec.badge ? ' <span class="badge">' + spec.badge + "</span>" : "") +
      "</div>" +
      '<div class="legend"><span><i style="background:var(--accent)"></i> click a field</span>' +
      '<span>MSB first</span></div></div>';
    html += '<div class="diagram__scroll"><div class="diagram__inner">';

    // Bit ruler
    html += `<div class="diagram__ruler"><span class="diagram__ruler-label">bit</span><div class="diagram__ruler-track" style="${gridStyle}">`;
    for (let i = 0; i < bitsPerRow; i++) {
      const cls = i % 8 === 0 ? "byte" : (i % 4 === 0 ? "tick" : "");
      html += `<span class="${cls}">${i}</span>`;
    }
    html += "</div></div>";

    for (let r = 0; r < rows; r++) {
      const rowStart = r * bitsPerRow;
      const rowEnd = rowStart + bitsPerRow;
      html += '<div class="diagram__row">';
      html += `<span class="diagram__offset">${hex(rowStart / 8, 2)}</span>`;
      html += `<div class="diagram__track" style="${gridStyle}">`;
      fields.forEach((f) => {
        if (f._end <= rowStart || f._start >= rowEnd) return;
        const a = Math.max(f._start, rowStart) - rowStart;
        const b = Math.min(f._end, rowEnd) - rowStart;
        const span = b - a;
        const first = f._start >= rowStart && f._start < rowEnd;
        const cls = ["diagram__field"];
        if (!first) cls.push("is-cont");
        if (span <= 2) cls.push("is-tiny");
        else if (span <= 5) cls.push("is-narrow");
        if (f._variable) cls.push("is-variable");
        const label = first ? esc(f.name) : "↳ " + esc(f.name);
        const meta = f.value != null
          ? String(f.value)
          : (f._variable ? "var" : f.bits + "b");
        html += `<button type="button" class="${cls.join(" ")}" data-field="${esc(f.id)}" ` +
          `data-tone="${esc(f.tone)}" data-variable="${f._variable ? "1" : "0"}" ` +
          `style="grid-column:${a + 1} / span ${span};--tone:var(--tone-${esc(f.tone)})" ` +
          `aria-label="${esc(f.name)}, bits ${f._start} to ${f._end - 1}, ${meta}">` +
          `<span class="f-name">${label}</span><span class="f-meta" data-value>${esc(meta)}</span>` +
          "</button>";
      });
      html += "</div></div>";
    }
    html += "</div></div>";
    html += `<p class="diagram__note">${spec.note || "Bit 0 is the most significant bit of the first octet. Fields are drawn MSB-first; offsets count from the start of the structure."}</p>`;
    html += "</div>";
    el.innerHTML = html;

    const fieldById = new Map(fields.map((f) => [f.id, f]));
    const segments = $$(".diagram__field", el);
    let selected = null;

    function setHot(id, on) {
      segments.forEach((seg) => {
        if (seg.dataset.field === id) seg.classList.toggle("is-hot", on);
      });
      if (table) {
        $$("[data-field]", table).forEach((row) => {
          if (row.dataset.field === id) row.classList.toggle("is-hot", on);
        });
      }
    }

    function select(id, silent) {
      selected = id;
      segments.forEach((seg) => seg.classList.toggle("is-selected", seg.dataset.field === id));
      $$("[data-field]", el.parentElement || el).forEach((row) => {
        if (row.tagName === "TR") row.classList.toggle("is-hot", row.dataset.field === id);
      });
      const f = fieldById.get(id);
      if (f) {
        renderInspector(inspector, f, { start: f._start, end: f._end });
        if (table) {
          $$("[data-field]", table).forEach((row) => row.classList.toggle("is-hot", row.dataset.field === id));
        }
        if (!silent && spec.onSelect) spec.onSelect(f, { start: f._start, end: f._end });
      }
    }

    function clear() {
      selected = null;
      segments.forEach((seg) => seg.classList.remove("is-selected"));
      if (table) $$("[data-field]", table).forEach((row) => row.classList.remove("is-hot"));
      renderInspector(inspector, null);
    }

    el.addEventListener("mouseover", (event) => {
      const seg = event.target.closest(".diagram__field");
      if (!seg || !el.contains(seg)) return;
      setHot(seg.dataset.field, true);
      const f = fieldById.get(seg.dataset.field);
      if (f) renderInspector(inspector, f, { start: f._start, end: f._end });
    });
    el.addEventListener("mouseout", (event) => {
      const seg = event.target.closest(".diagram__field");
      if (!seg || !el.contains(seg)) return;
      const related = event.relatedTarget && event.relatedTarget.closest ? event.relatedTarget.closest(".diagram__field") : null;
      if (related && related.dataset.field === seg.dataset.field) return;
      setHot(seg.dataset.field, false);
      if (selected) {
        const f = fieldById.get(selected);
        renderInspector(inspector, f, { start: f._start, end: f._end });
      } else {
        renderInspector(inspector, null);
      }
    });
    el.addEventListener("click", (event) => {
      const seg = event.target.closest(".diagram__field");
      if (!seg || !el.contains(seg)) return;
      if (selected === seg.dataset.field) clear();
      else select(seg.dataset.field);
    });
    el.addEventListener("keydown", (event) => {
      if (event.key === "Enter" || event.key === " ") {
        const seg = event.target.closest(".diagram__field");
        if (!seg) return;
        event.preventDefault();
        if (selected === seg.dataset.field) clear();
        else select(seg.dataset.field);
      }
      if (event.key === "Escape") clear();
    });

    if (table) {
      table.addEventListener("mouseover", (event) => {
        const row = event.target.closest("tr[data-field]");
        if (row) setHot(row.dataset.field, true);
      });
      table.addEventListener("mouseout", (event) => {
        const row = event.target.closest("tr[data-field]");
        if (row) setHot(row.dataset.field, false);
      });
      table.addEventListener("click", (event) => {
        const row = event.target.closest("tr[data-field]");
        if (!row) return;
        select(row.dataset.field);
        const seg = segments.find((s) => s.dataset.field === row.dataset.field);
        if (seg) seg.focus({ preventScroll: true });
      });
    }

    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && selected) {
        // only if focus is within the page, never steal from a dialog
        if (!event.target.closest("dialog") && (el.contains(event.target) || event.target === document.body)) clear();
      }
    });

    const controller = {
      el,
      fields,
      bits: totalBits,
      select,
      clear,
      get selected() { return selected; },
      meta(id) { const f = fieldById.get(id); return f ? { start: f._start, end: f._end } : null; },
      setValues(values) {
        Object.keys(values || {}).forEach((id) => {
          const f = fieldById.get(id);
          if (!f) return;
          f.value = values[id];
          el.querySelectorAll(`.diagram__field[data-field="${CSS.escape(id)}"] [data-value]`).forEach((m) => {
            m.textContent = values[id];
          });
        });
        if (selected) {
          const f = fieldById.get(selected);
          renderInspector(inspector, f, { start: f._start, end: f._end });
        }
      }
    };
    renderInspector(inspector, null);
    return controller;
  }

  function fieldTable(target, controller, options = {}) {
    const el = typeof target === "string" ? $(target) : target;
    if (!el) return;
    const fields = controller.fields;
    const cols = options.columns || ["field", "bits", "offset", "range/values", "rfc"];
    const headLabels = {
      field: "Field", bits: "Bits", offset: "Offset", "range/values": options.rangeHeader || "Range / values",
      rfc: "Reference", value: "Value", notes: "Notes"
    };
    let html = '<div class="table-wrap"><table class="data-table"><thead><tr>';
    cols.forEach((c) => { html += `<th class="${c === "bits" || c === "offset" ? "num" : ""}">${headLabels[c] || c}</th>`; });
    html += "</tr></thead><tbody>";
    fields.forEach((f) => {
      const meta = controller.meta(f.id);
      html += `<tr data-field="${esc(f.id)}">`;
      cols.forEach((c) => {
        if (c === "field") {
          html += `<td><span class="tone-dot" style="--tone:var(--tone-${esc(f.tone)})"></span><b>${esc(f.name)}</b></td>`;
        } else if (c === "bits") {
          html += `<td class="num">${f.bits === "var" ? "var" : f.bits}</td>`;
        } else if (c === "offset") {
          html += `<td class="num">${meta.start}–${meta.end - 1}</td>`;
        } else if (c === "range/values") {
          html += `<td>${f.range ? esc(f.range) : (f.desc ? esc(f.desc) : "—")}</td>`;
        } else if (c === "rfc") {
          html += `<td class="nowrap">${f.rfc ? (f.rfcUrl ? `<a href="${esc(f.rfcUrl)}" target="_blank" rel="noopener">${esc(f.rfc)}</a>` : esc(f.rfc)) : "—"}</td>`;
        } else if (c === "value") {
          html += `<td>${f.value != null ? esc(f.value) : "—"}</td>`;
        } else if (c === "notes") {
          html += `<td class="small">${f.note ? esc(f.note) : "—"}</td>`;
        }
      });
      html += "</tr>";
    });
    html += "</tbody></table></div>";
    el.innerHTML = html;
  }


  /* ---------- byte lane (byte-aligned wire diagrams) ---------- */
  function byteLane(target, spec) {
    const el = typeof target === "string" ? $(target) : target;
    if (!el) throw new Error("Byte lane target not found");
    const fields = [];
    let cursor = spec.startByte || 0;
    const varBytes = spec.varBytes || 4;
    (spec.fields || []).forEach((raw, index) => {
      const f = Object.assign({}, raw);
      f.id = f.id || "b" + index;
      f.tone = f.tone || TONES[index % TONES.length];
      f.variable = f.variable || f.bytes === "var";
      f._start = cursor;
      f._displayBytes = f.variable ? (f.varBytes || varBytes) : Math.max(1, Number(f.bytes) || 1);
      f._end = cursor + f._displayBytes;
      cursor = f._end;
      fields.push(f);
    });
    const inspector = spec.inspector ? (typeof spec.inspector === "string" ? $(spec.inspector) : spec.inspector) : null;
    // Track and ticks share one explicit column template so every offset
    // tick lines up with the left edge of its box, regardless of padding.
    const columns = fields.length
      ? fields.map((f) => `minmax(14px, ${f.variable ? 2 : f._displayBytes}fr)`).join(" ")
      : "1fr";
    let html = '<div class="byte-lane' + (spec.compact ? " byte-lane--compact" : "") + '">';
    html += '<div class="byte-lane__head"><div class="byte-lane__title">' + (spec.title || "byte layout") +
      (spec.badge ? ' <span class="badge">' + spec.badge + "</span>" : "") +
      '</div><div class="byte-lane__legend"><span><i></i> click a field</span><span>byte offsets</span></div></div>';
    html += `<div class="byte-lane__scroll"><div class="byte-lane__inner" style="--cols:${columns}"><div class="byte-lane__track">`;
    fields.forEach((f) => {
      const size = f.variable ? "var" : f._displayBytes + " B";
      html += `<button type="button" class="byte-field" data-byte-field="${esc(f.id)}" data-variable="${f.variable ? "1" : "0"}" ` +
        `style="--tone:var(--tone-${esc(f.tone)})" ` +
        `aria-label="${esc(f.name)}, ${size}, starting at byte ${f._start}">` +
        `<span class="bf-name">${esc(f.name)}</span>` +
        `<span class="bf-size">${esc(size)}</span>` +
        `<span class="bf-off">+${f._start}</span>` +
        (f.variable ? '<span class="bf-ellipsis">…</span>' : "") +
        "</button>";
    });
    html += '</div><div class="byte-lane__ticks">';
    fields.forEach((f) => {
      html += `<span>${f._start}</span>`;
    });
    html += "</div></div></div>";
    html += `<p class="diagram__note">${spec.note || "Byte-aligned wire layout. Variable-length fields are shown at a nominal width; the actual length is carried by the field before them (or by the packet boundary)."}</p>`;
    html += "</div>";
    el.innerHTML = html;
    const fieldById = new Map(fields.map((f) => [f.id, f]));
    const blocks = $$(".byte-field", el);
    let selected = null;

    function setHot(id, on) { blocks.forEach((b) => { if (b.dataset.byteField === id) b.classList.toggle("is-hot", on); }); }
    function select(id) {
      selected = id;
      blocks.forEach((b) => b.classList.toggle("is-selected", b.dataset.byteField === id));
      const f = fieldById.get(id);
      if (f) renderInspector(inspector, f, { start: f._start, end: f._end, byteMode: true });
    }
    function clear() {
      selected = null;
      blocks.forEach((b) => b.classList.remove("is-selected"));
      renderInspector(inspector, null);
    }
    el.addEventListener("mouseover", (event) => {
      const b = event.target.closest(".byte-field");
      if (!b || !el.contains(b)) return;
      setHot(b.dataset.byteField, true);
      const f = fieldById.get(b.dataset.byteField);
      if (f) renderInspector(inspector, f, { start: f._start, end: f._end, byteMode: true });
    });
    el.addEventListener("mouseout", (event) => {
      const b = event.target.closest(".byte-field");
      if (!b || !el.contains(b)) return;
      const rel = event.relatedTarget && event.relatedTarget.closest ? event.relatedTarget.closest(".byte-field") : null;
      if (rel && rel.dataset.byteField === b.dataset.byteField) return;
      setHot(b.dataset.byteField, false);
      if (selected) {
        const f = fieldById.get(selected);
        renderInspector(inspector, f, { start: f._start, end: f._end, byteMode: true });
      } else renderInspector(inspector, null);
    });
    el.addEventListener("click", (event) => {
      const b = event.target.closest(".byte-field");
      if (!b || !el.contains(b)) return;
      if (selected === b.dataset.byteField) clear();
      else select(b.dataset.byteField);
    });
    el.addEventListener("keydown", (event) => {
      if (event.key === "Escape") clear();
    });
    if (inspector) renderInspector(inspector, null);
    return {
      el, fields,
      select, clear,
      get selected() { return selected; },
      setValues(values) {
        Object.keys(values || {}).forEach((id) => {
          const f = fieldById.get(id);
          if (!f) return;
          f.value = values[id];
          el.querySelectorAll(`.byte-field[data-byte-field="${CSS.escape(id)}"] .bf-size`).forEach((m) => {
            m.textContent = values[id];
          });
        });
        if (selected) {
          const f = fieldById.get(selected);
          renderInspector(inspector, f, { start: f._start, end: f._end, byteMode: true });
        }
      }
    };
  }

  function tabs(root) {
    const el = typeof root === "string" ? $(root) : root;
    if (!el) return;
    const tabButtons = $$('[role="tab"]', el);
    function activate(btn) {
      tabButtons.forEach((b) => {
        const on = b === btn;
        b.setAttribute("aria-selected", on ? "true" : "false");
        b.tabIndex = on ? 0 : -1;
        const panel = document.getElementById(b.getAttribute("aria-controls"));
        if (panel) panel.hidden = !on;
      });
      btn.focus();
    }
    tabButtons.forEach((btn, i) => {
      btn.addEventListener("click", () => activate(btn));
      btn.addEventListener("keydown", (event) => {
        if (event.key !== "ArrowRight" && event.key !== "ArrowLeft" && event.key !== "Home" && event.key !== "End") return;
        event.preventDefault();
        let next = i;
        if (event.key === "ArrowRight") next = (i + 1) % tabButtons.length;
        if (event.key === "ArrowLeft") next = (i - 1 + tabButtons.length) % tabButtons.length;
        if (event.key === "Home") next = 0;
        if (event.key === "End") next = tabButtons.length - 1;
        activate(tabButtons[next]);
      });
    });
  }


  /* ---------- protocol taxonomy ---------- */
  function initStacks() {
    const data = window.PH_PROTOCOLS || {};
    $$("[data-stack]").forEach((el) => {
      const info = data[el.getAttribute("data-stack")];
      if (!info) { el.hidden = true; return; }
      const path = (info.path || []).map((seg) => {
        const note = seg.note ? `<small>${esc(seg.note)}</small>` : "";
        if (seg.current) return `<li class="is-current"><span aria-current="location">${esc(seg.label)}</span>${note}</li>`;
        if (seg.href) return `<li><a href="${esc(seg.href)}">${esc(seg.label)}</a>${note}</li>`;
        return `<li><span>${esc(seg.label)}</span>${note}</li>`;
      });
      const sep = '<li class="stackbar__arrow" aria-hidden="true">→</li>';
      el.hidden = false;
      el.innerHTML =
        '<div class="stackbar__layer">' +
        `<span class="layer-code">${esc(info.layerCode)}</span>` +
        `<div><b>${esc(info.layerLabel)}</b><small>${esc(info.layerNote)}</small></div>` +
        "</div>" +
        `<ol class="stackbar__path" aria-label="Encapsulation path">${path.join(sep)}</ol>`;
    });
  }


  function initStackModel() {
    const host = $("[data-stack-model]");
    if (!host) return;
    const layers = window.PH_STACK || [];
    const protocols = window.PH_PROTOCOLS || {};
    if (!layers.length || !Object.keys(protocols).length) { host.hidden = true; return; }
    const layerKeys = new Set(layers.map((layer) => layer.key));
    const entries = Object.keys(protocols)
      .map((key) => Object.assign({ key }, protocols[key]))
      .filter((p) => p.modelLayer && layerKeys.has(p.modelLayer));
    const presentNames = new Set(entries.map((p) => p.name));
    const tones = ["a", "b", "c", "d", "e", "f", "g"];
    const byLayer = {};
    entries.forEach((p, i) => {
      if (!byLayer[p.modelLayer]) byLayer[p.modelLayer] = [];
      p._tone = p.tone || tones[i % tones.length];
      byLayer[p.modelLayer].push(p);
    });
    const rows = layers.map((layer) => {
      const items = byLayer[layer.key] || [];
      const planned = (layer.planned || []).filter((name) => !entries.some((p) => p.name.toLowerCase().includes(name.toLowerCase()) || name.toLowerCase().includes(p.name.toLowerCase())));
      const canFilter = items.length > 0;
      const labelInner =
        `<span class="layer-code">${esc(layer.code)}</span>` +
        `<span class="stack-layer__text"><b>${esc(layer.name)}</b><small>${esc(layer.note)}</small></span>` +
        `<span class="stack-layer__count">${items.length || "soon"}</span>`;
      const label = canFilter
        ? `<button type="button" class="stack-layer__filter" data-layer-filter="${esc(layer.key)}" aria-pressed="false" aria-label="Filter field sheets to ${esc(layer.name)}">${labelInner}</button>`
        : `<div class="stack-layer__filter stack-layer__filter--static">${labelInner}</div>`;
      const nodes = items.map((p) =>
        `<a class="stack-node" href="${esc(p.href || p.key + ".html")}" style="--tone:var(--tone-${esc(p._tone)})">` +
        `<span class="stack-node__name">${esc(p.name)}</span>` +
        `<span class="stack-node__note">${esc(p.modelNote || p.layerNote || "")}</span>` +
        `</a>`
      ).join("");
      const plannedNodes = planned.map((name) =>
        `<span class="stack-node stack-node--planned"><span class="stack-node__name">${esc(name)}</span><small>planned</small></span>`
      ).join("");
      return `<div class="stack-layer${layer.overlay ? " stack-layer--overlay" : ""}${items.length ? "" : " stack-layer--empty"}" data-layer-row="${esc(layer.key)}">` +
        label +
        `<div class="stack-layer__body">${nodes}${plannedNodes || (items.length ? "" : '<span class="stack-layer__placeholder">no protocol page yet</span>')}</div>` +
        `</div>`;
    }).join("");
    host.hidden = false;
    host.innerHTML =
      `<div class="stack-model__head"><span>TCP/IP model</span><span data-stack-model-status>${entries.length} protocol pages · ${layers.length} layers</span></div>` +
      rows +
      `<div class="stack-model__foot"><span class="layer-code">ALL</span>` +
      `<div><b>Packet dissector</b><small>one frame · every layer · hex sync</small></div>` +
      `<a href="dissect.html">open dissector →</a></div>`;
  }

  function initProtocolFilter() {
    const bar = $("[data-protocol-filter]");
    if (!bar) return;
    const buttons = $$("[data-layer-filter]");
    const chips = $$(".layer-chip[data-layer-filter]", bar);
    const cards = $$("#protocol-grid .protocol-card");
    const rows = $$("[data-layer-row]");
    const status = $(".protocol-filter__status", bar);
    const modelStatus = $("[data-stack-model-status]");
    const modelDefault = modelStatus ? modelStatus.textContent : "";
    if (!buttons.length || !cards.length) return;

    function matches(layer, filter) {
      return filter === "all" || layer === filter;
    }

    function apply(filter) {
      let shown = 0;
      cards.forEach((card) => {
        const show = matches(card.dataset.layer, filter);
        card.hidden = !show;
        if (show) shown += 1;
      });
      buttons.forEach((btn) => {
        const on = btn.getAttribute("data-layer-filter") === filter;
        btn.classList.toggle("is-active", on);
        btn.setAttribute("aria-pressed", on ? "true" : "false");
      });
      let activeName = filter === "tools" ? "Cross-layer" : "";
      rows.forEach((row) => {
        const on = filter !== "all" && row.getAttribute("data-layer-row") === filter;
        row.classList.toggle("is-active", on);
        if (on) {
          const label = row.querySelector(".stack-layer__text b");
          if (label) activeName = label.textContent;
        }
      });
      if (status) status.textContent = shown + (shown === 1 ? " entry" : " entries") + " shown";
      if (modelStatus) modelStatus.textContent = filter === "all" ? modelDefault : activeName + " · " + shown + (shown === 1 ? " field sheet" : " field sheets");
    }

    chips.forEach((btn) => {
      const filter = btn.getAttribute("data-layer-filter");
      const count = cards.filter((card) => matches(card.dataset.layer, filter)).length;
      const badge = btn.querySelector("b");
      if (badge) badge.textContent = String(count);
    });
    buttons.forEach((btn) => btn.addEventListener("click", () => apply(btn.getAttribute("data-layer-filter"))));
    apply("all");
  }

  /* ---------- search ---------- */
  let searchDialog = null;
  let searchInput = null;
  let searchList = null;
  let searchEmpty = null;
  let searchActive = -1;
  let searchResults = [];

  function searchEntries() {
    return Array.isArray(window.PH_SEARCH) ? window.PH_SEARCH : [];
  }

  function scoreEntry(entry, terms) {
    let score = 0;
    const name = (entry.name || "").toLowerCase();
    const text = ((entry.meta || "") + " " + (entry.text || "") + " " + (entry.p || "")).toLowerCase();
    for (const term of terms) {
      if (!term) continue;
      if (name === term) score += 60;
      else if (name.startsWith(term)) score += 34;
      else if (name.includes(term)) score += 22;
      else if (text.includes(term)) score += 7;
      else return -1;
    }
    return score;
  }

  function filterSearch(query) {
    const entries = searchEntries();
    const q = query.trim().toLowerCase();
    if (!q) {
      return entries.filter((e) => e.kind === "protocol").slice(0, 8)
        .concat(entries.filter((e) => e.kind !== "protocol" && e.popular).slice(0, 6));
    }
    const terms = q.split(/\s+/).filter(Boolean);
    return entries
      .map((e) => ({ e, s: scoreEntry(e, terms) }))
      .filter((x) => x.s >= 0)
      .sort((a, b) => b.s - a.s || (a.e.name || "").localeCompare(b.e.name || ""))
      .slice(0, 30)
      .map((x) => x.e);
  }

  function buildSearchDialog() {
    if (searchDialog) return;
    searchDialog = document.createElement("dialog");
    searchDialog.className = "search-dialog";
    searchDialog.setAttribute("aria-label", "Search protocols and fields");
    searchDialog.innerHTML =
      '<div class="search-dialog__head">' +
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="11" cy="11" r="7"></circle><path d="m20 20-3.5-3.5"></path></svg>' +
      '<input type="search" id="ph-search-input" placeholder="search fields, flags, RFCs, hex…" autocomplete="off" spellcheck="false" aria-label="Search">' +
      '<kbd>esc</kbd></div>' +
      '<div class="search-dialog__body"><div class="search-dialog__group">jump to</div><ul class="search-dialog__list" role="listbox" aria-label="Search results"></ul><div class="search-dialog__empty" hidden>No matches. Try <code>SACK</code>, <code>0x94</code>, <code>fragment</code>, or <code>RFC 9000</code>.</div></div>' +
      '<div class="search-dialog__foot"><span><kbd>↑</kbd><kbd>↓</kbd> navigate</span><span><kbd>↵</kbd> open</span><span><kbd>/</kbd> search anywhere</span><span>no network requests</span></div>';
    document.body.appendChild(searchDialog);
    searchInput = $("#ph-search-input", searchDialog);
    searchList = $(".search-dialog__list", searchDialog);
    searchEmpty = $(".search-dialog__empty", searchDialog);

    searchInput.addEventListener("input", () => renderSearch(searchInput.value));
    searchInput.addEventListener("keydown", (event) => {
      if (event.key === "ArrowDown") { event.preventDefault(); moveSearch(1); }
      else if (event.key === "ArrowUp") { event.preventDefault(); moveSearch(-1); }
      else if (event.key === "Enter") {
        event.preventDefault();
        if (searchResults[searchActive]) goSearch(searchResults[searchActive]);
      } else if (event.key === "Escape") {
        searchDialog.close();
      }
    });
    searchDialog.addEventListener("click", (event) => {
      if (event.target === searchDialog) searchDialog.close();
    });
    searchDialog.addEventListener("close", () => { searchActive = -1; });
  }

  function renderSearch(query) {
    searchResults = filterSearch(query);
    searchActive = -1;
    if (!searchResults.length) {
      searchList.innerHTML = "";
      searchEmpty.hidden = false;
      return;
    }
    searchEmpty.hidden = true;
    searchList.innerHTML = searchResults.map((e, i) =>
      `<li role="option"><button type="button" data-index="${i}" aria-selected="false">` +
      `<span class="p">${esc(e.p || "")}</span>` +
      `<span class="n">${esc(e.name || "")}</span>` +
      `<span class="m">${esc(e.meta || "")}</span>` +
      "</button></li>").join("");
    $$("button", searchList).forEach((btn) => {
      btn.addEventListener("click", () => goSearch(searchResults[Number(btn.dataset.index)]));
    });
  }

  function moveSearch(dir) {
    if (!searchResults.length) return;
    searchActive = (searchActive + dir + searchResults.length) % searchResults.length;
    $$("button", searchList).forEach((btn, i) => btn.setAttribute("aria-selected", i === searchActive ? "true" : "false"));
    const active = $$("button", searchList)[searchActive];
    if (active) active.scrollIntoView({ block: "nearest" });
  }

  function goSearch(entry) {
    if (!entry) return;
    searchDialog.close();
    location.href = entry.href;
  }

  function openSearch(preset) {
    buildSearchDialog();
    if (searchDialog.open) {
      if (preset != null) { searchInput.value = preset; renderSearch(preset); }
      setTimeout(() => searchInput.focus(), 10);
      return;
    }
    renderSearch(preset || "");
    if (preset) searchInput.value = preset;
    if (typeof searchDialog.showModal === "function") searchDialog.showModal();
    else searchDialog.setAttribute("open", "");
    setTimeout(() => searchInput.focus(), 10);
  }

  function bindSearch() {
    $$("[data-search-open]").forEach((btn) => btn.addEventListener("click", (e) => {
      e.preventDefault();
      openSearch("");
    }));
    document.addEventListener("keydown", (event) => {
      const tag = (event.target.tagName || "").toLowerCase();
      const typing = tag === "input" || tag === "textarea" || tag === "select" || event.target.isContentEditable;
      if ((event.key === "/" && !typing) || ((event.metaKey || event.ctrlKey) && event.key.toLowerCase() === "k")) {
        event.preventDefault();
        openSearch("");
      }
    });
    $$("[data-home-search]").forEach(bindHomeSearch);
  }

  function bindHomeSearch(form) {
    const input = $("input", form);
    const results = $(".home-search__results", form);
    const meta = $(".home-search__meta span:last-child", form);
    if (!input || !results) return;
    function run() {
      const list = filterSearch(input.value).slice(0, 8);
      if (!input.value.trim()) {
        results.innerHTML = "";
        if (meta) meta.textContent = "fuzzy search across every page";
        return;
      }
      if (!list.length) {
        results.innerHTML = '<li class="empty">No match. Try “SACK”, “fragment”, “varint”, or “0x94”.</li>';
        if (meta) meta.textContent = "0 results";
        return;
      }
      results.innerHTML = list.map((e) =>
        `<li><a href="${esc(e.href)}"><span class="p">${esc(e.p || "")}</span>` +
        `<span class="n">${esc(e.name || "")}</span><span class="m">${esc(e.meta || "")}</span></a></li>`
      ).join("");
      if (meta) meta.textContent = list.length + " shown · press / for the full index";
    }
    input.addEventListener("input", run);
    input.addEventListener("keydown", (event) => {
      if (event.key !== "Enter") return;
      const first = $("a", results);
      if (first) { event.preventDefault(); location.href = first.getAttribute("href"); }
    });
  }

  /* ---------- theme ---------- */
  const THEMES = ["green", "amber", "ice", "pink", "bone"];
  function applyTheme(name, persist) {
    const theme = THEMES.includes(name) ? name : "green";
    if (theme === "green") document.documentElement.removeAttribute("data-theme");
    else document.documentElement.setAttribute("data-theme", theme);
    $$("[data-theme-name]").forEach((el) => { el.textContent = theme; });
    $$("[data-theme-toggle]").forEach((el) => {
      el.setAttribute("title", "Theme: " + theme + " — click to cycle");
      el.setAttribute("aria-label", "Theme: " + theme + ". Click to cycle.");
    });
    const meta = $('meta[name="theme-color"]');
    if (meta) meta.setAttribute("content", getComputedStyle(document.documentElement).getPropertyValue("--bg").trim() || "#0b0e14");
    if (persist) {
      try { localStorage.setItem("ph-theme", theme); } catch (_) { /* noop */ }
    }
  }
  function initTheme() {
    let saved = null;
    try { saved = localStorage.getItem("ph-theme"); } catch (_) { /* noop */ }
    const params = new URLSearchParams(location.search);
    applyTheme(params.get("theme") || saved || "green", false);
    $$("[data-theme-toggle]").forEach((btn) => btn.addEventListener("click", () => {
      const current = document.documentElement.getAttribute("data-theme") || "green";
      const idx = THEMES.indexOf(current);
      applyTheme(THEMES[(idx + 1) % THEMES.length], true);
    }));
  }

  /* ---------- misc bindings ---------- */
  function initCopy() {
    document.addEventListener("click", (event) => {
      const btn = event.target.closest("[data-copy], .copy-btn");
      if (!btn) return;
      event.preventDefault();
      let text = btn.getAttribute("data-copy");
      if (!text) {
        const target = btn.getAttribute("data-copy-target");
        if (target) {
          const el = $(target);
          if (el) text = el.textContent;
        }
      }
      if (!text) {
        const output = btn.closest(".output");
        if (output) text = output.textContent;
      }
      if (!text) return;
      copyText(text).then((ok) => toast(ok ? "copied to clipboard" : "copy failed"));
    });
  }

  function initSiteHeader() {
    const hosts = $$("[data-site-header]");
    if (!hosts.length) return;
    const current = (location.pathname.split("/").pop() || "").replace(/\.html$/, "");
    const about = current === "about"
      ? ""
      : '<a class="icon-btn" href="about.html">about</a>';
    const html =
      '<div class="site-header__inner">' +
      `<a class="brand" href="${homeHref()}" aria-label="netlens.dev home">` +
      '<span class="brand__box"><span class="prompt">$</span> netlens.dev <span class="brand__cursor" aria-hidden="true"></span></span>' +
      '</a>' +
      '<span class="brand__rule" aria-hidden="true"></span>' +
      '<div class="header-tools">' +
      '<button class="icon-btn icon-btn--search" type="button" data-search-open aria-label="Search protocols and fields">' +
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="11" cy="11" r="7"></circle><path d="m20 20-3.5-3.5"></path></svg>' +
      '<span>search</span><span class="kbd-hint">/</span>' +
      '</button>' +
      about +
      '<a class="icon-btn icon-btn--square" href="https://github.com/xetxezarreta/netlens.dev" target="_blank" rel="noopener" aria-label="View source on GitHub" title="View source on GitHub">' +
      '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><path d="M12 .5C5.73.5.75 5.48.75 11.75c0 4.97 3.22 9.18 7.69 10.67.56.1.77-.24.77-.54 0-.27-.01-1.16-.02-2.1-3.13.68-3.79-1.51-3.79-1.51-.51-1.3-1.25-1.65-1.25-1.65-1.02-.7.08-.69.08-.69 1.13.08 1.72 1.16 1.72 1.16 1 1.72 2.63 1.22 3.27.93.1-.72.39-1.22.71-1.5-2.5-.28-5.13-1.25-5.13-5.57 0-1.23.44-2.23 1.16-3.02-.12-.28-.5-1.42.11-2.96 0 0 .95-.3 3.1 1.15a10.8 10.8 0 0 1 5.64 0c2.15-1.45 3.1-1.15 3.1-1.15.61 1.54.23 2.68.11 2.96.72.79 1.16 1.79 1.16 3.02 0 4.33-2.64 5.29-5.15 5.56.4.35.76 1.04.76 2.1 0 1.52-.01 2.74-.01 3.11 0 .3.2.65.78.54a11.26 11.26 0 0 0 7.68-10.67C23.25 5.48 18.27.5 12 .5z"></path></svg>' +
      '</a>' +
      '<button class="icon-btn" type="button" data-theme-toggle aria-label="Change theme">' +
      '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><circle cx="12" cy="12" r="4"></circle><path d="M12 2v2M12 20v2M4.9 4.9l1.4 1.4M17.7 17.7l1.4 1.4M2 12h2M20 12h2M4.9 19.1l1.4-1.4M17.7 6.3l1.4-1.4"></path></svg>' +
      '<span data-theme-name>green</span>' +
      '</button>' +
      '</div></div>';
    hosts.forEach((host) => { host.innerHTML = html; });
  }

  function initSiteFooter() {
    const hosts = $$("[data-site-footer]");
    if (!hosts.length) return;
    const protocols = window.PH_PROTOCOLS || {};
    const links = [`<a href="${homeHref()}">home</a>`];
    Object.keys(protocols).forEach((key) => {
      if (protocols[key].footer === false) return;
      links.push(`<a href="${esc(key)}.html">${esc(key)}</a>`);
    });
    links.push('<a href="about.html">about</a>');
    links.push('<a href="about.html#contact">contact</a>');
    const html =
      '<div class="site-footer__inner">' +
      '<div><span class="foot-brand">netlens.dev</span> · wire formats, bit by bit<br>© <span data-year>2026</span> · static field guide · no trackers</div>' +
      '<div class="foot-note">RFCs are the source of truth. Diagrams are educational; check the current RFC, errata and your implementation before putting anything on the wire.</div>' +
      `<div class="foot-links">${links.join("")}</div>` +
      '</div>';
    hosts.forEach((host) => { host.innerHTML = html; });
  }

  function initMobileNav() {
    const header = $(".site-header");
    const tools = header ? $(".header-tools", header) : null;
    if (!header || !tools || $("[data-mobile-nav]", tools)) return;
    const protocols = window.PH_PROTOCOLS || {};
    const layers = window.PH_STACK || [];
    if (!Object.keys(protocols).length || !layers.length) return;

    const current = (location.pathname.split("/").pop() || "").replace(/\.html$/, "");
    const layerKeys = new Set(layers.map((layer) => layer.key));
    const link = (key, label) => {
      const active = key === current ? ' class="is-active" aria-current="page"' : "";
      return `<li><a href="${esc(key)}.html"${active}>${esc(label)}</a></li>`;
    };
    let html = '<div class="mobile-nav__group"><p class="rail__label">site</p><ul>' +
      `<li><a href="${homeHref()}"${current === "" || current === "index" ? ' class="is-active" aria-current="page"' : ""}>home</a></li>` +
      "</ul></div>";

    layers.forEach((layer) => {
      const keys = Object.keys(protocols).filter((key) => protocols[key].modelLayer === layer.key);
      if (!keys.length) return;
      html += `<div class="mobile-nav__group"><p class="rail__label">${esc(layer.name)}</p><ul>` +
        keys.map((key) => link(key, protocols[key].name || key)).join("") + "</ul></div>";
    });

    const cross = Object.keys(protocols).filter((key) => protocols[key].modelLayer && !layerKeys.has(protocols[key].modelLayer));
    if (cross.length) {
      html += '<div class="mobile-nav__group"><p class="rail__label">cross-layer</p><ul>' +
        cross.map((key) => link(key, protocols[key].name || key)).join("") + "</ul></div>";
    }

    html += '<div class="mobile-nav__group"><p class="rail__label">about</p><ul>' +
      `<li><a href="about.html"${current === "about" ? ' class="is-active" aria-current="page"' : ""}>about &amp; conventions</a></li>` +
      '<li><a href="about.html#contact">contact</a></li>' +
      "</ul></div>";

    const btn = document.createElement("button");
    btn.type = "button";
    btn.className = "icon-btn mobile-nav-btn";
    btn.setAttribute("data-mobile-nav", "");
    btn.setAttribute("aria-label", "Open navigation");
    btn.setAttribute("aria-expanded", "false");
    btn.setAttribute("aria-controls", "ph-mobile-nav");
    btn.innerHTML = '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" aria-hidden="true"><path d="M4 6h16M4 12h16M4 18h16"></path></svg><span>menu</span>';
    tools.insertBefore(btn, tools.firstChild);

    const panel = document.createElement("div");
    panel.className = "mobile-nav";
    panel.id = "ph-mobile-nav";
    panel.hidden = true;
    panel.setAttribute("role", "navigation");
    panel.setAttribute("aria-label", "Site navigation");
    panel.innerHTML = html;
    header.appendChild(panel);

    function setOpen(open) {
      panel.hidden = !open;
      btn.setAttribute("aria-expanded", open ? "true" : "false");
      btn.classList.toggle("is-active", open);
    }
    btn.addEventListener("click", () => setOpen(panel.hidden));
    panel.addEventListener("click", (event) => {
      if (event.target.closest("a")) setOpen(false);
    });
    document.addEventListener("click", (event) => {
      if (panel.hidden) return;
      if (panel.contains(event.target) || btn.contains(event.target)) return;
      setOpen(false);
    });
    document.addEventListener("keydown", (event) => {
      if (event.key === "Escape" && !panel.hidden) {
        setOpen(false);
        btn.focus();
      }
    });
    window.addEventListener("resize", () => {
      if (window.innerWidth > 980) setOpen(false);
    });
  }

  function initRailProtocols() {
    const host = $("[data-rail-protocols]");
    if (!host) return;
    const protocols = window.PH_PROTOCOLS || {};
    const current = (location.pathname.split("/").pop() || "").replace(/\.html$/, "");
    const items = Object.keys(protocols)
      .filter((key) => protocols[key].rail !== false)
      .map((key) => {
        const p = protocols[key];
        const active = key === current ? ' class="is-active"' : "";
        const layer = p.railLayer || p.modelLayer || "";
        return `<li><a href="${esc(key)}.html"${active} data-layer="${esc(layer)}" title="${esc(layer)}">${esc(key)}</a></li>`;
      });
    host.innerHTML = "<ul>" + items.join("") + "</ul>";
  }

  function initMobileToc() {
    const main = $("main");
    if (!main || $("[data-mobile-toc]")) return;
    const seen = new Set();
    let links = $$('.rail a[href^="#"]')
      .filter((a) => {
        const href = a.getAttribute("href");
        if (!href || seen.has(href)) return false;
        seen.add(href);
        return true;
      })
      .map((a) => ({ href: a.getAttribute("href"), label: a.textContent.trim() }));
    let insertAfter = main.querySelector(".page-head");
    let insertBefore = null;

    if (!links.length) {
      const sections = $$("main section[id]");
      links = sections
        .map((section) => {
          const heading = section.querySelector("h2");
          if (!heading) return null;
          return { href: "#" + section.id, label: heading.textContent.trim() };
        })
        .filter(Boolean);
      if (!links.length) return;
      insertAfter = null;
      insertBefore = sections[0];
    }

    const details = document.createElement("details");
    details.className = "mobile-toc";
    details.setAttribute("data-mobile-toc", "");
    details.innerHTML =
      "<summary>on this page</summary><ul>" +
      links.map((link) => `<li><a href="${esc(link.href)}">${esc(link.label)}</a></li>`).join("") +
      "</ul>";

    if (insertAfter) insertAfter.insertAdjacentElement("afterend", details);
    else if (insertBefore && insertBefore.parentNode) insertBefore.parentNode.insertBefore(details, insertBefore);
    else main.prepend(details);

    details.addEventListener("click", (event) => {
      if (event.target.closest("a")) details.open = false;
    });
  }

  function initRail() {
    const links = $$('.rail a[href^="#"], .mobile-toc a[href^="#"]');
    if (!links.length || !("IntersectionObserver" in window)) return;
    const sections = links.map((a) => document.getElementById(a.getAttribute("href").slice(1))).filter(Boolean);
    if (!sections.length) return;
    const observer = new IntersectionObserver((entries) => {
      entries.forEach((entry) => {
        if (!entry.isIntersecting) return;
        links.forEach((a) => {
          const on = a.getAttribute("href") === "#" + entry.target.id;
          a.classList.toggle("is-active", on);
          if (on) a.setAttribute("aria-current", "location");
          else a.removeAttribute("aria-current");
        });
      });
    }, { rootMargin: "-15% 0px -70% 0px", threshold: 0 });
    sections.forEach((s) => observer.observe(s));
  }

  function initTabs() {
    $$("[data-tabs]").forEach((el) => tabs(el));
  }

  function initYear() {
    $$("[data-year]").forEach((el) => { el.textContent = new Date().getFullYear(); });
  }

  function initExternal() {
    $$('a[target="_blank"]').forEach((a) => {
      if (!a.rel) a.rel = "noopener";
    });
  }

  // Static markup and noscript fallbacks still point at index.html; rewrite
  // visible home links to the root so navigating home never shows the filename.
  function initHomeLinks() {
    const home = homeHref();
    if (home === "index.html") return;
    const from = "index.html";
    $$("a[href]").forEach((a) => {
      const href = a.getAttribute("href");
      if (href === from) a.setAttribute("href", home);
      else if (href.indexOf(from + "#") === 0) a.setAttribute("href", home + href.slice(from.length));
    });
  }


  /* ---------- shareable state (URL hash) and text export ---------- */

  function bytesToBase64Url(bytes) {
    let binary = "";
    const chunk = 0x8000;
    for (let i = 0; i < bytes.length; i += chunk) {
      binary += String.fromCharCode.apply(null, Array.from(bytes.subarray(i, i + chunk)));
    }
    return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
  }

  function base64UrlToBytes(text) {
    const normalized = String(text).replace(/-/g, "+").replace(/_/g, "/");
    const padded = normalized + "=".repeat((4 - (normalized.length % 4)) % 4);
    const binary = atob(padded);
    const bytes = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    return bytes;
  }

  function encodeState(value) {
    const json = JSON.stringify(value);
    const bytes = typeof TextEncoder !== "undefined"
      ? new TextEncoder().encode(json)
      : Uint8Array.from(Array.from(json).map((c) => c.charCodeAt(0) & 255));
    return bytesToBase64Url(bytes);
  }

  function decodeState(text) {
    try {
      const bytes = base64UrlToBytes(text);
      const json = typeof TextDecoder !== "undefined"
        ? new TextDecoder().decode(bytes)
        : String.fromCharCode.apply(null, Array.from(bytes));
      return JSON.parse(json);
    } catch (_) { return null; }
  }

  function readHashState() {
    const match = String(location.hash || "").match(/[#&]s=([^&]+)/);
    return match ? decodeState(match[1]) : null;
  }

  function hashForState(value) {
    return "#s=" + encodeState(value);
  }

  function shareState(value, message) {
    const url = location.origin && location.origin !== "null"
      ? location.origin + location.pathname + location.search + hashForState(value)
      : location.href.split("#")[0] + hashForState(value);
    history.replaceState(null, "", hashForState(value));
    copyText(url).then(() => toast(message || "permalink copied"), () => toast("could not copy permalink"));
    return url;
  }

  function downloadText(filename, text, mime) {
    const blob = new Blob([text], { type: mime || "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const link = document.createElement("a");
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    link.remove();
    setTimeout(() => URL.revokeObjectURL(url), 1000);
  }

  function captureFormState() {
    const values = {};
    $$("main input[id], main select[id], main textarea[id]").forEach((el) => {
      const type = (el.getAttribute("type") || "").toLowerCase();
      if (["button", "submit", "reset", "file", "image"].includes(type)) return;
      if (el.type === "checkbox" || el.type === "radio") values[el.id] = el.checked;
      else values[el.id] = el.value;
    });
    return values;
  }

  function applyFormState(values) {
    if (!values) return;
    Object.keys(values).forEach((id) => {
      const el = document.getElementById(id);
      if (!el) return;
      if (el.type === "checkbox" || el.type === "radio") el.checked = !!values[id];
      else el.value = values[id];
      el.dispatchEvent(new Event("input", { bubbles: true }));
      el.dispatchEvent(new Event("change", { bubbles: true }));
    });
  }

  function stateForPage() {
    return {
      page: "form",
      path: location.pathname,
      values: captureFormState()
    };
  }

  function restorePageState() {
    const state = readHashState();
    if (!state || state.page !== "form" || state.path !== location.pathname) return false;
    setTimeout(() => applyFormState(state.values), 0);
    return true;
  }

  function pageSnapshot() {
    const outputs = {};
    $$("main pre[id]").forEach((el) => {
      const text = el.textContent.trim();
      if (text) outputs[el.id] = text;
    });
    return {
      page: "snapshot",
      path: location.pathname,
      title: document.title,
      url: location.href.split("#")[0],
      values: captureFormState(),
      outputs
    };
  }

  function initPermalink() {
    const head = $(".page-head");
    if (!head || $("[data-state-permalink]", head)) return;
    if (!$("main input[id], main select[id], main textarea[id]")) return;
    const row = document.createElement("div");
    row.className = "btn-row";
    row.style.marginTop = "8px";
    row.setAttribute("data-page-actions", "");

    const link = document.createElement("button");
    link.type = "button";
    link.className = "btn btn--ghost";
    link.setAttribute("data-state-permalink", "");
    link.textContent = "copy page link";
    link.addEventListener("click", () => {
      shareState(stateForPage(), "page-state permalink copied");
    });

    const json = document.createElement("button");
    json.type = "button";
    json.className = "btn btn--ghost";
    json.textContent = "download state JSON";
    json.addEventListener("click", () => {
      const name = (location.pathname.split("/").pop() || "page").replace(/\.html$/, "");
      downloadText(name + "-state.json", JSON.stringify(pageSnapshot(), null, 2), "application/json");
    });

    row.appendChild(link);
    row.appendChild(json);
    const badges = head.querySelector(".badges");
    if (badges) badges.insertAdjacentElement("afterend", row);
    else head.appendChild(row);
    restorePageState();
  }

  function initHeroGrid() {
    const hero = $(".hero");
    if (!hero || !window.matchMedia || !window.requestAnimationFrame) return;
    const finePointer = window.matchMedia("(hover: hover) and (pointer: fine)");
    const reducedMotion = window.matchMedia("(prefers-reduced-motion: reduce)");
    if (!finePointer.matches || reducedMotion.matches) return;

    let frame = null;
    let x = 0;
    let y = 0;

    function apply() {
      frame = null;
      hero.style.setProperty("--grid-shift-x", (x * 10).toFixed(2) + "px");
      hero.style.setProperty("--grid-shift-y", (y * 8).toFixed(2) + "px");
    }

    hero.addEventListener("pointermove", (event) => {
      const rect = hero.getBoundingClientRect();
      x = (event.clientX - rect.left) / rect.width - 0.5;
      y = (event.clientY - rect.top) / rect.height - 0.5;
      if (!frame) frame = requestAnimationFrame(apply);
    });

    hero.addEventListener("pointerleave", () => {
      if (frame) cancelAnimationFrame(frame);
      frame = null;
      hero.style.setProperty("--grid-shift-x", "0px");
      hero.style.setProperty("--grid-shift-y", "0px");
    });
  }

  function initScrollRegions() {
    const selector = ".table-wrap, .diagram__scroll, .byte-lane__scroll, .hexdump, pre";
    let raf = null;
    function mark() {
      $$(selector).forEach((el) => {
        const scrollable = el.scrollWidth > el.clientWidth + 2 && el.clientWidth > 0;
        if (scrollable) {
          if (!el.hasAttribute("tabindex")) {
            el.dataset.autoTab = "1";
            el.setAttribute("tabindex", "0");
          }
        } else if (el.dataset.autoTab === "1") {
          el.removeAttribute("tabindex");
          delete el.dataset.autoTab;
        }
      });
    }
    function schedule() {
      if (raf) return;
      raf = requestAnimationFrame(() => { raf = null; mark(); });
    }
    mark();
    window.addEventListener("resize", schedule);
    if ("MutationObserver" in window) {
      new MutationObserver(schedule).observe(document.body, { childList: true, subtree: true });
    }
  }

  function init() {
    initSiteHeader();
    initTheme();
    initCopy();
    bindSearch();
    initMobileNav();
    initSiteFooter();
    initRailProtocols();
    initMobileToc();
    initRail();
    initTabs();
    initYear();
    initExternal();
    initHomeLinks();
    initStacks();
    initStackModel();
    initProtocolFilter();
    initPermalink();
    initHeroGrid();
    initScrollRegions();
  }

  Object.assign(PH, {
    $, $$, esc, hex, bin, parseNumber, parseHex, bytesToHex, bytesToAscii, concatBytes,
    u8, u16be, u16le, u32be, u32le, u64le, put16be, put16le, put32be, put32le, put64le,
    checksum16, checksumValid, parseIPv4, ipv4String, toast, copyText, setStatus,
    hexdump, diagram, fieldTable, byteLane, renderInspector, tabs, applyTheme, openSearch, initStacks,
    encodeState, decodeState, readHashState, hashForState, shareState, downloadText,
    bytesToBase64Url, base64UrlToBytes, captureFormState, applyFormState, pageSnapshot
  });

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
