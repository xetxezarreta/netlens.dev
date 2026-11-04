/* Cross-protocol toolbox — all client-side */
(function () {
  "use strict";

  const PH = window.PH;

  function onesSum(bytes) {
    let sum = 0;
    for (let i = 0; i < bytes.length; i += 2) {
      sum += (bytes[i] << 8) + (i + 1 < bytes.length ? bytes[i + 1] : 0);
      sum = (sum & 0xffff) + (sum >>> 16);
    }
    while (sum >>> 16) sum = (sum & 0xffff) + (sum >>> 16);
    return sum;
  }

  function initChecksum() {
    const input = document.getElementById("sum-input");
    if (!input) return;
    const offset = document.getElementById("sum-offset");
    const out = document.getElementById("sum-out");
    const verify = document.getElementById("sum-verify");

    function run() {
      let bytes;
      try { bytes = PH.parseHex(input.value); }
      catch (err) {
        out.innerHTML = '<span class="err">hex error: ' + PH.esc(err.message) + "</span>";
        verify.textContent = "—";
        return;
      }
      const valid = PH.checksumValid(bytes);
      verify.textContent = valid ? "0xffff ✓" : "0x" + PH.hex(PH.checksum16(bytes), 4);
      verify.className = valid ? "good-text" : "warn-text";
      const sum = onesSum(bytes);
      const raw = (~sum) & 0xffff;
      let zeroHtml = "";
      const off = offset.value === "" ? null : Number(offset.value);
      if (off != null && Number.isInteger(off) && off >= 0 && off + 2 <= bytes.length) {
        const copy = new Uint8Array(bytes);
        copy[off] = 0;
        copy[off + 1] = 0;
        const expected = PH.checksum16(copy);
        zeroHtml = `<div class="row"><span>checksum with bytes ${off}–${off + 1} zeroed</span><b>0x${PH.hex(expected, 4)}</b></div>`;
      }
      out.innerHTML =
        `<div class="row"><span>length</span><b>${bytes.length} bytes${bytes.length % 2 ? " (odd; padded with 00)" : ""}</b></div>` +
        `<div class="row"><span>folded one's-complement sum</span><b>0x${PH.hex(sum, 4)}</b></div>` +
        `<div class="row"><span>checksum (complement)</span><b>0x${PH.hex(raw, 4)}</b></div>` +
        `<div class="row"><span>verify over whole input</span><b class="${valid ? "ok" : "warn"}">${valid ? "valid (sum = 0xffff)" : "not valid (sum = 0x" + PH.hex(sum, 4) + ")"}</b></div>` +
        zeroHtml;
    }

    document.getElementById("sum-run").addEventListener("click", run);
    document.getElementById("sum-example").addEventListener("click", () => {
      input.value = "45 BA 00 28 12 34 20 00 40 06 33 E0 0A 00 00 01 0A 00 00 02";
      offset.value = "10";
      run();
    });
    document.getElementById("sum-zero").addEventListener("click", () => {
      try {
        const bytes = PH.parseHex(input.value);
        const off = Number(offset.value);
        if (!Number.isInteger(off) || off < 0 || off + 2 > bytes.length) throw new Error("offset is outside the input");
        bytes[off] = 0;
        bytes[off + 1] = 0;
        input.value = PH.bytesToHex(bytes);
        run();
      } catch (err) {
        out.innerHTML = '<span class="err">' + PH.esc(err.message) + "</span>";
      }
    });
    input.addEventListener("keydown", (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key === "Enter") run();
    });
    run();
  }

  function initVarint() {
    const input = document.getElementById("tool-varint-input");
    if (!input) return;
    const status = document.getElementById("tool-varint-status");
    const out = document.getElementById("tool-varint-out");
    const Q = window.QUIC;
    if (!Q) return;
    document.getElementById("tool-varint-encode").addEventListener("click", () => {
      try {
        const raw = input.value.trim();
        const v = BigInt(raw);
        const bytes = Q.varintEncode(v);
        out.textContent = PH.bytesToHex(bytes) + "\n" + bytes.length + " byte(s), value " + v.toString();
        PH.setStatus(status, "encoded " + v.toString() + " → " + bytes.length + " byte(s)", "ok");
      } catch (err) {
        PH.setStatus(status, "encode error: " + err.message, "bad");
        out.textContent = "no result";
      }
    });
    document.getElementById("tool-varint-decode").addEventListener("click", () => {
      try {
        const bytes = PH.parseHex(input.value);
        const r = Q.varintDecode(bytes, 0);
        const left = bytes.length - r.size;
        out.textContent = "value " + r.value.toString() + "\n" + r.size + " byte(s), prefix " + ["00", "01", "10", "11"][r.prefix] + (left ? "\n" + left + " trailing byte(s)" : "");
        PH.setStatus(status, "decoded " + r.size + "-byte varint" + (left ? " · " + left + " trailing byte(s)" : ""), left ? "warn" : "ok");
      } catch (err) {
        PH.setStatus(status, "decode error: " + err.message, "bad");
        out.textContent = "no result";
      }
    });
  }

  function initTLV() {
    const input = document.getElementById("tlv-input");
    if (!input) return;
    const status = document.getElementById("tlv-status");
    const host = document.getElementById("tlv-out");
    const widthSel = document.getElementById("tlv-lenwidth");

    function run() {
      let bytes;
      try { bytes = PH.parseHex(input.value); }
      catch (err) {
        PH.setStatus(status, "hex error: " + err.message, "bad");
        host.innerHTML = "";
        return;
      }
      const width = widthSel.value;
      const lengthBytes = width === "1" ? 1 : 2;
      const off = 0;
      let i = 0;
      const rows = [];
      const warnings = [];
      while (i < bytes.length) {
        const start = i;
        if (i + 1 + lengthBytes > bytes.length) {
          warnings.push(`TLV at offset ${start} is truncated before its length field`);
          break;
        }
        const type = bytes[i++];
        let length;
        if (lengthBytes === 1) length = bytes[i++];
        else if (width === "2be") { length = PH.u16be(bytes, i); i += 2; }
        else { length = PH.u16le(bytes, i); i += 2; }
        if (i + length > bytes.length) {
          warnings.push(`TLV type 0x${PH.hex(type, 2)} at offset ${start} claims ${length} bytes but only ${bytes.length - i} remain`);
          break;
        }
        const data = bytes.slice(i, i + length);
        i += length;
        rows.push({ start, type, length, data });
      }
      if (!rows.length) {
        host.innerHTML = "";
        PH.setStatus(status, warnings.length ? warnings[0] : "no TLVs found", warnings.length ? "bad" : "warn");
        return;
      }
      const table = rows.map((r) =>
        `<tr><td class="num">${r.start}</td><td><code>0x${PH.hex(r.type, 2)}</code></td><td class="num">${r.length}</td><td><code>${r.data.length ? PH.esc(PH.bytesToHex(r.data)) : "—"}</code></td><td class="small">${PH.esc(PH.bytesToAscii(r.data))}</td></tr>`
      ).join("");
      host.innerHTML =
        `<div class="decode-summary"><span class="pill">${rows.length} TLV(s)</span><span class="pill">${bytes.length} B</span><span class="pill">length width ${lengthBytes}</span></div>` +
        `<div class="table-wrap" tabindex="0" style="margin-top:10px"><table class="data-table"><thead><tr><th class="num">Offset</th><th>Type</th><th class="num">Length</th><th>Value</th><th>ASCII</th></tr></thead><tbody>${table}</tbody></table></div>` +
        (warnings.length ? '<div class="callout callout--warn"><div class="callout__title">parser notes</div><ul class="dashed" style="margin:0">' + warnings.map((w) => `<li>${PH.esc(w)}</li>`).join("") + "</ul></div>" : "");
      PH.setStatus(status, `${rows.length} TLV(s) · ${i}/${bytes.length} bytes consumed${warnings.length ? " · " + warnings.length + " note(s)" : ""}`, warnings.length ? "warn" : "ok");
    }
    document.getElementById("tlv-run").addEventListener("click", run);
    widthSel.addEventListener("change", run);
    input.addEventListener("keydown", (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key === "Enter") run();
    });
    run();
  }

  function initBits() {
    const input = document.getElementById("bits-input");
    if (!input) return;
    const out = document.getElementById("bits-out");
    function run() {
      let bytes;
      try { bytes = PH.parseHex(input.value); }
      catch (err) {
        out.innerHTML = '<span class="err">hex error: ' + PH.esc(err.message) + "</span>";
        return;
      }
      const binary = Array.from(bytes, (b) => b.toString(2).padStart(8, "0")).join(" ");
      let intVal = "—";
      if (bytes.length <= 8) {
        let v = 0n;
        for (const b of bytes) v = (v << 8n) | BigInt(b);
        intVal = v.toString() + " (0x" + v.toString(16) + ")";
      } else {
        intVal = "> 8 bytes; integer view omitted";
      }
      out.innerHTML =
        `<div class="row"><span>bytes</span><b>${bytes.length}</b></div>` +
        `<div class="row"><span>hex</span><b>${PH.esc(PH.bytesToHex(bytes))}</b></div>` +
        `<div class="row"><span>binary</span><b style="word-break:break-all;text-align:right">${binary}</b></div>` +
        `<div class="row"><span>ASCII</span><b>${PH.esc(PH.bytesToAscii(bytes))}</b></div>` +
        `<div class="row"><span>unsigned integer</span><b>${PH.esc(intVal)}</b></div>`;
    }
    document.getElementById("bits-run").addEventListener("click", run);
    input.addEventListener("input", run);
    run();
  }

  function initMask() {
    const host = document.getElementById("mask-bits");
    if (!host) return;
    const hexOut = document.getElementById("mask-hex");
    const binOut = document.getElementById("mask-bin");
    const decOut = document.getElementById("mask-dec");
    function update() {
      let byte = 0;
      host.querySelectorAll("input[data-mask]").forEach((el) => {
        if (el.checked) byte |= 1 << Number(el.getAttribute("data-mask"));
      });
      hexOut.textContent = "0x" + PH.hex(byte, 2);
      binOut.textContent = byte.toString(2).padStart(8, "0");
      decOut.textContent = String(byte);
    }
    host.querySelectorAll("input[data-mask]").forEach((el) => el.addEventListener("change", update));
    update();
  }

  function init() {
    initChecksum();
    initVarint();
    initTLV();
    initBits();
    initMask();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
