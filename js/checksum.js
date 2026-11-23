/* Checksum lab page: RFC 1071, CRC-32, CRC-32c, FNV, Adler, simple sums. */
(function () {
  "use strict";

  const PH = window.PH;
  const C = window.ChecksumCodec;

  function readBytes() {
    const mode = document.getElementById("checksum-mode").value;
    const raw = document.getElementById("checksum-input").value;
    if (mode === "text") return new TextEncoder().encode(raw);
    return PH.parseHex(raw);
  }

  function copyButton(value, label) {
    return `<button class="copy-btn" type="button" data-copy="${PH.esc(value)}" aria-label="Copy ${PH.esc(label)}">copy</button>`;
  }

  function row(name, value, note, status) {
    const cls = status === "good" ? "ok" : status === "warn" ? "warn" : "";
    return `<div class="row"><span>${PH.esc(name)}<br><small class="dim">${PH.esc(note)}</small></span><span><b class="${cls}">${PH.esc(value)}</b> ${copyButton(value, name)}</span></div>`;
  }

  function render(bytes) {
    const host = document.getElementById("checksum-result");
    const a = C.analyse(bytes);
    const hex = PH.bytesToHex(bytes);
    host.innerHTML =
      `<div class="tool-result">` +
      row("Internet checksum", C.hex16(a.internet), "RFC 1071 · IPv4/TCP/UDP/ICMP") +
      row("CRC-32", C.hex32(a.crc32), "IEEE 802.3 · zlib · PNG") +
      row("CRC-32c", C.hex32(a.crc32c), "Castagnoli · SCTP · iSCSI") +
      row("FNV-1a 32", C.hex32(a.fnv1a32), "non-cryptographic hash") +
      row("FNV-1a 64", C.hex64(a.fnv1a64), "non-cryptographic hash") +
      row("Adler-32", C.hex32(a.adler32), "zlib stream checksum") +
      row("Sum-8", C.hex8(a.sum8), "8-bit sum mod 256") +
      row("XOR-8", C.hex8(a.xor8), "8-bit XOR") +
      row("LRC", C.hex8(a.lrc), "two's-complement byte sum") +
      row("Length", a.length + " B", hex ? hex.slice(0, 72) + (hex.length > 72 ? "…" : "") : "empty") +
      `</div>`;
  }

  function run(showErrors) {
    const status = document.getElementById("checksum-status");
    let bytes;
    try { bytes = readBytes(); }
    catch (err) {
      if (showErrors !== false) PH.setStatus(status, "input error: " + err.message, "bad");
      document.getElementById("checksum-result").innerHTML = "";
      return;
    }
    if (!bytes.length) {
      if (showErrors !== false) PH.setStatus(status, "no bytes supplied", "warn");
      document.getElementById("checksum-result").innerHTML = "";
      return;
    }
    render(bytes);
    PH.setStatus(status, `${bytes.length} B · Internet ${C.hex16(C.internetChecksum(bytes))} · CRC-32 ${C.hex32(C.crc32(bytes))} · CRC-32c ${C.hex32(C.crc32c(bytes))}`, "ok");
    return bytes;
  }

  function init() {
    const input = document.getElementById("checksum-input");
    if (!input) return;
    document.getElementById("checksum-run").addEventListener("click", () => run(true));
    input.addEventListener("keydown", (event) => { if (event.key === "Enter") run(true); });
    document.getElementById("checksum-mode").addEventListener("change", () => run(false));
    document.querySelectorAll("[data-checksum]").forEach((btn) => btn.addEventListener("click", () => {
      document.getElementById("checksum-mode").value = "hex";
      input.value = btn.getAttribute("data-checksum");
      run(true);
    }));

    const verifyInput = document.getElementById("checksum-verify-input");
    function verify(showErrors) {
      const status = document.getElementById("checksum-verify-status");
      const host = document.getElementById("checksum-verify-result");
      let bytes;
      try { bytes = PH.parseHex(verifyInput.value); }
      catch (err) {
        if (showErrors !== false) PH.setStatus(status, "hex error: " + err.message, "bad");
        host.innerHTML = "";
        return;
      }
      const valid = C.checksumValid(bytes);
      const sum = C.internetChecksum(bytes);
      host.innerHTML = `<div class="tool-result"><div class="row"><span>one's-complement sum</span><b class="${valid ? "ok" : "warn"}">${valid ? "valid (0xFFFF)" : "not 0xFFFF"}</b></div><div class="row"><span>complement</span><b>${C.hex16(sum)}</b></div><div class="row"><span>bytes</span><b>${bytes.length} B</b></div></div>`;
      PH.setStatus(status, valid ? "Internet checksum verifies" : "Internet checksum does not verify", valid ? "ok" : "warn");
    }
    document.getElementById("checksum-verify").addEventListener("click", () => verify(true));
    verifyInput.addEventListener("keydown", (event) => { if (event.key === "Enter") verify(true); });
    run(false);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
