/* TLS 1.3 key-log decryption.
 *
 * This module never invents keys. It reads an SSLKEYLOGFILE-style text blob,
 * matches entries by client_random and derives the TLS 1.3 traffic keys with
 * WebCrypto HKDF + AES-GCM. Unsupported cipher suites (currently ChaCha20)
 * are reported instead of guessed. The decrypted bytes stay in this tab.
 */
(function (global) {
  "use strict";

  const PH = global.PH;
  const LABELS = {
    CLIENT_HANDSHAKE_TRAFFIC_SECRET: true,
    SERVER_HANDSHAKE_TRAFFIC_SECRET: true,
    CLIENT_TRAFFIC_SECRET_0: true,
    SERVER_TRAFFIC_SECRET_0: true,
    CLIENT_EARLY_TRAFFIC_SECRET: true,
    EXPORTER_SECRET: true
  };

  function hexToBytes(text) {
    const clean = String(text || "").replace(/[^0-9a-fA-F]/g, "");
    if (clean.length % 2) return null;
    const out = new Uint8Array(clean.length / 2);
    for (let i = 0; i < out.length; i += 1) out[i] = parseInt(clean.slice(i * 2, i * 2 + 2), 16);
    return out;
  }

  function bytesToHex(bytes) {
    return Array.from(bytes || []).map((value) => ("0" + value.toString(16)).slice(-2)).join("");
  }

  function parse(text) {
    const entries = {};
    let count = 0;
    String(text || "").split(/\r?\n/).forEach((line) => {
      const parts = line.trim().split(/\s+/);
      if (parts.length < 3) return;
      const label = parts[0];
      if (!LABELS[label]) return;
      const clientRandom = String(parts[1]).toLowerCase();
      const secret = hexToBytes(parts[2]);
      if (!secret) return;
      entries[clientRandom] = entries[clientRandom] || {};
      entries[clientRandom][label] = secret;
      count += 1;
    });
    return { entries, count };
  }

  function cipherInfo(suite) {
    if (suite === 0x1301) return { name: "TLS_AES_128_GCM_SHA256", hash: "SHA-256", keyLength: 16, ivLength: 12, algorithm: "AES-GCM" };
    if (suite === 0x1302) return { name: "TLS_AES_256_GCM_SHA384", hash: "SHA-384", keyLength: 32, ivLength: 12, algorithm: "AES-GCM" };
    if (suite === 0x1303) return { name: "TLS_CHACHA20_POLY1305_SHA256", hash: "SHA-256", keyLength: 32, ivLength: 12, algorithm: "CHACHA20-POLY1305" };
    return null;
  }

  function hkdfLabel(length, label, context) {
    const labelBytes = new TextEncoder().encode(label);
    const contextBytes = context || new Uint8Array(0);
    const out = new Uint8Array(2 + 1 + labelBytes.length + 1 + contextBytes.length);
    out[0] = (length >>> 8) & 255;
    out[1] = length & 255;
    out[2] = labelBytes.length;
    out.set(labelBytes, 3);
    out[3 + labelBytes.length] = contextBytes.length;
    out.set(contextBytes, 4 + labelBytes.length);
    return out;
  }

  async function expandLabel(secret, label, context, length, hash) {
    const subtle = global.crypto && global.crypto.subtle;
    if (!subtle) throw new Error("WebCrypto is unavailable in this browser");
    const key = await subtle.importKey("raw", secret, { name: "HKDF" }, false, ["deriveBits"]);
    const bits = await subtle.deriveBits({
      name: "HKDF", hash: { name: hash }, salt: new Uint8Array(0),
      info: hkdfLabel(length, label, context)
    }, key, length * 8);
    return new Uint8Array(bits);
  }

  function recordHeader(record) {
    const length = record.length || (record.fragment ? record.fragment.length : 0);
    return Uint8Array.from([23, 3, 3, (length >>> 8) & 255, length & 255]);
  }

  function nonceFor(iv, sequence) {
    const nonce = new Uint8Array(iv);
    let value = sequence;
    for (let i = 0; i < 8; i += 1) {
      nonce[nonce.length - 1 - i] ^= value & 255;
      value = Math.floor(value / 256);
    }
    return nonce;
  }

  async function decryptRecord(record, keyBytes, iv, sequence, cipher) {
    const subtle = global.crypto && global.crypto.subtle;
    if (!subtle) throw new Error("WebCrypto is unavailable in this browser");
    if (cipher.algorithm !== "AES-GCM") throw new Error("Cipher " + cipher.name + " is not supported by WebCrypto here");
    const key = await subtle.importKey("raw", keyBytes, { name: "AES-GCM" }, false, ["decrypt"]);
    const plain = await subtle.decrypt({
      name: "AES-GCM", iv: nonceFor(iv, sequence),
      additionalData: recordHeader(record), tagLength: 128
    }, key, record.fragment);
    return new Uint8Array(plain);
  }

  function innerContent(plain) {
    let end = plain.length - 1;
    while (end >= 0 && plain[end] === 0) end -= 1;
    if (end < 0) return { type: null, data: new Uint8Array(0) };
    return { type: plain[end], data: plain.subarray(0, end) };
  }

  async function deriveKeys(secret, cipher) {
    const key = await expandLabel(secret, "key", new Uint8Array(0), cipher.keyLength, cipher.hash);
    const iv = await expandLabel(secret, "iv", new Uint8Array(0), cipher.ivLength, cipher.hash);
    return { key, iv };
  }

  async function decryptDirection(direction, secrets, cipher) {
    const records = (direction && direction.records) || [];
    const result = { records: [], handshake: [], application: [], alerts: [], warnings: [] };
    if (!records.length || !secrets.length) return result;
    const keys = [];
    for (let i = 0; i < secrets.length; i += 1) {
      const derived = await deriveKeys(secrets[i].secret, cipher);
      keys.push({ label: secrets[i].label, secret: secrets[i].secret, key: derived.key, iv: derived.iv, sequence: 0 });
    }
    let active = 0;
    for (let i = 0; i < records.length; i += 1) {
      const record = records[i];
      if (!record.fragment || !record.fragment.length) continue;
      if (record.type != null && record.type !== 23) continue;
      let plain = null;
      let used = null;
      const order = [active].concat(keys.map((_, index) => index).filter((index) => index !== active));
      for (let j = 0; j < order.length; j += 1) {
        const candidate = keys[order[j]];
        try {
          plain = await decryptRecord(record, candidate.key, candidate.iv, candidate.sequence, cipher);
          candidate.sequence += 1;
          used = candidate;
          active = order[j];
          break;
        } catch (_) { /* try the next epoch */ }
      }
      if (!plain) {
        result.warnings.push("Record at offset " + record.offset + " did not decrypt with the supplied keys");
        continue;
      }
      const inner = innerContent(plain);
      const item = { offset: record.offset, outerLength: record.length, innerType: inner.type, data: inner.data, epoch: used ? used.label : "" };
      result.records.push(item);
      if (inner.type === 22) result.handshake.push(item);
      else if (inner.type === 23) result.application.push(item);
      else if (inner.type === 21) result.alerts.push(item);
      if (inner.type === 22 && inner.data.length && inner.data[0] === 24) {
        const hashLength = cipher.hash === "SHA-384" ? 48 : 32;
        const nextSecret = await expandLabel(used.secret, "traffic upd", new Uint8Array(0), hashLength, cipher.hash);
        const next = await deriveKeys(nextSecret, cipher);
        keys.push({ label: "KEY_UPDATE", secret: nextSecret, key: next.key, iv: next.iv, sequence: 0 });
        active = keys.length - 1;
      }
    }
    return result;
  }

  async function decryptFlow(flow, keylog) {
    const app = flow.app;
    if (!app || app.kind !== "tls" || !app.context) return { error: "Select a TLS flow first" };
    const clientRandom = bytesToHex(app.context.clientRandom);
    const entry = keylog.entries[clientRandom];
    if (!entry) return { error: "No key-log entry for client_random " + clientRandom };
    const cipher = cipherInfo(app.context.cipherSuite);
    if (!cipher) return { error: "Unsupported TLS 1.3 cipher suite 0x" + PH.hex(app.context.cipherSuite, 4) };
    if (cipher.algorithm !== "AES-GCM") return { error: cipher.name + " is not supported by WebCrypto in this browser" };
    const decoded = app.decoded || {};
    const clientSecrets = [];
    const serverSecrets = [];
    if (entry.CLIENT_HANDSHAKE_TRAFFIC_SECRET) clientSecrets.push({ label: "CLIENT_HANDSHAKE_TRAFFIC_SECRET", secret: entry.CLIENT_HANDSHAKE_TRAFFIC_SECRET });
    if (entry.CLIENT_TRAFFIC_SECRET_0) clientSecrets.push({ label: "CLIENT_TRAFFIC_SECRET_0", secret: entry.CLIENT_TRAFFIC_SECRET_0 });
    if (entry.SERVER_HANDSHAKE_TRAFFIC_SECRET) serverSecrets.push({ label: "SERVER_HANDSHAKE_TRAFFIC_SECRET", secret: entry.SERVER_HANDSHAKE_TRAFFIC_SECRET });
    if (entry.SERVER_TRAFFIC_SECRET_0) serverSecrets.push({ label: "SERVER_TRAFFIC_SECRET_0", secret: entry.SERVER_TRAFFIC_SECRET_0 });
    if (!clientSecrets.length && !serverSecrets.length) return { error: "The key-log entry has no TLS 1.3 traffic secrets" };
    try {
      const aToB = await decryptDirection(decoded.aToB, clientSecrets, cipher);
      const bToA = await decryptDirection(decoded.bToA, serverSecrets, cipher);
      return {
        clientRandom, cipher, context: app.context,
        directions: { aToB, bToA },
        warnings: aToB.warnings.concat(bToA.warnings)
      };
    } catch (err) {
      return { error: err.message };
    }
  }

  function applicationBytes(result, direction) {
    const items = result && result.directions && result.directions[direction] ? result.directions[direction].application : [];
    return PH.concatBytes.apply(null, items.map((item) => item.data));
  }

  function handshakeBytes(result, direction) {
    const items = result && result.directions && result.directions[direction] ? result.directions[direction].handshake : [];
    return PH.concatBytes.apply(null, items.map((item) => item.data));
  }

  global.PHTLSKeys = {
    parse, decryptFlow, applicationBytes, handshakeBytes, cipherInfo,
    bytesToHex, hexToBytes, expandLabel, deriveKeys, decryptRecord, nonceFor, recordHeader
  };
})(typeof window !== "undefined" ? window : globalThis);
