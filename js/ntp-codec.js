/* NTPv4 (RFC 5905) packet codec. Parses the 48-byte header, 64-bit NTP
   timestamps, reference identifiers and trailing extension/MAC bytes.
   It does not implement clock discipline, authentication or kiss-o'-death handling. */
(function (global) {
  "use strict";

  const PH = global.PH || (global.window && global.window.PH);

  const NTP_EPOCH_OFFSET = 2208988800; /* seconds from 1900-01-01 to 1970-01-01 */
  const MODES = {
    0: "reserved", 1: "symmetric active", 2: "symmetric passive", 3: "client",
    4: "server", 5: "broadcast", 6: "NTP control", 7: "private"
  };
  const LEAP = { 0: "no warning", 1: "last minute has 61 s", 2: "last minute has 59 s", 3: "clock not synchronized" };
  const KISS = {
    ACST: "The server is not synchronized to a valid time source",
    AUTH: "Authentication failure",
    AUTO: "Autokey sequence error",
    BCST: "Broadcast server failure",
    CRYP: "Authentication failure",
    DENY: "Access denied",
    DROP: "Access denied (dropped)",
    RSTR: "Access denied (rate exceeded)",
    INIT: "Server is initializing",
    MCST: "Multicast server failure",
    NKEY: "No key found",
    RATE: "Rate exceeded",
    RMOT: "Remote modification refused",
    STEP: "Step change in progress"
  };

  function modeName(mode) { return MODES[mode] || "mode " + mode; }

  function toInt(value, name, min, max, fallback) {
    if (value == null || value === "") {
      if (fallback != null) return fallback;
      throw new Error(name + " is required");
    }
    const n = Number(value);
    if (!Number.isInteger(n) || n < min || n > max) throw new Error(name + " must be " + min + "–" + max);
    return n;
  }

  function toBytes(value) {
    if (value instanceof Uint8Array) return value;
    if (Array.isArray(value)) return Uint8Array.from(value);
    if (value == null || String(value).trim() === "") return new Uint8Array(0);
    return PH.parseHex(value);
  }

  function pad4(value) {
    const padded = (value.length + 3) & ~3;
    if (padded === value.length) return value;
    const out = new Uint8Array(padded);
    out.set(value, 0);
    return out;
  }

  function toNtpTimestamp(date) {
    const ms = (date instanceof Date ? date.getTime() : Number(date));
    if (!Number.isFinite(ms)) throw new Error("Invalid date");
    const seconds = ms / 1000 + NTP_EPOCH_OFFSET;
    const whole = Math.floor(seconds);
    const fraction = Math.round((seconds - whole) * 0x100000000);
    const hi = whole >>> 0;
    const lo = fraction >>> 0;
    return { hi, lo, seconds: whole, fraction: lo, text: (whole - NTP_EPOCH_OFFSET) + "s" };
  }

  function fromNtpTimestamp(bytes, offset) {
    const hi = PH.u32be(bytes, offset);
    const lo = PH.u32be(bytes, offset + 4);
    if (hi === 0 && lo === 0) return null;
    const seconds = hi - NTP_EPOCH_OFFSET;
    const ms = seconds * 1000 + (lo / 0x100000000) * 1000;
    return { hi, lo, seconds, ms, date: new Date(ms), fraction: lo / 0x100000000 };
  }

  function refIdText(stratum, bytes) {
    if (stratum === 0) {
      const code = String.fromCharCode(bytes[0], bytes[1], bytes[2], bytes[3]);
      return { text: code, kiss: KISS[code] || null };
    }
    if (stratum === 1) return { text: String.fromCharCode(bytes[0], bytes[1], bytes[2], bytes[3]).replace(/\0+$/, "") };
    return { text: PH.ipv4String(bytes, 0) };
  }

  function decodeNtp(bytes) {
    if (!(bytes instanceof Uint8Array)) bytes = Uint8Array.from(bytes);
    if (bytes.length < 48) throw new Error("NTP needs at least the 48-byte header");
    const warnings = [];
    const b0 = bytes[0];
    const leap = b0 >> 6;
    const version = (b0 >> 3) & 0x07;
    const mode = b0 & 0x07;
    const stratum = bytes[1];
    const poll = bytes[2] > 127 ? bytes[2] - 256 : bytes[2];
    const precision = bytes[3] > 127 ? bytes[3] - 256 : bytes[3];
    const rootDelayRaw = PH.u32be(bytes, 4);
    const rootDispRaw = PH.u32be(bytes, 8);
    const rootDelay = (rootDelayRaw > 0x7fffffff ? rootDelayRaw - 0x100000000 : rootDelayRaw) / 65536;
    const rootDispersion = rootDispRaw / 65536;
    const ref = refIdText(stratum, bytes.subarray(12, 16));
    const out = {
      bytes, leap, leapText: LEAP[leap], version, mode, modeName: modeName(mode),
      stratum, poll, precision, rootDelay, rootDispersion,
      referenceId: ref.text, kissCode: ref.kiss || null,
      reference: fromNtpTimestamp(bytes, 16),
      origin: fromNtpTimestamp(bytes, 24),
      receive: fromNtpTimestamp(bytes, 32),
      transmit: fromNtpTimestamp(bytes, 40),
      extensions: [], mac: null, warnings
    };
    if (version !== 4 && version !== 3) warnings.push("Version " + version + " is not NTPv3 or NTPv4");
    if (stratum > 16) warnings.push("Stratum " + stratum + " is outside 0–16");
    if (mode === 3 && stratum !== 0) warnings.push("A client request normally has stratum 0");
    if (bytes.length > 48) {
      let pos = 48;
      while (pos + 4 <= bytes.length) {
        const type = PH.u16be(bytes, pos);
        const length = PH.u16be(bytes, pos + 2);
        if (length < 16 || length % 4 || pos + length > bytes.length) break;
        out.extensions.push({ type, length, value: bytes.subarray(pos + 4, pos + length) });
        pos += length;
      }
      const rest = bytes.length - pos;
      if (rest >= 16) {
        out.mac = {
          keyId: PH.u32be(bytes, pos),
          digest: bytes.subarray(pos + 4),
          length: rest
        };
        pos = bytes.length;
      }
      if (pos < bytes.length) warnings.push((bytes.length - pos) + " trailing byte(s) after the parsed extensions");
    }
    out.referenceText = out.reference ? out.reference.date.toISOString() : "zero";
    out.transmitText = out.transmit ? out.transmit.date.toISOString() : "zero";
    return out;
  }

  function buildExtension(ext) {
    const value = pad4(toBytes(ext.value));
    const total = Math.max(16, 4 + value.length);
    if (total % 4) throw new Error("NTP extension length must be a multiple of 4");
    const bytes = new Uint8Array(total);
    PH.put16be(bytes, 0, toInt(ext.type, "Extension type", 0, 65535, 0x0104));
    PH.put16be(bytes, 2, total);
    bytes.set(value, 4);
    return bytes;
  }

  function buildNtp(input) {
    const now = input.now instanceof Date ? input.now : new Date();
    const leap = toInt(input.leap, "Leap indicator", 0, 3, 0);
    const version = toInt(input.version, "Version", 3, 4, 4);
    const mode = toInt(input.mode, "Mode", 0, 7, 3);
    const stratum = toInt(input.stratum, "Stratum", 0, 255, 0);
    const poll = toInt(input.poll, "Poll", -128, 127, 6);
    const precision = toInt(input.precision, "Precision", -128, 127, -20);
    const bytes = new Uint8Array(48);
    bytes[0] = (leap << 6) | (version << 3) | mode;
    bytes[1] = stratum;
    bytes[2] = poll & 255;
    bytes[3] = precision & 255;
    const rootDelay = Math.round(Number(input.rootDelay || 0) * 65536);
    const rootDispersion = Math.round(Number(input.rootDispersion || 0) * 65536);
    PH.put32be(bytes, 4, rootDelay < 0 ? rootDelay + 0x100000000 : rootDelay);
    PH.put32be(bytes, 8, rootDispersion);
    let refId = toBytes(input.referenceId);
    if (refId.length === 0) {
      const text = String(input.referenceIdText || "LOCL").slice(0, 4).padEnd(4, "\0");
      refId = Uint8Array.from(text, (c) => c.charCodeAt(0) & 255);
    }
    if (refId.length !== 4) throw new Error("Reference ID must be exactly 4 bytes");
    bytes.set(refId, 12);
    const stamp = (value, fallback) => {
      if (value == null || value === "") {
        if (fallback === null) return { hi: 0, lo: 0 };
        return toNtpTimestamp(fallback || now);
      }
      if (value instanceof Date) return toNtpTimestamp(value);
      if (typeof value === "number") return toNtpTimestamp(new Date(value));
      const bytesIn = toBytes(value);
      if (bytesIn.length !== 8) throw new Error("A timestamp must be a Date, epoch milliseconds or 8 hex bytes");
      return { hi: PH.u32be(bytesIn, 0), lo: PH.u32be(bytesIn, 4) };
    };
    const refStamp = stamp(input.reference, new Date(now.getTime() - 3600 * 1000));
    const originStamp = stamp(input.origin, null);
    const receiveStamp = stamp(input.receive, now);
    const transmitStamp = stamp(input.transmit, now);
    [refStamp, originStamp, receiveStamp, transmitStamp].forEach((s, i) => {
      PH.put32be(bytes, 16 + i * 8, s.hi);
      PH.put32be(bytes, 20 + i * 8, s.lo);
    });
    const extensions = input.extensions || [];
    if (!extensions.length) {
      return {
        bytes, leap, version, mode, modeName: modeName(mode), stratum, poll, precision,
        referenceId: input.referenceIdText || null, extensions: [],
        transmit: fromNtpTimestamp(bytes, 40), reference: fromNtpTimestamp(bytes, 16)
      };
    }
    const parts = extensions.map(buildExtension);
    const total = 48 + parts.reduce((n, p) => n + p.length, 0);
    const out = new Uint8Array(total);
    out.set(bytes, 0);
    let pos = 48;
    parts.forEach((p) => { out.set(p, pos); pos += p.length; });
    return {
      bytes: out, leap, version, mode, modeName: modeName(mode), stratum, poll, precision,
      extensions: parts.length, transmit: fromNtpTimestamp(out, 40), reference: fromNtpTimestamp(out, 16)
    };
  }

  function stampText(stamp) {
    if (!stamp) return "zero";
    return stamp.date.toISOString() + " · " + stamp.seconds + "s + " + stamp.fraction.toFixed(6);
  }

  global.NTPCodec = {
    NTP_EPOCH_OFFSET, MODES, LEAP, KISS, modeName, toNtpTimestamp, fromNtpTimestamp,
    decodeNtp, buildNtp, stampText
  };
})(typeof window !== "undefined" ? window : globalThis);
