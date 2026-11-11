/* pcap / pcapng reader and writer.
 *
 * Pure byte parsing: no DOM, no fetch, no upload. The workbench reads a File
 * with FileReader, hands the ArrayBuffer to this module and never leaves the
 * browser. Records keep an offset into the original buffer so frames are not
 * copied until they are dissected.
 */
(function (global) {
  "use strict";

  const MAX_FRAME = 262144;
  const MAX_BLOCKS = 1000000;
  const CLASSIC_HEADER = 24;

  const LINK_TYPES = {
    0: "Null / loopback",
    1: "Ethernet",
    101: "Raw IP",
    105: "IEEE 802.11",
    113: "Linux SLL",
    127: "Radiotap",
    228: "IPv4",
    229: "IPv6",
    276: "Linux SLL2"
  };

  function toBytes(input) {
    if (input instanceof Uint8Array) return input;
    if (input instanceof ArrayBuffer) return new Uint8Array(input);
    if (input && input.buffer instanceof ArrayBuffer) return new Uint8Array(input.buffer, input.byteOffset || 0, input.byteLength);
    return Uint8Array.from(input || []);
  }

  function u16(bytes, off, little) {
    if (off + 2 > bytes.length) return 0;
    return little
      ? ((bytes[off + 1] << 8) | bytes[off]) >>> 0
      : ((bytes[off] << 8) | bytes[off + 1]) >>> 0;
  }

  function u32(bytes, off, little) {
    if (off + 4 > bytes.length) return 0;
    return little
      ? (((bytes[off + 3] << 24) >>> 0) + (bytes[off + 2] << 16) + (bytes[off + 1] << 8) + bytes[off]) >>> 0
      : (((bytes[off] << 24) >>> 0) + (bytes[off + 1] << 16) + (bytes[off + 2] << 8) + bytes[off + 3]) >>> 0;
  }

  function i32(bytes, off, little) {
    return u32(bytes, off, little) | 0;
  }

  function hex4(value) { return ("00000000" + (value >>> 0).toString(16)).slice(-8); }

  function detect(bytes) {
    if (!bytes || bytes.length < 4) return null;
    const m = hex4(u32(bytes, 0, false));
    if (m === "a1b2c3d4" || m === "d4c3b2a1" || m === "a1b23c4d" || m === "4d3cb2a1") return "pcap";
    if (m === "0a0d0d0a") return "pcapng";
    return null;
  }

  function linkTypeName(value) {
    return LINK_TYPES[value] || ("link type " + value);
  }

  function pushWarning(capture, message) {
    if (capture.warnings.indexOf(message) === -1) capture.warnings.push(message);
  }

  function makeRecord(capture, fields) {
    const record = {
      number: capture.records.length + 1,
      index: capture.records.length,
      ts: fields.ts,
      tsSec: fields.tsSec,
      tsFrac: fields.tsFrac,
      caplen: fields.caplen,
      origlen: fields.origlen,
      offset: fields.offset,
      linkType: fields.linkType,
      interfaceId: fields.interfaceId == null ? 0 : fields.interfaceId,
      noTimestamp: Boolean(fields.noTimestamp)
    };
    capture.records.push(record);
    return record;
  }

  /* ---------- classic pcap ---------- */

  function classicProfile(bytes) {
    const m = hex4(u32(bytes, 0, false));
    if (m === "a1b2c3d4") return { little: false, resolution: 1e-6, label: "microsecond" };
    if (m === "d4c3b2a1") return { little: true, resolution: 1e-6, label: "microsecond" };
    if (m === "a1b23c4d") return { little: false, resolution: 1e-9, label: "nanosecond" };
    if (m === "4d3cb2a1") return { little: true, resolution: 1e-9, label: "nanosecond" };
    return null;
  }

  function parseClassic(bytes) {
    const profile = classicProfile(bytes);
    if (!profile) throw new Error("Not a classic pcap file (bad magic)");
    const capture = {
      format: "pcap",
      bytes,
      littleEndian: profile.little,
      resolution: profile.resolution,
      resolutionLabel: profile.label,
      version: null,
      snaplen: 0,
      linkType: 1,
      interfaces: [],
      records: [],
      warnings: [],
      unsupported: false
    };
    if (bytes.length < CLASSIC_HEADER) {
      pushWarning(capture, "pcap global header is truncated (" + bytes.length + " B, expected 24 B)");
      return capture;
    }
    const major = u16(bytes, 4, profile.little);
    const minor = u16(bytes, 6, profile.little);
    capture.version = major + "." + minor;
    if (major !== 2) pushWarning(capture, "pcap version " + capture.version + " is not 2.x; parsing anyway");
    capture.thiszone = i32(bytes, 8, profile.little);
    capture.sigfigs = u32(bytes, 12, profile.little);
    capture.snaplen = u32(bytes, 16, profile.little);
    capture.linkType = u32(bytes, 20, profile.little);
    capture.interfaces = [{
      id: 0,
      linkType: capture.linkType,
      snaplen: capture.snaplen,
      resolution: capture.resolution,
      name: "interface 0"
    }];

    let offset = CLASSIC_HEADER;
    while (offset + 16 <= bytes.length) {
      const tsSec = u32(bytes, offset, profile.little);
      const tsFrac = u32(bytes, offset + 4, profile.little);
      const caplen = u32(bytes, offset + 8, profile.little);
      const origlen = u32(bytes, offset + 12, profile.little);
      offset += 16;
      const remaining = bytes.length - offset;
      if (caplen > MAX_FRAME) {
        pushWarning(capture, "packet " + (capture.records.length + 1) + " has caplen " + caplen + "; refusing to read an oversized frame");
        break;
      }
      if (caplen > remaining) {
        pushWarning(capture, "packet " + (capture.records.length + 1) + " is truncated: caplen " + caplen + " but only " + remaining + " B remain");
        break;
      }
      if (capture.snaplen && caplen > capture.snaplen) {
        pushWarning(capture, "packet " + (capture.records.length + 1) + " caplen " + caplen + " exceeds snaplen " + capture.snaplen);
      }
      makeRecord(capture, {
        ts: tsSec + tsFrac * capture.resolution,
        tsSec,
        tsFrac,
        caplen,
        origlen,
        offset,
        linkType: capture.linkType
      });
      offset += caplen;
      if (capture.records.length > MAX_BLOCKS) {
        pushWarning(capture, "packet limit reached; the rest of the capture was not read");
        break;
      }
    }
    if (offset < bytes.length) {
      pushWarning(capture, (bytes.length - offset) + " trailing byte(s) after the last complete packet");
    }
    return capture;
  }

  /* ---------- pcapng ---------- */

  const NG_SHB = 0x0a0d0d0a;
  const NG_IDB = 0x00000001;
  const NG_PB = 0x00000002;
  const NG_SPB = 0x00000003;
  const NG_NRB = 0x00000004;
  const NG_ISB = 0x00000005;
  const NG_EPB = 0x00000006;
  const NG_DSB = 0x0000000a;

  function ngEndianAt(bytes, offset) {
    if (offset + 12 > bytes.length) return null;
    if (u32(bytes, offset + 8, true) === 0x1a2b3c4d) return true;
    if (u32(bytes, offset + 8, false) === 0x1a2b3c4d) return false;
    return null;
  }

  function ngEndian(bytes) {
    return ngEndianAt(bytes, 0);
  }

  function parseOptions(bytes, start, end, little) {
    const options = {};
    let offset = start;
    while (offset + 4 <= end) {
      const code = u16(bytes, offset, little);
      const length = u16(bytes, offset + 2, little);
      offset += 4;
      if (code === 0) break;
      if (offset + length > end) break;
      const value = bytes.subarray(offset, offset + length);
      if (code === 2) options.name = String.fromCharCode.apply(null, Array.from(value).filter((b) => b >= 32 && b < 127));
      else if (code === 9 && length >= 1) options.tsresolRaw = value[0];
      else if (code === 14 && length >= 8) {
        options.tsoffset = (u32(value, 0, little) * 4294967296) + u32(value, 4, little);
      }
      offset += (length + 3) & ~3;
    }
    return options;
  }

  function tsResolution(raw) {
    if (raw == null) return { value: 1e-6, label: "10^-6 s (default)" };
    if (raw & 0x80) {
      const power = raw & 0x7f;
      return { value: Math.pow(2, -power), label: "2^-" + power + " s" };
    }
    return { value: Math.pow(10, -raw), label: "10^-" + raw + " s" };
  }

  function nrbMac(value) {
    if (typeof global.EthernetCodec !== "undefined" && global.EthernetCodec.macString) return global.EthernetCodec.macString(value);
    return Array.from(value).map((byte) => ("0" + byte.toString(16)).slice(-2)).join(":");
  }

  function nrbIPv4(value) {
    return Array.from(value).join(".");
  }

  function nrbIPv6(value) {
    if (typeof global.IPv6Codec !== "undefined" && global.IPv6Codec.formatIPv6) return global.IPv6Codec.formatIPv6(value);
    return Array.from(value).map((byte) => ("0" + byte.toString(16)).slice(-2)).join("");
  }

  function parseNg(bytes) {
    let little = ngEndian(bytes);
    if (little == null) throw new Error("Not a pcapng file (bad byte-order magic)");
    const capture = {
      format: "pcapng",
      bytes,
      littleEndian: little,
      resolution: 1e-6,
      resolutionLabel: "10^-6 s",
      version: null,
      snaplen: 0,
      linkType: 0,
      interfaces: [],
      records: [],
      warnings: [],
      sections: [],
      decryptionSecrets: [],
      nameResolution: [],
      interfaceStats: [],
      unsupported: false
    };
    let offset = 0;
    let sectionIndex = -1;
    let blockCount = 0;
    let sectionIfaces = [];
    while (offset + 12 <= bytes.length) {
      let type = u32(bytes, offset, little);
      let total = u32(bytes, offset + 4, little);
      if (type === NG_SHB) {
        const detected = ngEndianAt(bytes, offset);
        if (detected == null) {
          pushWarning(capture, "pcapng section header at " + offset + " has no byte-order magic; stopping");
          break;
        }
        little = detected;
        total = u32(bytes, offset + 4, little);
      }
      if (total < 12 || total % 4 !== 0) {
        pushWarning(capture, "pcapng block at " + offset + " has invalid length " + total + "; stopping");
        break;
      }
      if (offset + total > bytes.length) {
        pushWarning(capture, "pcapng block at " + offset + " is truncated (" + total + " B declared, " + (bytes.length - offset) + " B remain)");
        break;
      }
      if (u32(bytes, offset + total - 4, little) !== total) {
        pushWarning(capture, "pcapng block at " + offset + " has a mismatched trailing length; stopping");
        break;
      }
      const body = offset + 8;
      const bodyEnd = offset + total - 4;

      if (type === NG_SHB) {
        sectionIndex += 1;
        sectionIfaces = [];
        const major = u16(bytes, body + 4, little);
        const minor = u16(bytes, body + 6, little);
        const version = major + "." + minor;
        capture.version = capture.version || version;
        capture.sections.push({ index: sectionIndex, littleEndian: little, version });
        if (sectionIndex === 0) capture.littleEndian = little;
        if (major !== 1) pushWarning(capture, "pcapng section " + sectionIndex + " version " + version + " is not 1.x; parsing anyway");
      } else if (type === NG_IDB) {
        if (sectionIndex < 0) {
          pushWarning(capture, "pcapng interface block appears before a section header; skipping");
        } else {
          const linkType = u16(bytes, body, little);
          const snaplen = u32(bytes, body + 4, little);
          const options = parseOptions(bytes, body + 8, bodyEnd, little);
          const res = tsResolution(options.tsresolRaw);
          const localId = sectionIfaces.length;
          const iface = {
            id: capture.interfaces.length,
            localId,
            section: sectionIndex,
            linkType,
            snaplen,
            resolution: res.value,
            resolutionLabel: res.label,
            name: options.name || ("interface " + capture.interfaces.length),
            tsoffset: options.tsoffset || 0
          };
          sectionIfaces.push(iface);
          capture.interfaces.push(iface);
          if (capture.interfaces.length === 1) {
            capture.linkType = linkType;
            capture.snaplen = snaplen;
            capture.resolution = res.value;
            capture.resolutionLabel = res.label;
          }
        }
      } else if (type === NG_EPB || type === NG_PB) {
        const isPb = type === NG_PB;
        if (!sectionIfaces.length) {
          pushWarning(capture, "pcapng packet block appears before any interface description; skipping");
        } else {
          const ifaceId = isPb ? u16(bytes, body, little) : u32(bytes, body, little);
          const tsHigh = u32(bytes, body + 4, little);
          const tsLow = u32(bytes, body + 8, little);
          const caplen = u32(bytes, body + 12, little);
          const origlen = u32(bytes, body + 16, little);
          const dataOffset = body + 20;
          const iface = sectionIfaces[ifaceId];
          if (!iface) {
            pushWarning(capture, "pcapng packet references unknown interface " + ifaceId + " in section " + sectionIndex + "; skipping");
          } else if (caplen > MAX_FRAME) {
            pushWarning(capture, "pcapng packet has caplen " + caplen + "; skipping an oversized frame");
          } else if (dataOffset + caplen > bodyEnd) {
            pushWarning(capture, "pcapng packet is truncated (caplen " + caplen + " B)");
          } else {
            const rawTs = (tsHigh * 4294967296) + tsLow;
            const ts = rawTs * iface.resolution + (iface.tsoffset || 0);
            makeRecord(capture, {
              ts,
              tsSec: Math.floor(ts),
              tsFrac: Math.round((ts - Math.floor(ts)) * 1e6),
              caplen,
              origlen,
              offset: dataOffset,
              linkType: iface.linkType,
              interfaceId: iface.id
            });
          }
        }
      } else if (type === NG_SPB) {
        if (!sectionIfaces.length) {
          pushWarning(capture, "pcapng simple packet block appears before any interface description; skipping");
        } else {
          const origlen = u32(bytes, body, little);
          const iface = sectionIfaces[0];
          const available = Math.max(0, bodyEnd - (body + 4));
          const caplen = Math.min(origlen, available, iface.snaplen || MAX_FRAME, MAX_FRAME);
          makeRecord(capture, {
            ts: 0,
            tsSec: 0,
            tsFrac: 0,
            caplen,
            origlen,
            offset: body + 4,
            linkType: iface.linkType,
            interfaceId: iface.id,
            noTimestamp: true
          });
        }
      } else if (type === NG_DSB) {
        const secretType = u32(bytes, body, little);
        const length = u32(bytes, body + 4, little);
        if (body + 8 + length > bodyEnd) {
          pushWarning(capture, "pcapng decryption secrets block is truncated");
        } else {
          capture.decryptionSecrets.push({
            type: secretType,
            label: secretType === 0x544c534b ? "TLS Key Log" : "type 0x" + hex4(secretType),
            data: bytes.subarray(body + 8, body + 8 + length)
          });
        }
      } else if (type === NG_NRB) {
        let pos = body;
        while (pos + 4 <= bodyEnd) {
          const recordType = u16(bytes, pos, little);
          const length = u16(bytes, pos + 2, little);
          pos += 4;
          if (recordType === 0) break;
          if (pos + length > bodyEnd) {
            pushWarning(capture, "pcapng name resolution record is truncated");
            break;
          }
          const value = bytes.subarray(pos, pos + length);
          const entry = { type: recordType, length, raw: value };
          if (recordType === 1 && length >= 4) entry.address = nrbIPv4(value.subarray(0, 4));
          else if (recordType === 2 && length >= 16) entry.address = nrbIPv6(value.subarray(0, 16));
          else if (recordType === 3 && length >= 6) entry.address = nrbMac(value.subarray(0, 6));
          else if (recordType === 4 && length >= 8) entry.address = nrbMac(value.subarray(0, 8));
          const text = Array.from(value).map((byte) => byte >= 32 && byte < 127 ? String.fromCharCode(byte) : "").join("").trim();
          if (text) entry.name = text;
          capture.nameResolution.push(entry);
          pos += (length + 3) & ~3;
        }
      } else if (type === NG_ISB) {
        const ifaceId = u32(bytes, body, little);
        const tsHigh = u32(bytes, body + 4, little);
        const tsLow = u32(bytes, body + 8, little);
        const iface = sectionIfaces[ifaceId];
        const rawTs = (tsHigh * 4294967296) + tsLow;
        capture.interfaceStats.push({
          interfaceId: iface ? iface.id : ifaceId,
          section: sectionIndex,
          ts: iface ? rawTs * iface.resolution + (iface.tsoffset || 0) : rawTs,
          options: parseOptions(bytes, body + 12, bodyEnd, little)
        });
      }

      offset += total;
      blockCount += 1;
      if (blockCount > MAX_BLOCKS) {
        pushWarning(capture, "block limit reached; the rest of the capture was not read");
        break;
      }
    }
    if (!capture.interfaces.length) pushWarning(capture, "pcapng capture contains no interface description block");
    return capture;
  }

  /* ---------- public helpers ---------- */

  function parse(input) {
    const bytes = toBytes(input);
    if (!bytes.length) throw new Error("Empty input");
    const kind = detect(bytes);
    if (kind === "pcap") return parseClassic(bytes);
    if (kind === "pcapng") return parseNg(bytes);
    throw new Error("Not a pcap or pcapng file (unrecognised magic bytes)");
  }

  function recordBytes(capture, record) {
    const start = record.offset;
    const end = Math.min(capture.bytes.length, start + record.caplen);
    return capture.bytes.subarray(start, end);
  }

  function fromFrames(frames, options) {
    const opts = options || {};
    const parts = [];
    let total = 0;
    (frames || []).forEach((frame) => {
      const bytes = toBytes(frame.bytes || frame);
      parts.push(bytes);
      total += bytes.length;
    });
    const bytes = new Uint8Array(total);
    let cursor = 0;
    parts.forEach((part) => { bytes.set(part, cursor); cursor += part.length; });
    const linkType = opts.linkType == null ? 1 : opts.linkType;
    const capture = {
      format: "synthetic",
      bytes,
      littleEndian: true,
      resolution: 1e-6,
      resolutionLabel: "microsecond",
      version: null,
      snaplen: total,
      linkType,
      interfaces: [{ id: 0, linkType, snaplen: total, resolution: 1e-6, resolutionLabel: "10^-6 s", name: "shared frame" }],
      records: [],
      warnings: [],
      unsupported: false,
      synthetic: true
    };
    let offset = 0;
    (frames || []).forEach((frame, index) => {
      const bytesView = parts[index];
      const ts = frame && frame.ts != null ? frame.ts : 0;
      makeRecord(capture, {
        ts,
        tsSec: Math.floor(ts),
        tsFrac: Math.round((ts - Math.floor(ts)) * 1e6),
        caplen: bytesView.length,
        origlen: bytesView.length,
        offset,
        linkType: frame && frame.linkType != null ? frame.linkType : linkType,
        noTimestamp: !ts
      });
      offset += bytesView.length;
    });
    return capture;
  }

  /* ---------- writers ---------- */

  function Writer(initial) {
    this.bytes = new Uint8Array(initial || 1024);
    this.length = 0;
  }
  Writer.prototype.ensure = function (extra) {
    if (this.length + extra <= this.bytes.length) return;
    let size = this.bytes.length;
    while (size < this.length + extra) size *= 2;
    const next = new Uint8Array(size);
    next.set(this.bytes.subarray(0, this.length));
    this.bytes = next;
  };
  Writer.prototype.u8 = function (value) {
    this.ensure(1);
    this.bytes[this.length++] = value & 255;
    return this;
  };
  Writer.prototype.u16 = function (value, little) {
    this.ensure(2);
    if (little) { this.bytes[this.length++] = value & 255; this.bytes[this.length++] = (value >>> 8) & 255; }
    else { this.bytes[this.length++] = (value >>> 8) & 255; this.bytes[this.length++] = value & 255; }
    return this;
  };
  Writer.prototype.u32 = function (value, little) {
    this.ensure(4);
    value = value >>> 0;
    if (little) {
      this.bytes[this.length++] = value & 255;
      this.bytes[this.length++] = (value >>> 8) & 255;
      this.bytes[this.length++] = (value >>> 16) & 255;
      this.bytes[this.length++] = (value >>> 24) & 255;
    } else {
      this.bytes[this.length++] = (value >>> 24) & 255;
      this.bytes[this.length++] = (value >>> 16) & 255;
      this.bytes[this.length++] = (value >>> 8) & 255;
      this.bytes[this.length++] = value & 255;
    }
    return this;
  };
  Writer.prototype.raw = function (bytes) {
    this.ensure(bytes.length);
    this.bytes.set(bytes, this.length);
    this.length += bytes.length;
    return this;
  };
  Writer.prototype.pad4 = function (length) {
    const pad = (4 - (length % 4)) % 4;
    for (let i = 0; i < pad; i += 1) this.u8(0);
    return pad;
  };
  Writer.prototype.finish = function () {
    return this.bytes.subarray(0, this.length);
  };

  function encodeClassic(capture, records) {
    const list = records || capture.records;
    if (!list.length) throw new Error("No packets to write");
    const linkType = list[0].linkType;
    if (list.some((record) => record.linkType !== linkType)) {
      throw new Error("Classic pcap can only hold one link type; export pcapng instead");
    }
    const snaplen = Math.max(capture.snaplen || 0, ...list.map((record) => record.caplen), 65535);
    const writer = new Writer(24 + list.reduce((sum, record) => sum + 16 + record.caplen, 0));
    writer.u32(0xa1b2c3d4, true); // little-endian magic, microsecond file
    writer.u16(2, true).u16(4, true);
    writer.u32(0, true).u32(0, true); // thiszone, sigfigs
    writer.u32(snaplen, true).u32(linkType, true);
    list.forEach((record) => {
      const ts = record.ts > 0 ? record.ts : 0;
      const sec = Math.floor(ts);
      const frac = Math.round((ts - sec) * 1e6);
      writer.u32(sec, true).u32(frac, true).u32(record.caplen, true).u32(record.origlen || record.caplen, true);
      writer.raw(recordBytes(capture, record));
    });
    return writer.finish();
  }

  function encodeNg(capture, records) {
    const list = records || capture.records;
    if (!list.length) throw new Error("No packets to write");
    const linkTypes = [];
    list.forEach((record) => {
      if (linkTypes.indexOf(record.linkType) === -1) linkTypes.push(record.linkType);
    });
    const writer = new Writer(1024);
    // Section Header Block
    writer.u32(NG_SHB, true).u32(28, true);
    writer.u32(0x1a2b3c4d, true).u16(1, true).u16(0, true);
    writer.u32(0xffffffff, true).u32(0xffffffff, true);
    writer.u32(28, true);
    // Interface Description Blocks
    linkTypes.forEach((linkType) => {
      writer.u32(NG_IDB, true).u32(20, true);
      writer.u16(linkType, true).u16(0, true).u32(Math.max(capture.snaplen || 0, 65535), true);
      writer.u32(20, true);
    });
    // Decryption Secrets Blocks (TLS key logs and other secrets)
    (capture.decryptionSecrets || []).forEach((secret) => {
      const data = toBytes(secret.data);
      const padded = (data.length + 3) & ~3;
      const total = 8 + 8 + padded + 4;
      writer.u32(NG_DSB, true).u32(total, true);
      writer.u32(secret.type || 0, true).u32(data.length, true);
      writer.raw(data);
      writer.pad4(data.length);
      writer.u32(total, true);
    });
    // Enhanced Packet Blocks
    list.forEach((record) => {
      const ifaceId = Math.max(0, linkTypes.indexOf(record.linkType));
      const frame = recordBytes(capture, record);
      const padded = (frame.length + 3) & ~3;
      const total = 8 + 20 + padded + 4;
      const ts = record.ts > 0 ? record.ts : 0;
      const units = Math.round(ts * 1e6);
      const high = Math.floor(units / 4294967296);
      const low = units % 4294967296;
      writer.u32(NG_EPB, true).u32(total, true);
      writer.u32(ifaceId, true).u32(high, true).u32(low, true);
      writer.u32(frame.length, true).u32(record.origlen || frame.length, true);
      writer.raw(frame);
      writer.pad4(frame.length);
      writer.u32(total, true);
    });
    return writer.finish();
  }

  function encode(capture, records, options) {
    const opts = options || {};
    const format = opts.format || (capture.format === "pcapng" ? "pcapng" : "pcap");
    return format === "pcapng" ? encodeNg(capture, records) : encodeClassic(capture, records);
  }

  function summary(capture) {
    const first = capture.records[0];
    const last = capture.records[capture.records.length - 1];
    return {
      format: capture.format,
      packets: capture.records.length,
      linkTypes: capture.interfaces.map((iface) => linkTypeName(iface.linkType)).filter((name, i, all) => all.indexOf(name) === i),
      duration: first && last ? Math.max(0, last.ts - first.ts) : 0,
      firstTime: first ? first.ts : 0,
      lastTime: last ? last.ts : 0,
      warnings: capture.warnings.length
    };
  }

  global.PCapCodec = {
    parse,
    detect,
    recordBytes,
    fromFrames,
    encode,
    encodeClassic,
    encodeNg,
    summary,
    linkTypeName,
    toBytes,
    MAX_FRAME,
    LINK_TYPES
  };
})(typeof window !== "undefined" ? window : globalThis);
