/* TLS 1.3 (and the TLS 1.2 handshake shapes that still appear on the wire)
   record/handshake/extension codec — shared by the TLS page, the packet
   dissector and tests.

   Scope: plaintext record layer and handshake messages. Records protected
   with TLS 1.3 AEAD keys are reported as opaque application data; this codec
   deliberately does not implement key derivation or decryption. */
(function (global) {
  "use strict";

  const PH = global.PH;

  const CONTENT_TYPES = {
    20: "ChangeCipherSpec",
    21: "Alert",
    22: "Handshake",
    23: "Application Data",
    24: "Heartbeat"
  };

  const HANDSHAKE_TYPES = {
    0: "HelloRequest",
    1: "ClientHello",
    2: "ServerHello",
    4: "NewSessionTicket",
    5: "EndOfEarlyData",
    8: "EncryptedExtensions",
    11: "Certificate",
    12: "ServerKeyExchange",
    13: "CertificateRequest",
    14: "ServerHelloDone",
    15: "CertificateVerify",
    16: "ClientKeyExchange",
    20: "Finished",
    24: "KeyUpdate",
    254: "MessageHash"
  };

  const EXTENSION_TYPES = {
    0: "server_name",
    1: "max_fragment_length",
    5: "status_request",
    10: "supported_groups",
    11: "ec_point_formats",
    13: "signature_algorithms",
    16: "application_layer_protocol_negotiation",
    18: "signed_certificate_timestamp",
    21: "padding",
    22: "encrypt_then_mac",
    23: "extended_master_secret",
    27: "compress_certificate",
    28: "record_size_limit",
    35: "session_ticket",
    41: "pre_shared_key",
    42: "early_data",
    43: "supported_versions",
    44: "cookie",
    45: "psk_key_exchange_modes",
    47: "certificate_authorities",
    49: "post_handshake_auth",
    50: "signature_algorithms_cert",
    51: "key_share",
    0xff01: "renegotiation_info",
    0xfe0d: "encrypted_client_hello"
  };

  const VERSIONS = {
    0x0300: "SSL 3.0",
    0x0301: "TLS 1.0",
    0x0302: "TLS 1.1",
    0x0303: "TLS 1.2",
    0x0304: "TLS 1.3"
  };

  const CIPHER_SUITES = {
    0x1301: "TLS_AES_128_GCM_SHA256",
    0x1302: "TLS_AES_256_GCM_SHA384",
    0x1303: "TLS_CHACHA20_POLY1305_SHA256",
    0x1304: "TLS_AES_128_CCM_SHA256",
    0x1305: "TLS_AES_128_CCM_8_SHA256",
    0x1306: "TLS_AEGIS_256_SHA512",
    0x1307: "TLS_AEGIS_128L_SHA256",
    0x009c: "TLS_RSA_WITH_AES_128_GCM_SHA256",
    0x009d: "TLS_RSA_WITH_AES_256_GCM_SHA384",
    0xc02b: "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256",
    0xc02c: "TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384",
    0xc02f: "TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256",
    0xc030: "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384",
    0xcca8: "TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0xcca9: "TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256",
    0xccaa: "TLS_DHE_RSA_WITH_CHACHA20_POLY1305_SHA256",
    0x5600: "TLS_FALLBACK_SCSV"
  };

  const GROUPS = {
    0x0017: "secp256r1",
    0x0018: "secp384r1",
    0x0019: "secp521r1",
    0x001a: "brainpoolP256r1",
    0x001b: "brainpoolP384r1",
    0x001c: "brainpoolP512r1",
    0x001d: "x25519",
    0x001e: "x448",
    0x0100: "ffdhe2048",
    0x0101: "ffdhe3072",
    0x0102: "ffdhe4096",
    0x0103: "ffdhe6144",
    0x0104: "ffdhe8192",
    0x11ec: "X25519MLKEM768",
    0x6399: "X25519Kyber768Draft00"
  };

  const SIG_SCHEMES = {
    0x0201: "rsa_pkcs1_sha1",
    0x0203: "ecdsa_sha1",
    0x0401: "rsa_pkcs1_sha256",
    0x0403: "ecdsa_secp256r1_sha256",
    0x0501: "rsa_pkcs1_sha384",
    0x0503: "ecdsa_secp384r1_sha384",
    0x0601: "rsa_pkcs1_sha512",
    0x0603: "ecdsa_secp521r1_sha512",
    0x0804: "rsa_pss_rsae_sha256",
    0x0805: "rsa_pss_rsae_sha384",
    0x0806: "rsa_pss_rsae_sha512",
    0x0807: "ed25519",
    0x0808: "ed448",
    0x0809: "rsa_pss_pss_sha256",
    0x080a: "rsa_pss_pss_sha384",
    0x080b: "rsa_pss_pss_sha512"
  };

  const ALERTS = {
    0: "close_notify", 10: "unexpected_message", 20: "bad_record_mac",
    21: "decryption_failed", 22: "record_overflow", 40: "handshake_failure",
    42: "bad_certificate", 43: "unsupported_certificate", 44: "certificate_revoked",
    45: "certificate_expired", 46: "certificate_unknown", 47: "illegal_parameter",
    48: "unknown_ca", 49: "access_denied", 50: "decode_error", 51: "decrypt_error",
    70: "protocol_version", 71: "insufficient_security", 80: "internal_error",
    86: "inappropriate_fallback", 90: "user_canceled", 100: "no_renegotiation",
    109: "missing_extension", 110: "unsupported_extension", 112: "unrecognized_name",
    113: "bad_certificate_status_response", 115: "unknown_psk_identity",
    116: "certificate_required", 120: "no_application_protocol"
  };

  const PSK_MODES = { 0: "psk_ke", 1: "psk_dhe_ke" };

  const NAME_TYPES = { 0: "host_name" };

  const CLIENT_CERT_TYPES = {
    1: "rsa_sign", 2: "dss_sign", 3: "rsa_fixed_dh", 4: "dss_fixed_dh",
    5: "rsa_fixed_ecdsa", 64: "ecdsa_sign", 65: "rsa_fixed_ecdsa",
    66: "ecdsa_fixed_ecdsa"
  };

  /* ---------- small helpers ---------- */

  function toBytes(value) {
    if (value instanceof Uint8Array) return value;
    if (Array.isArray(value)) return Uint8Array.from(value);
    if (value == null || value === "") return new Uint8Array(0);
    return PH.parseHex(String(value));
  }

  function asciiBytes(text) {
    const s = String(text == null ? "" : text);
    const out = new Uint8Array(s.length);
    for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 255;
    return out;
  }

  function asciiString(bytes) {
    let out = "";
    for (let i = 0; i < bytes.length; i++) {
      const b = bytes[i];
      out += b >= 32 && b < 127 ? String.fromCharCode(b) : ".";
    }
    return out;
  }

  function preview(bytes, max) {
    const n = max == null ? 16 : max;
    return bytes.length <= n
      ? PH.bytesToHex(bytes)
      : PH.bytesToHex(bytes.subarray(0, n)) + " …";
  }

  function nameFrom(map, code, fallback) {
    return map[code] != null ? map[code] : fallback;
  }

  function versionName(code) { return nameFrom(VERSIONS, code, code == null ? "unknown" : "0x" + PH.hex(code, 4)); }
  function cipherName(code) { return nameFrom(CIPHER_SUITES, code, code == null ? "unknown" : "0x" + PH.hex(code, 4)); }
  function groupName(code) { return nameFrom(GROUPS, code, code == null ? "unknown group" : "group 0x" + PH.hex(code, 4)); }
  function sigName(code) { return nameFrom(SIG_SCHEMES, code, code == null ? "unknown" : "0x" + PH.hex(code, 4)); }
  function extName(code) { return nameFrom(EXTENSION_TYPES, code, "extension 0x" + PH.hex(code, 4)); }
  function alertName(code) { return nameFrom(ALERTS, code, "alert " + code); }
  function contentTypeName(code) { return nameFrom(CONTENT_TYPES, code, "content type " + code); }
  function handshakeName(code) { return nameFrom(HANDSHAKE_TYPES, code, "handshake type " + code); }

  function u24(bytes, off) {
    return ((bytes[off] << 16) | (bytes[off + 1] << 8) | bytes[off + 2]) >>> 0;
  }

  function need(bytes, pos, count, warnings, label) {
    if (pos + count > bytes.length) {
      warnings.push(label + " is truncated: needs " + count + " byte(s) at offset " + pos + ", only " +
        Math.max(0, bytes.length - pos) + " remain");
      return false;
    }
    return true;
  }

  function pairList(values, mapper) {
    const out = [];
    for (let i = 0; i + 1 < values.length; i += 2) {
      const code = (values[i] << 8) | values[i + 1];
      out.push({ code, name: mapper(code) });
    }
    return out;
  }

  function field(name, value, note) {
    return { name, value: value == null ? "—" : String(value), note: note || "" };
  }

  /* ---------- record layer ---------- */

  function decodeRecords(bytes) {
    const warnings = [];
    const records = [];
    let pos = 0;
    while (pos + 5 <= bytes.length) {
      const type = bytes[pos];
      const major = bytes[pos + 1];
      const minor = bytes[pos + 2];
      const length = PH.u16be(bytes, pos + 3);
      if (!CONTENT_TYPES[type]) {
        warnings.push("Unknown TLS content type " + type + " at offset " + pos + "; record walk stopped");
        break;
      }
      if (major !== 3) {
        warnings.push("Legacy record version " + major + "." + minor + " at offset " + pos +
          " does not start with 3.x; this is probably not TLS");
        break;
      }
      const fragmentOffset = pos + 5;
      const available = Math.min(length, Math.max(0, bytes.length - fragmentOffset));
      if (fragmentOffset + length > bytes.length) {
        warnings.push("Record " + (records.length + 1) + " declares " + length +
          " byte(s) but only " + available + " are captured");
      }
      const record = {
        index: records.length,
        type, typeName: contentTypeName(type),
        legacyVersion: major + "." + minor,
        versionCode: (major << 8) | minor,
        versionName: versionName((major << 8) | minor),
        length,
        offset: pos,
        headerLength: 5,
        fragmentOffset,
        fragment: bytes.subarray(fragmentOffset, fragmentOffset + available),
        truncated: fragmentOffset + length > bytes.length
      };
      records.push(record);
      pos = fragmentOffset + length;
      if (pos > bytes.length) break;
    }
    if (pos < bytes.length && records.length) {
      warnings.push((bytes.length - pos) + " trailing byte(s) after the last TLS record");
    }
    return { records, warnings, length: Math.min(pos, bytes.length) };
  }

  /* ---------- extensions ---------- */

  function decodeExtensions(bytes, context, warnings) {
    const extensions = [];
    let pos = 0;
    while (pos + 4 <= bytes.length) {
      const type = PH.u16be(bytes, pos);
      const length = PH.u16be(bytes, pos + 2);
      const dataStart = pos + 4;
      if (dataStart + length > bytes.length) {
        warnings.push("Extension " + extName(type) + " declares " + length +
          " byte(s) but only " + (bytes.length - dataStart) + " remain");
      }
      const data = bytes.subarray(dataStart, Math.min(bytes.length, dataStart + length));
      const ext = {
        type, name: extName(type), length, offset: pos, data,
        fields: [], summary: "", warnings: []
      };
      parseExtension(ext, context, warnings);
      extensions.push(ext);
      pos = dataStart + length;
    }
    if (pos !== bytes.length) {
      warnings.push((bytes.length - pos) + " trailing byte(s) in the extension block");
    }
    return extensions;
  }

  function parseExtension(ext, context, warnings) {
    const d = ext.data;
    const local = ext.warnings;
    const push = (message) => { local.push(message); };
    switch (ext.type) {
      case 0: {
        if (d.length === 0 && (context === "encrypted" || context === "server")) {
          ext.summary = "empty acknowledgement";
          ext.fields = [field("Response", "empty")];
          break;
        }
        if (d.length < 2) { push("server_name extension is too short"); break; }
        const listLength = PH.u16be(d, 0);
        let p = 2;
        const names = [];
        const end = Math.min(d.length, 2 + listLength);
        while (p + 3 <= end) {
          const type = d[p];
          const length = PH.u16be(d, p + 1);
          p += 3;
          if (p + length > end) { push("server_name entry overruns the list"); break; }
          names.push({ type, typeName: NAME_TYPES[type] || "type " + type, value: asciiString(d.subarray(p, p + length)) });
          p += length;
        }
        if (2 + listLength > d.length) push("server_name list length exceeds the extension");
        ext.names = names;
        ext.summary = names.map((n) => n.value).join(", ") || "empty name list";
        ext.fields = names.length
          ? names.map((n, i) => field("Name " + (i + 1), n.value, n.typeName))
          : [field("List length", listLength)];
        break;
      }
      case 10: {
        if (d.length < 2) { push("supported_groups is too short"); break; }
        const listLength = PH.u16be(d, 0);
        const groups = pairList(d.subarray(2, Math.min(d.length, 2 + listLength)), groupName);
        ext.groups = groups;
        ext.summary = groups.map((g) => g.name).join(", ") || "no groups";
        ext.fields = groups.map((g, i) => field("Group " + (i + 1), g.name, "0x" + PH.hex(g.code, 4)));
        if (2 + listLength !== d.length) push("supported_groups length does not match the extension");
        break;
      }
      case 11: {
        if (d.length < 1) { push("ec_point_formats is too short"); break; }
        const count = d[0];
        const formatNames = ["uncompressed", "ansiX962_compressed_prime", "ansiX962_compressed_char2"];
        const formats = Array.from(d.subarray(1, 1 + count), (v) => formatNames[v] || "format " + v);
        ext.summary = formats.join(", ") || "none";
        ext.fields = formats.map((f, i) => field("Format " + (i + 1), f));
        break;
      }
      case 13:
      case 50: {
        if (d.length < 2) { push(ext.name + " is too short"); break; }
        const listLength = PH.u16be(d, 0);
        const schemes = pairList(d.subarray(2, Math.min(d.length, 2 + listLength)), sigName);
        ext.schemes = schemes;
        ext.summary = schemes.map((s) => s.name).join(", ") || "no schemes";
        ext.fields = schemes.map((s, i) => field("Scheme " + (i + 1), s.name, "0x" + PH.hex(s.code, 4)));
        if (2 + listLength !== d.length) push(ext.name + " length does not match the extension");
        break;
      }
      case 16: {
        if (d.length < 2) { push("ALPN extension is too short"); break; }
        const listLength = PH.u16be(d, 0);
        let p = 2;
        const protocols = [];
        const end = Math.min(d.length, 2 + listLength);
        while (p < end) {
          const length = d[p];
          p += 1;
          if (p + length > end) { push("ALPN protocol overruns the list"); break; }
          protocols.push(asciiString(d.subarray(p, p + length)));
          p += length;
        }
        ext.protocols = protocols;
        ext.summary = protocols.join(", ") || "empty ALPN list";
        ext.fields = protocols.map((value, i) => field("Protocol " + (i + 1), value));
        if (2 + listLength > d.length) push("ALPN list length exceeds the extension");
        break;
      }
      case 43: {
        if (context === "server") {
          if (d.length !== 2) push("ServerHello supported_versions should be 2 bytes");
          const code = d.length >= 2 ? PH.u16be(d, 0) : null;
          ext.selectedVersion = code;
          ext.summary = code == null ? "truncated" : versionName(code);
          ext.fields = [field("Selected version", code == null ? "—" : versionName(code), code == null ? "" : "0x" + PH.hex(code, 4))];
        } else {
          if (d.length < 1) { push("supported_versions is too short"); break; }
          const count = d[0];
          const versions = [];
          for (let p = 1; p + 1 < d.length && p <= count; p += 2) {
            const code = PH.u16be(d, p);
            versions.push({ code, name: versionName(code) });
          }
          ext.versions = versions;
          ext.summary = versions.map((v) => v.name).join(", ") || "no versions";
          ext.fields = versions.map((v, i) => field("Version " + (i + 1), v.name, "0x" + PH.hex(v.code, 4)));
          if (count !== versions.length * 2) push("supported_versions byte count does not match the list");
        }
        break;
      }
      case 51: {
        if (context === "server") {
          if (d.length < 4) { push("ServerHello key_share is too short"); break; }
          const group = PH.u16be(d, 0);
          const length = PH.u16be(d, 2);
          const key = d.subarray(4, Math.min(d.length, 4 + length));
          ext.group = group;
          ext.key = key;
          ext.summary = groupName(group) + " · " + key.length + " B key";
          ext.fields = [field("Group", groupName(group), "0x" + PH.hex(group, 4)), field("Key length", key.length + " B"), field("Key", preview(key, 32))];
          if (4 + length !== d.length) push("key_share key length does not match the extension");
        } else {
          if (d.length < 2) { push("key_share is too short"); break; }
          const listLength = PH.u16be(d, 0);
          let p = 2;
          const shares = [];
          const end = Math.min(d.length, 2 + listLength);
          while (p + 4 <= end) {
            const group = PH.u16be(d, p);
            const length = PH.u16be(d, p + 2);
            p += 4;
            if (p + length > end) { push("key_share entry overruns the list"); break; }
            shares.push({ group, groupName: groupName(group), key: d.subarray(p, p + length) });
            p += length;
          }
          ext.shares = shares;
          ext.summary = shares.map((s) => s.groupName + " · " + s.key.length + " B").join(", ") || "no shares";
          ext.fields = shares.length
            ? shares.map((s, i) => field("Share " + (i + 1), s.groupName + " · " + s.key.length + " B", preview(s.key, 24)))
            : [field("List length", listLength)];
          if (2 + listLength > d.length) push("key_share list length exceeds the extension");
        }
        break;
      }
      case 45: {
        if (d.length < 1) { push("psk_key_exchange_modes is too short"); break; }
        const count = d[0];
        const modes = Array.from(d.subarray(1, 1 + count), (v) => PSK_MODES[v] || "mode " + v);
        ext.summary = modes.join(", ") || "none";
        ext.fields = modes.map((m, i) => field("Mode " + (i + 1), m));
        break;
      }
      case 41: {
        let p = 0;
        const identities = [];
        if (d.length >= 2) {
          const identitiesLength = PH.u16be(d, 0);
          p = 2;
          const end = Math.min(d.length, 2 + identitiesLength);
          while (p + 6 <= end) {
            const length = PH.u16be(d, p);
            p += 2;
            if (p + length + 4 > end) { push("pre_shared_key identity overruns the list"); break; }
            identities.push({ identity: d.subarray(p, p + length), age: PH.u32be(d, p + length) });
            p += length + 4;
          }
          p = 2 + identitiesLength;
        }
        const binders = [];
        if (p + 2 <= d.length) {
          const bindersLength = PH.u16be(d, p);
          p += 2;
          const end = Math.min(d.length, p + bindersLength);
          while (p < end) {
            const length = d[p];
            p += 1;
            if (p + length > end) { push("pre_shared_key binder overruns the list"); break; }
            binders.push(d.subarray(p, p + length));
            p += length;
          }
        }
        ext.identities = identities;
        ext.binders = binders;
        ext.summary = identities.length + " identity(ies) · " + binders.length + " binder(s)";
        ext.fields = [
          field("Identities", identities.length),
          field("Binders", binders.length)
        ];
        identities.slice(0, 3).forEach((identity, i) => {
          ext.fields.push(field("Identity " + (i + 1), preview(identity.identity, 16), "age " + identity.age));
        });
        break;
      }
      case 42: {
        if (d.length === 0) ext.summary = "empty · early_data acknowledged";
        else if (d.length === 4) {
          const max = PH.u32be(d, 0);
          ext.summary = "max_early_data_size " + max;
          ext.fields = [field("Max early data", max + " B")];
        } else {
          ext.summary = d.length + " B";
          ext.fields = [field("Data", preview(d))];
        }
        break;
      }
      case 44: {
        if (d.length < 2) { push("cookie extension is too short"); break; }
        const length = PH.u16be(d, 0);
        ext.summary = length + " B cookie";
        ext.fields = [field("Cookie length", length + " B"), field("Cookie", preview(d.subarray(2, 2 + length), 24))];
        break;
      }
      case 28: {
        if (d.length !== 2) push("record_size_limit should be 2 bytes");
        const limit = d.length >= 2 ? PH.u16be(d, 0) : null;
        ext.summary = limit == null ? "truncated" : limit + " B";
        ext.fields = [field("Record size limit", limit == null ? "—" : limit + " B")];
        break;
      }
      case 5: {
        if (d.length >= 1) {
          ext.fields.push(field("Status type", d[0] === 1 ? "ocsp" : String(d[0])));
          if (d[0] === 1 && d.length >= 5) {
            const responderLength = PH.u16be(d, 1);
            ext.fields.push(field("Responder ID length", responderLength + " B"));
            ext.summary = "OCSP status_request · " + responderLength + " B responder ID";
          } else {
            ext.summary = "status_request";
          }
        } else {
          push("status_request is empty");
        }
        break;
      }
      case 47: {
        if (d.length < 2) { push("certificate_authorities is too short"); break; }
        const listLength = PH.u16be(d, 0);
        const names = [];
        let p = 2;
        const end = Math.min(d.length, 2 + listLength);
        while (p + 2 <= end) {
          const length = PH.u16be(d, p);
          p += 2;
          if (p + length > end) { push("authority name overruns the list"); break; }
          names.push(d.subarray(p, p + length));
          p += length;
        }
        ext.summary = names.length + " distinguished name(s)";
        ext.fields = [field("Names", names.length)];
        break;
      }
      case 21:
        ext.summary = d.length + " padding byte(s)";
        ext.fields = [field("Padding", d.length + " B")];
        break;
      case 23:
        ext.summary = "extended_master_secret";
        break;
      case 22:
        ext.summary = "encrypt_then_mac";
        break;
      case 49:
        ext.summary = "post_handshake_auth";
        break;
      case 35:
        ext.summary = d.length + " B session ticket";
        ext.fields = [field("Ticket", preview(d, 24))];
        break;
      case 0xfe0d:
        ext.summary = "encrypted ClientHello · " + d.length + " B";
        ext.fields = [field("ECH", preview(d, 24))];
        break;
      case 0xff01:
        ext.summary = d.length ? "renegotiation info · " + d.length + " B" : "renegotiation info";
        break;
      default:
        ext.summary = d.length + " B · " + preview(d, 16);
        ext.fields = [field("Data", preview(d, 32))];
        break;
    }
    if (!ext.summary) ext.summary = ext.length + " B";
  }

  /* ---------- handshake body parsers (continued in part 2) ---------- */

  function extByType(extensions, type) {
    return (extensions || []).find((ext) => ext.type === type) || null;
  }

  function summarizeExtensions(extensions) {
    if (!extensions || !extensions.length) return "no extensions";
    return extensions.map((ext) => ext.name).join(", ");
  }

  function representCipherSuites(suites) {
    if (!suites.length) return "empty";
    const names = suites.map((suite) => suite.name);
    return names.length <= 4 ? names.join(", ") : names.slice(0, 4).join(", ") + " +" + (names.length - 4);
  }

  function parseClientHello(body, ctx, warnings) {
    if (body.length < 34) {
      warnings.push("ClientHello is shorter than legacy_version + random");
      return { fields: [field("Length", body.length + " B")], summary: "ClientHello · truncated" };
    }
    const legacyVersion = PH.u16be(body, 0);
    const random = body.subarray(2, 34);
    let pos = 34;
    const fields = [
      field("Legacy version", versionName(legacyVersion), "0x" + PH.hex(legacyVersion, 4)),
      field("Random", preview(random, 16), "32 bytes")
    ];
    let sessionId = new Uint8Array(0);
    if (pos < body.length) {
      let sidLength = body[pos];
      pos += 1;
      if (sidLength > 32) warnings.push("ClientHello session_id is " + sidLength + " bytes; maximum is 32");
      if (pos + sidLength > body.length) {
        warnings.push("ClientHello session_id overruns the message");
        sidLength = Math.max(0, body.length - pos);
      }
      sessionId = body.subarray(pos, pos + sidLength);
      pos += sidLength;
      fields.push(field("Session ID", sessionId.length ? sessionId.length + " B · " + preview(sessionId, 16) : "empty"));
    } else {
      warnings.push("ClientHello ends before session_id");
    }
    let suites = [];
    if (pos + 2 <= body.length) {
      const suitesLength = PH.u16be(body, pos);
      pos += 2;
      if (suitesLength % 2) warnings.push("ClientHello cipher_suites length is not a multiple of 2");
      if (pos + suitesLength > body.length) warnings.push("ClientHello cipher_suites overrun the message");
      suites = pairList(body.subarray(pos, Math.min(body.length, pos + suitesLength)), cipherName);
      pos += suitesLength;
    }
    let compression = [];
    if (pos < body.length) {
      const count = body[pos];
      pos += 1;
      if (pos + count > body.length) warnings.push("ClientHello compression methods overrun the message");
      compression = Array.from(body.subarray(pos, Math.min(body.length, pos + count)));
      pos += count;
      if (!compression.includes(0)) warnings.push("ClientHello compression methods do not include null (0)");
    }
    let extensions = [];
    if (pos + 2 <= body.length) {
      const extLength = PH.u16be(body, pos);
      pos += 2;
      if (pos + extLength > body.length) warnings.push("ClientHello extensions overrun the message");
      extensions = decodeExtensions(body.subarray(pos, Math.min(body.length, pos + extLength)), "client", warnings);
      pos += extLength;
    } else if (pos < body.length) {
      warnings.push((body.length - pos) + " byte(s) after compression methods but no extension length");
    }
    if (pos < body.length) warnings.push((body.length - pos) + " trailing byte(s) after ClientHello extensions");

    fields.push(field("Cipher suites", suites.length + " · " + representCipherSuites(suites)));
    fields.push(field("Compression", compression.length ? compression.join(", ") : "none"));
    fields.push(field("Extensions", extensions.length + " · " + summarizeExtensions(extensions)));

    const supportedVersions = extByType(extensions, 43);
    const serverName = extByType(extensions, 0);
    const alpn = extByType(extensions, 16);
    const groups = extByType(extensions, 10);
    const keyShare = extByType(extensions, 51);
    const versions = supportedVersions && supportedVersions.versions
      ? supportedVersions.versions.map((v) => v.code)
      : [legacyVersion];
    ctx.clientVersions = versions;
    ctx.legacyVersion = legacyVersion;
    ctx.clientRandom = random;
    ctx.sessionId = sessionId;
    ctx.sni = serverName && serverName.names && serverName.names[0] ? serverName.names[0].value : null;
    ctx.alpn = alpn ? alpn.protocols : null;
    ctx.keyShareGroups = keyShare && keyShare.shares ? keyShare.shares.map((s) => s.group) : (groups ? groups.groups.map((g) => g.code) : []);
    ctx.cipherSuites = suites;

    const summaryBits = [];
    if (ctx.sni) summaryBits.push("SNI " + ctx.sni);
    if (ctx.alpn) summaryBits.push("ALPN " + ctx.alpn.join("/"));
    summaryBits.push(suites.length + " suite(s)");
    summaryBits.push(extensions.length + " extension(s)");
    return {
      legacyVersion, random, sessionId, suites, compression, extensions,
      clientVersions: versions,
      fields, summary: "ClientHello · " + summaryBits.join(" · ")
    };
  }

  function parseServerHello(body, ctx, warnings) {
    if (body.length < 38) {
      warnings.push("ServerHello is shorter than legacy_version + random + session_id + cipher_suite");
      return { fields: [field("Length", body.length + " B")], summary: "ServerHello · truncated" };
    }
    const legacyVersion = PH.u16be(body, 0);
    const random = body.subarray(2, 34);
    let pos = 34;
    const fields = [
      field("Legacy version", versionName(legacyVersion), "0x" + PH.hex(legacyVersion, 4)),
      field("Random", preview(random, 16), "32 bytes")
    ];
    const sidLength = body[pos];
    pos += 1;
    if (sidLength > 32) warnings.push("ServerHello session_id is " + sidLength + " bytes; maximum is 32");
    if (pos + sidLength > body.length) warnings.push("ServerHello session_id overruns the message");
    const sessionId = body.subarray(pos, Math.min(body.length, pos + sidLength));
    pos += sidLength;
    fields.push(field("Session ID echo", sessionId.length ? sessionId.length + " B · " + preview(sessionId, 16) : "empty"));
    let cipherSuite = null;
    if (pos + 2 <= body.length) {
      cipherSuite = PH.u16be(body, pos);
      pos += 2;
      fields.push(field("Cipher suite", cipherName(cipherSuite), "0x" + PH.hex(cipherSuite, 4)));
    } else {
      warnings.push("ServerHello ends before cipher_suite");
    }
    let compression = null;
    if (pos < body.length) {
      compression = body[pos];
      pos += 1;
      fields.push(field("Compression", compression === 0 ? "0 · null" : String(compression)));
      if (compression !== 0) warnings.push("ServerHello legacy_compression_method is " + compression + "; TLS 1.3 requires 0");
    }
    let extensions = [];
    if (pos + 2 <= body.length) {
      const extLength = PH.u16be(body, pos);
      pos += 2;
      if (pos + extLength > body.length) warnings.push("ServerHello extensions overrun the message");
      extensions = decodeExtensions(body.subarray(pos, Math.min(body.length, pos + extLength)), "server", warnings);
      pos += extLength;
    }
    if (pos < body.length) warnings.push((body.length - pos) + " trailing byte(s) after ServerHello extensions");
    fields.push(field("Extensions", extensions.length + " · " + summarizeExtensions(extensions)));

    const supportedVersion = extByType(extensions, 43);
    const keyShare = extByType(extensions, 51);
    const negotiatedVersion = supportedVersion && supportedVersion.selectedVersion != null
      ? supportedVersion.selectedVersion : legacyVersion;
    ctx.negotiatedVersion = negotiatedVersion;
    ctx.serverRandom = random;
    ctx.cipherSuite = cipherSuite;
    ctx.serverSessionId = sessionId;
    ctx.serverKeyShare = keyShare || null;
    return {
      legacyVersion, random, sessionId, cipherSuite, compression, extensions,
      negotiatedVersion,
      fields,
      summary: "ServerHello · " + versionName(negotiatedVersion) + " · " + cipherName(cipherSuite) +
        " · " + extensions.length + " extension(s)"
    };
  }

  function parseEncryptedExtensions(body, ctx, warnings) {
    if (body.length < 2) {
      warnings.push("EncryptedExtensions is shorter than its extension length");
      return { fields: [], summary: "EncryptedExtensions · truncated" };
    }
    const extLength = PH.u16be(body, 0);
    if (2 + extLength > body.length) warnings.push("EncryptedExtensions length exceeds the message");
    const extensions = decodeExtensions(body.subarray(2, Math.min(body.length, 2 + extLength)), "encrypted", warnings);
    if (2 + extLength < body.length) warnings.push((body.length - 2 - extLength) + " trailing byte(s) after EncryptedExtensions");
    const alpn = extByType(extensions, 16);
    if (alpn) ctx.alpn = alpn.protocols;
    return {
      extensions,
      fields: [
        field("Extensions", extensions.length + " · " + summarizeExtensions(extensions)),
        field("ALPN", alpn ? alpn.protocols.join(", ") : "not present")
      ],
      summary: "EncryptedExtensions · " + extensions.length + " extension(s)" +
        (alpn ? " · ALPN " + alpn.protocols.join("/") : "")
    };
  }

  function tryCertificate13(body) {
    let p = 0;
    if (!body.length) throw new Error("empty Certificate");
    const contextLength = body[p];
    p += 1;
    if (p + contextLength + 2 > body.length) throw new Error("request context overruns Certificate");
    const requestContext = body.subarray(p, p + contextLength);
    p += contextLength;
    const listLength = PH.u16be(body, p);
    p += 2;
    if (p + listLength > body.length) throw new Error("certificate_list overruns Certificate");
    const end = p + listLength;
    const certs = [];
    while (p < end) {
      if (p + 3 > end) throw new Error("truncated certificate length");
      const certLength = u24(body, p);
      p += 3;
      if (p + certLength > end) throw new Error("certificate overruns certificate_list");
      const der = body.subarray(p, p + certLength);
      p += certLength;
      let extensions = [];
      if (p + 2 <= end) {
        const extLength = PH.u16be(body, p);
        p += 2;
        if (p + extLength > end) throw new Error("certificate extensions overrun the entry");
        extensions = decodeExtensions(body.subarray(p, p + extLength), "certificate", []);
        p += extLength;
      }
      certs.push({ der, length: der.length, extensions });
    }
    if (p !== end) throw new Error("certificate_list has trailing bytes");
    return { format: "TLS 1.3", requestContext, certs, trailing: body.length - end };
  }

  function parseCertificate12(body, warnings) {
    if (body.length < 3) {
      warnings.push("TLS 1.2 Certificate is shorter than its 3-byte list length");
      return { format: "TLS 1.2", requestContext: new Uint8Array(0), certs: [], trailing: body.length };
    }
    const listLength = u24(body, 0);
    let p = 3;
    if (p + listLength > body.length) warnings.push("TLS 1.2 certificate_list length exceeds the message");
    const end = Math.min(body.length, 3 + listLength);
    const certs = [];
    while (p + 3 <= end) {
      const certLength = u24(body, p);
      p += 3;
      if (p + certLength > end) { warnings.push("TLS 1.2 certificate overruns the list"); break; }
      const der = body.subarray(p, p + certLength);
      p += certLength;
      certs.push({ der, length: der.length, extensions: [] });
    }
    return { format: "TLS 1.2", requestContext: new Uint8Array(0), certs, trailing: body.length - end };
  }

  function parseCertificate(body, ctx, warnings) {
    let parsed = null;
    if (ctx.negotiatedVersion && ctx.negotiatedVersion < 0x0304) {
      parsed = parseCertificate12(body, warnings);
    } else {
      try {
        parsed = tryCertificate13(body);
      } catch (err) {
        parsed = parseCertificate12(body, warnings);
        warnings.push("Certificate did not match the TLS 1.3 shape (" + err.message + "); parsed as TLS 1.2");
      }
    }
    const fields = [
      field("Format", parsed.format),
      field("Request context", parsed.requestContext.length ? preview(parsed.requestContext, 16) : "empty"),
      field("Certificates", parsed.certs.length)
    ];
    parsed.certs.slice(0, 6).forEach((cert, index) => {
      fields.push(field("Certificate " + (index + 1), cert.length + " B" + (cert.extensions.length ? " · " + cert.extensions.length + " extension(s)" : ""), preview(cert.der, 16)));
    });
    if (parsed.trailing) warnings.push(parsed.trailing + " trailing byte(s) after the certificate list");
    parsed.certs.forEach((cert, index) => {
      if (cert.der.length < 2 || cert.der[0] !== 0x30) {
        warnings.push("Certificate " + (index + 1) + " does not start with a DER SEQUENCE (0x30)");
      }
    });
    return {
      ...parsed,
      fields,
      summary: "Certificate · " + parsed.format + " · " + parsed.certs.length + " certificate(s)" +
        (parsed.certs.length ? " · " + parsed.certs[0].length + " B leaf" : "")
    };
  }

  function parseCertificateRequest(body, ctx, warnings) {
    if (ctx.negotiatedVersion && ctx.negotiatedVersion >= 0x0304) {
      let p = 0;
      const contextLength = body.length ? body[p] : 0;
      p += 1;
      if (p + contextLength + 2 > body.length) {
        warnings.push("CertificateRequest request context overruns the message");
        return { fields: [field("Length", body.length + " B")], summary: "CertificateRequest · truncated" };
      }
      const requestContext = body.subarray(p, p + contextLength);
      p += contextLength;
      const extLength = PH.u16be(body, p);
      p += 2;
      if (p + extLength > body.length) warnings.push("CertificateRequest extensions overrun the message");
      const extensions = decodeExtensions(body.subarray(p, Math.min(body.length, p + extLength)), "certificate-request", warnings);
      return {
        format: "TLS 1.3", requestContext, extensions,
        fields: [
          field("Format", "TLS 1.3"),
          field("Request context", requestContext.length ? preview(requestContext, 16) : "empty"),
          field("Extensions", extensions.length + " · " + summarizeExtensions(extensions))
        ],
        summary: "CertificateRequest · TLS 1.3 · " + extensions.length + " extension(s)"
      };
    }
    let p = 0;
    const fields = [field("Format", "TLS 1.2")];
    const certTypes = [];
    if (p < body.length) {
      const count = body[p];
      p += 1;
      for (let i = 0; i < count && p < body.length; i++, p++) {
        certTypes.push(CLIENT_CERT_TYPES[body[p]] || "type " + body[p]);
      }
      fields.push(field("Certificate types", certTypes.join(", ") || "none"));
    }
    const schemes = [];
    if (p + 2 <= body.length) {
      const length = PH.u16be(body, p);
      p += 2;
      const values = body.subarray(p, Math.min(body.length, p + length));
      schemes.push(...pairList(values, sigName).map((s) => s.name));
      p += length;
      fields.push(field("Signature schemes", schemes.join(", ") || "none"));
    }
    return { format: "TLS 1.2", certTypes, schemes, fields, summary: "CertificateRequest · TLS 1.2" };
  }

  function parseCertificateVerify(body, ctx, warnings) {
    if (body.length < 4) {
      warnings.push("CertificateVerify is shorter than its algorithm + signature length");
      return { fields: [field("Length", body.length + " B")], summary: "CertificateVerify · truncated" };
    }
    const scheme = PH.u16be(body, 0);
    const length = PH.u16be(body, 2);
    const signature = body.subarray(4, Math.min(body.length, 4 + length));
    if (4 + length > body.length) warnings.push("CertificateVerify signature length exceeds the message");
    return {
      scheme, signature,
      fields: [
        field("Signature scheme", sigName(scheme), "0x" + PH.hex(scheme, 4)),
        field("Signature length", signature.length + " B"),
        field("Signature", preview(signature, 32))
      ],
      summary: "CertificateVerify · " + sigName(scheme) + " · " + signature.length + " B"
    };
  }

  function parseNewSessionTicket(body, ctx, warnings) {
    let parsed = null;
    if (body.length >= 13) {
      let p = 0;
      const lifetime = PH.u32be(body, p); p += 4;
      const ageAdd = PH.u32be(body, p); p += 4;
      const nonceLength = body[p]; p += 1;
      if (p + nonceLength + 2 <= body.length) {
        const nonce = body.subarray(p, p + nonceLength); p += nonceLength;
        const ticketLength = PH.u16be(body, p); p += 2;
        if (p + ticketLength + 2 <= body.length) {
          const ticket = body.subarray(p, p + ticketLength); p += ticketLength;
          const extLength = PH.u16be(body, p); p += 2;
          if (p + extLength === body.length) {
            const extensions = decodeExtensions(body.subarray(p, p + extLength), "new-session-ticket", warnings);
            parsed = { format: "TLS 1.3", lifetime, ageAdd, nonce, ticket, extensions };
          }
        }
      }
    }
    if (!parsed) {
      if (body.length >= 6) {
        const lifetime = PH.u32be(body, 0);
        const ticketLength = PH.u16be(body, 4);
        const ticket = body.subarray(6, Math.min(body.length, 6 + ticketLength));
        parsed = { format: "TLS 1.2", lifetime, ticket };
        warnings.push("NewSessionTicket did not match the TLS 1.3 shape; parsed as TLS 1.2");
      } else {
        warnings.push("NewSessionTicket is too short");
        return { fields: [field("Length", body.length + " B")], summary: "NewSessionTicket · truncated" };
      }
    }
    const fields = [field("Format", parsed.format), field("Lifetime", parsed.lifetime + " s")];
    if (parsed.ageAdd != null) fields.push(field("Ticket age add", "0x" + PH.hex(parsed.ageAdd, 8)));
    if (parsed.nonce) fields.push(field("Nonce", parsed.nonce.length ? preview(parsed.nonce, 16) : "empty"));
    fields.push(field("Ticket", parsed.ticket.length + " B · " + preview(parsed.ticket, 16)));
    if (parsed.extensions) fields.push(field("Extensions", parsed.extensions.length + " · " + summarizeExtensions(parsed.extensions)));
    return { ...parsed, fields, summary: "NewSessionTicket · " + parsed.format + " · ticket " + parsed.ticket.length + " B" };
  }

  function decodeHandshakeMessage(type, body, ctx, warnings) {
    const message = {
      type, typeName: handshakeName(type), length: body.length, body,
      warnings: [], fields: [], summary: ""
    };
    switch (type) {
      case 1: Object.assign(message, parseClientHello(body, ctx, warnings)); break;
      case 2: Object.assign(message, parseServerHello(body, ctx, warnings)); break;
      case 8: Object.assign(message, parseEncryptedExtensions(body, ctx, warnings)); break;
      case 11: Object.assign(message, parseCertificate(body, ctx, warnings)); break;
      case 13: Object.assign(message, parseCertificateRequest(body, ctx, warnings)); break;
      case 15: Object.assign(message, parseCertificateVerify(body, ctx, warnings)); break;
      case 20:
        message.verifyData = body;
        message.fields = [field("Verify data", body.length ? preview(body, 32) : "empty")];
        message.summary = "Finished · " + body.length + " B verify_data";
        break;
      case 4: Object.assign(message, parseNewSessionTicket(body, ctx, warnings)); break;
      case 24:
        message.requestUpdate = body.length ? body[0] : null;
        message.fields = [field("Request update", message.requestUpdate == null ? "truncated" : (message.requestUpdate ? "1 · requested" : "0 · not requested"))];
        message.summary = "KeyUpdate · " + (message.requestUpdate ? "update requested" : "no update request");
        break;
      case 5:
        message.fields = [field("Length", body.length + " B")];
        message.summary = "EndOfEarlyData";
        break;
      case 0:
        message.fields = [field("Length", body.length + " B")];
        message.summary = "HelloRequest";
        break;
      case 12:
        message.fields = [field("Data", preview(body, 32))];
        message.summary = "ServerKeyExchange · " + body.length + " B (algorithm-specific)";
        break;
      case 16:
        message.fields = [field("Data", preview(body, 32))];
        message.summary = "ClientKeyExchange · " + body.length + " B (algorithm-specific)";
        break;
      case 14:
        message.fields = [field("Length", body.length + " B")];
        message.summary = "ServerHelloDone";
        break;
      default:
        message.fields = [field("Body", preview(body, 32))];
        message.summary = handshakeName(type) + " · " + body.length + " B";
        break;
    }
    message.fields.unshift(field("Type", type + " · " + message.typeName));
    message.fields.unshift(field("Length", body.length + " B", "handshake body"));
    return message;
  }

  function decodeHandshakeStream(records, warnings, ctx) {
    const messages = [];
    let pending = new Uint8Array(0);
    let pendingOffset = 0;
    records.forEach((record) => {
      if (record.type !== 22 || !record.fragment.length) return;
      if (!pending.length) pendingOffset = record.fragmentOffset;
      pending = PH.concatBytes(pending, record.fragment);
      let p = 0;
      while (p + 4 <= pending.length) {
        const type = pending[p];
        const length = u24(pending, p + 1);
        if (p + 4 + length > pending.length) break;
        const body = pending.subarray(p + 4, p + 4 + length);
        const message = decodeHandshakeMessage(type, body, ctx, warnings);
        message.offset = pendingOffset + p;
        message.recordIndex = record.index;
        message.warnings.slice().forEach((warning) => warnings.push(warning));
        messages.push(message);
        p += 4 + length;
      }
      if (p) {
        pending = pending.subarray(p);
        pendingOffset += p;
      }
    });
    if (pending.length) {
      warnings.push(pending.length + " byte(s) of an incomplete handshake message remain at the end of the capture");
    }
    return messages;
  }

  /* ---------- top-level decode ---------- */

  function decodeAlert(fragment, warnings) {
    if (!fragment || fragment.length < 2) {
      if (warnings) warnings.push("Alert record is shorter than level + description");
      return { level: null, levelName: "truncated", description: null, descriptionName: "truncated", fields: [], summary: "Alert · truncated" };
    }
    const level = fragment[0];
    const description = fragment[1];
    const levelName = level === 1 ? "warning" : level === 2 ? "fatal" : "level " + level;
    return {
      level, levelName, description, descriptionName: alertName(description),
      fields: [
        field("Level", level + " · " + levelName),
        field("Description", description + " · " + alertName(description))
      ],
      summary: "Alert · " + levelName + " · " + alertName(description)
    };
  }

  function decodeTls(bytes, opts) {
    const options = opts || {};
    const warnings = [];
    const recordInfo = decodeRecords(bytes);
    const records = recordInfo.records;
    const ctx = {};
    let handshakes = [];
    let alerts = [];
    let changeCipherSpecs = [];
    if (!records.length) {
      if (bytes.length >= 4 && HANDSHAKE_TYPES[bytes[0]] != null && u24(bytes, 1) <= bytes.length - 4) {
        handshakes = decodeHandshakeStream([
          { type: 22, fragment: bytes, fragmentOffset: 0, index: 0 }
        ], warnings, ctx);
        if (!handshakes.length) throw new Error("Not a TLS record stream and not a complete handshake message");
        return {
          kind: "tls", rawHandshake: true, bytes, records: [], handshakes, alerts: [],
          changeCipherSpecs: [], warnings, length: bytes.length, context: ctx,
          summary: "Raw TLS handshake · " + handshakes.map((m) => m.typeName).join(" → ")
        };
      }
      throw new Error("Not a TLS record stream: first byte " + (bytes.length ? "0x" + PH.hex(bytes[0]) : "(empty)") +
        " is not a known content type and no handshake header is present");
    }
    recordInfo.warnings.forEach((warning) => warnings.push(warning));
    handshakes = decodeHandshakeStream(records, warnings, ctx);
    records.forEach((record) => {
      if (record.type === 21) {
        const alert = decodeAlert(record.fragment, warnings);
        alert.recordIndex = record.index;
        alert.offset = record.fragmentOffset;
        alerts.push(alert);
      } else if (record.type === 20) {
        changeCipherSpecs.push({
          recordIndex: record.index, offset: record.fragmentOffset,
          value: record.fragment.length ? record.fragment[0] : null,
          valid: record.fragment.length === 1 && record.fragment[0] === 1
        });
        if (!(record.fragment.length === 1 && record.fragment[0] === 1)) {
          warnings.push("ChangeCipherSpec record should contain the single byte 0x01");
        }
      }
    });
    if (records.some((record) => record.truncated)) {
      warnings.push("The capture ends inside a TLS record; later layers may be missing");
    }
    if (ctx.negotiatedVersion >= 0x0304) {
      const encrypted = records.filter((record) => record.type === 23);
      if (encrypted.length) {
        warnings.push("TLS 1.3 encrypts handshake and application data after ServerHello; " +
          encrypted.length + " application-data record(s) are opaque without traffic keys");
      }
    }
    const summaryBits = [];
    if (ctx.negotiatedVersion) summaryBits.push(versionName(ctx.negotiatedVersion));
    else if (ctx.clientVersions && ctx.clientVersions.length) summaryBits.push(versionName(ctx.clientVersions[0]));
    if (ctx.sni) summaryBits.push("SNI " + ctx.sni);
    if (ctx.alpn) summaryBits.push("ALPN " + ctx.alpn.join("/"));
    if (handshakes.length) summaryBits.push(handshakes.map((m) => m.typeName).join(" → "));
    summaryBits.push(records.length + " record(s)");
    return {
      kind: "tls", bytes, records, handshakes, alerts,
      changeCipherSpecs, warnings,
      length: recordInfo.length,
      context: ctx,
      summary: "TLS · " + summaryBits.join(" · ")
    };
  }

  /* ---------- encoding ---------- */

  function putU24(arr, off, value) {
    arr[off] = (value >>> 16) & 255;
    arr[off + 1] = (value >>> 8) & 255;
    arr[off + 2] = value & 255;
  }

  function be16(value) {
    const out = new Uint8Array(2);
    PH.put16be(out, 0, value);
    return out;
  }

  function be24(value) {
    const out = new Uint8Array(3);
    putU24(out, 0, value);
    return out;
  }

  function be32(value) {
    const out = new Uint8Array(4);
    PH.put32be(out, 0, value);
    return out;
  }

  function buildExtension(type, data) {
    const payload = toBytes(data);
    if (payload.length > 0xffff) throw new Error("TLS extension exceeds 65535 bytes");
    return PH.concatBytes(be16(type), be16(payload.length), payload);
  }

  function buildHandshake(type, body) {
    if (body.length > 0xffffff) throw new Error("TLS handshake message exceeds 24-bit length");
    return PH.concatBytes(Uint8Array.from([type]), be24(body.length), body);
  }

  function buildRecord(type, fragment, version) {
    const payload = toBytes(fragment);
    if (payload.length > 0xffff) throw new Error("TLS record fragment exceeds 65535 bytes");
    return PH.concatBytes(Uint8Array.from([type]), be16(version == null ? 0x0303 : version), be16(payload.length), payload);
  }

  function inverse(map) {
    const out = {};
    Object.keys(map).forEach((code) => { out[map[code]] = Number(code); });
    return out;
  }

  const CIPHER_VALUES = inverse(CIPHER_SUITES);
  const GROUP_VALUES = inverse(GROUPS);
  const SIG_VALUES = inverse(SIG_SCHEMES);

  const VERSION_VALUES = inverse(VERSIONS);

  function codeValue(value, values, label) {
    if (typeof value === "number") {
      if (!Number.isInteger(value) || value < 0 || value > 0xffff) throw new Error(label + " must be 0–65535");
      return value;
    }
    const text = String(value == null ? "" : value).trim();
    if (values[text] != null) return values[text];
    if (/^0x[0-9a-f]+$/i.test(text)) {
      const n = parseInt(text.slice(2), 16);
      if (Number.isInteger(n) && n >= 0 && n <= 0xffff) return n;
    }
    if (/^\d+$/.test(text)) {
      const n = Number(text);
      if (n >= 0 && n <= 0xffff) return n;
    }
    throw new Error("Unknown " + label + " " + text);
  }

  function listCodes(values, table, label) {
    if (values == null) return [];
    if (typeof values === "string") {
      return values.split(/[\s,]+/).filter(Boolean).map((value) => codeValue(value, table, label));
    }
    return values.map((value) => codeValue(value, table, label));
  }

  function defaultRandom() {
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i++) out[i] = i;
    return out;
  }

  function defaultSessionId() {
    const out = new Uint8Array(32);
    for (let i = 0; i < 32; i++) out[i] = (i * 5 + 1) & 255;
    return out;
  }

  function defaultKeyShare(group) {
    const lengths = {
      0x0017: 65,   /* P-256 uncompressed point */
      0x0018: 97,   /* P-384 uncompressed point */
      0x0019: 133,  /* P-521 uncompressed point */
      0x001d: 32,   /* X25519 */
      0x001e: 56,   /* X448 */
      0x11ec: 1216, /* X25519MLKEM768: 32-byte X25519 + 1184-byte ML-KEM-768 */
      0x6399: 1216  /* X25519Kyber768Draft00 */
    };
    const length = lengths[group] || 32;
    const out = new Uint8Array(length);
    for (let i = 0; i < length; i++) out[i] = (i * 7 + 3) & 255;
    return out;
  }

  function buildClientHello(spec) {
    const input = spec || {};
    const random = input.random ? toBytes(input.random) : defaultRandom();
    if (random.length !== 32) throw new Error("ClientHello random must be exactly 32 bytes");
    const sessionId = input.sessionId != null ? toBytes(input.sessionId) : defaultSessionId();
    if (sessionId.length > 32) throw new Error("ClientHello session_id must be at most 32 bytes");
    const suites = listCodes(input.cipherSuites == null
      ? ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"]
      : input.cipherSuites, CIPHER_VALUES, "cipher suite");
    if (!suites.length) throw new Error("ClientHello needs at least one cipher suite");
    const versions = listCodes(input.supportedVersions == null ? ["0x0304", "0x0303"] : input.supportedVersions, VERSION_VALUES, "version");
    const groups = listCodes(input.groups == null ? ["x25519", "secp256r1", "secp384r1"] : input.groups, GROUP_VALUES, "group");
    const sigAlgs = listCodes(input.signatureAlgorithms == null
      ? ["rsa_pss_rsae_sha256", "ecdsa_secp256r1_sha256", "ed25519", "rsa_pkcs1_sha256"]
      : input.signatureAlgorithms, SIG_VALUES, "signature scheme");
    const keyShareGroup = codeValue(input.keyShareGroup == null ? (groups[0] == null ? 0x001d : groups[0]) : input.keyShareGroup, GROUP_VALUES, "key share group");
    const keyShare = input.keyShare ? toBytes(input.keyShare) : defaultKeyShare(keyShareGroup);
    const compression = input.compression == null ? [0] : input.compression.map(Number);
    if (compression.some((value) => !Number.isInteger(value) || value < 0 || value > 255)) {
      throw new Error("Compression methods must be 0–255");
    }
    const extensions = [];
    const sni = input.sni == null ? "example.com" : String(input.sni);
    if (sni) {
      const host = asciiBytes(sni);
      const name = PH.concatBytes(Uint8Array.from([0]), be16(host.length), host);
      extensions.push(buildExtension(0, PH.concatBytes(be16(name.length), name)));
    }
    if (groups.length) {
      extensions.push(buildExtension(10, PH.concatBytes(be16(groups.length * 2), ...groups.map(be16))));
    }
    if (sigAlgs.length) {
      extensions.push(buildExtension(13, PH.concatBytes(be16(sigAlgs.length * 2), ...sigAlgs.map(be16))));
    }
    const protocols = input.alpn == null ? ["h2", "http/1.1"] : input.alpn;
    if (protocols.length) {
      const entries = protocols.map((protocol) => {
        const bytes = asciiBytes(protocol);
        return PH.concatBytes(Uint8Array.from([bytes.length]), bytes);
      });
      const list = PH.concatBytes(...entries);
      extensions.push(buildExtension(16, PH.concatBytes(be16(list.length), list)));
    }
    if (versions.length) {
      extensions.push(buildExtension(43, PH.concatBytes(Uint8Array.from([versions.length * 2]), ...versions.map(be16))));
    }
    const pskModes = input.pskModes == null ? [] : input.pskModes.map(Number);
    if (pskModes.length) {
      extensions.push(buildExtension(45, PH.concatBytes(Uint8Array.from([pskModes.length]), Uint8Array.from(pskModes))));
    }
    if (keyShareGroup != null) {
      const share = PH.concatBytes(be16(keyShareGroup), be16(keyShare.length), keyShare);
      extensions.push(buildExtension(51, PH.concatBytes(be16(share.length), share)));
    }
    (input.extraExtensions || []).forEach((extra) => {
      const type = codeValue(extra.type, {}, "extension type");
      extensions.push(buildExtension(type, extra.data));
    });
    const extBlock = PH.concatBytes(...extensions);
    const body = PH.concatBytes(
      be16(input.legacyVersion == null ? 0x0303 : Number(input.legacyVersion)),
      random,
      Uint8Array.from([sessionId.length]),
      sessionId,
      be16(suites.length * 2),
      ...suites.map(be16),
      Uint8Array.from([compression.length]),
      Uint8Array.from(compression),
      be16(extBlock.length),
      extBlock
    );
    const handshake = buildHandshake(1, body);
    const recordVersion = input.recordVersion == null ? 0x0301 : Number(input.recordVersion);
    const bytes = buildRecord(22, handshake, recordVersion);
    return {
      bytes, handshake, body, recordVersion, random, sessionId, suites, versions,
      groups, sigAlgs, keyShareGroup, keyShare, extensions,
      length: bytes.length
    };
  }

  function buildServerHello(spec) {
    const input = spec || {};
    const random = input.random ? toBytes(input.random) : defaultRandom();
    if (random.length !== 32) throw new Error("ServerHello random must be exactly 32 bytes");
    const sessionId = input.sessionId != null ? toBytes(input.sessionId) : new Uint8Array(0);
    if (sessionId.length > 32) throw new Error("ServerHello session_id echo must be at most 32 bytes");
    const suite = codeValue(input.cipherSuite == null ? "TLS_AES_128_GCM_SHA256" : input.cipherSuite, CIPHER_VALUES, "cipher suite");
    const version = codeValue(input.supportedVersion == null ? "0x0304" : input.supportedVersion, VERSION_VALUES, "version");
    const group = codeValue(input.keyShareGroup == null ? "x25519" : input.keyShareGroup, GROUP_VALUES, "key share group");
    const keyShare = input.keyShare ? toBytes(input.keyShare) : defaultKeyShare(group);
    const extensions = [
      buildExtension(43, be16(version)),
      buildExtension(51, PH.concatBytes(be16(group), be16(keyShare.length), keyShare))
    ];
    (input.extraExtensions || []).forEach((extra) => {
      extensions.push(buildExtension(codeValue(extra.type, {}, "extension type"), extra.data));
    });
    const extBlock = PH.concatBytes(...extensions);
    const body = PH.concatBytes(
      be16(input.legacyVersion == null ? 0x0303 : Number(input.legacyVersion)),
      random,
      Uint8Array.from([sessionId.length]),
      sessionId,
      be16(suite),
      Uint8Array.from([0]),
      be16(extBlock.length),
      extBlock
    );
    const handshake = buildHandshake(2, body);
    const bytes = buildRecord(22, handshake, input.recordVersion == null ? 0x0303 : Number(input.recordVersion));
    return { bytes, handshake, body, random, sessionId, suite, version, group, keyShare, extensions, length: bytes.length };
  }

  function buildAlert(level, description, recordVersion) {
    const fragment = Uint8Array.from([Number(level == null ? 2 : level) & 255, Number(description == null ? 40 : description) & 255]);
    return buildRecord(21, fragment, recordVersion == null ? 0x0303 : recordVersion);
  }

  function buildApplicationData(data, recordVersion) {
    return buildRecord(23, toBytes(data), recordVersion == null ? 0x0303 : recordVersion);
  }

  function examples() {
    const clientHello = buildClientHello({
      sni: "example.com", alpn: ["h2", "http/1.1"],
      cipherSuites: ["TLS_AES_128_GCM_SHA256", "TLS_AES_256_GCM_SHA384", "TLS_CHACHA20_POLY1305_SHA256"],
      groups: ["x25519", "secp256r1", "secp384r1"],
      signatureAlgorithms: ["rsa_pss_rsae_sha256", "ecdsa_secp256r1_sha256", "ed25519", "rsa_pkcs1_sha256"],
      supportedVersions: ["0x0304", "0x0303"]
    });
    const serverHello = buildServerHello({
      sessionId: clientHello.sessionId,
      cipherSuite: "TLS_AES_128_GCM_SHA256",
      keyShareGroup: "x25519"
    });
    const alert = buildAlert(2, 40);
    const appData = buildApplicationData(asciiBytes("GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"));
    return {
      clientHello: { label: "TLS 1.3 ClientHello", bytes: clientHello.bytes, description: "SNI, ALPN, supported_versions, groups and an X25519 key share." },
      serverHello: { label: "TLS 1.3 ServerHello", bytes: serverHello.bytes, description: "Selected version and cipher suite, plus the server key share." },
      alert: { label: "handshake_failure alert", bytes: alert, description: "Fatal alert (level 2, description 40)." },
      appData: { label: "Application Data record", bytes: appData, description: "Plaintext bytes in an Application Data record; on a real connection this record is AEAD-protected and opaque." }
    };
  }

  global.TLSCodec = {
    CONTENT_TYPES, HANDSHAKE_TYPES, EXTENSION_TYPES, VERSIONS, CIPHER_SUITES, GROUPS,
    SIG_SCHEMES, ALERTS, PSK_MODES,
    contentTypeName, handshakeName, versionName, cipherName, groupName, sigName, extName, alertName,
    decodeRecords, decodeExtensions, decodeHandshakeMessage, decodeHandshakeStream,
    decodeAlert, decodeTls, buildExtension, buildHandshake, buildRecord,
    buildClientHello, buildServerHello, buildAlert, buildApplicationData, examples,
    asciiBytes, asciiString, u24
  };
})(window);
