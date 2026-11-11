/* TLS explorer — record/handshake diagrams, ClientHello/ServerHello encoder,
   record decoder and envelope extraction. */
(function () {
  "use strict";

  const PH = window.PH;
  const T = window.TLSCodec;
  const RFC = {
    tls13: "https://www.rfc-editor.org/rfc/rfc8446",
    tls12: "https://www.rfc-editor.org/rfc/rfc5246",
    alpn: "https://www.rfc-editor.org/rfc/rfc7301",
    sni: "https://www.rfc-editor.org/rfc/rfc6066",
    groups: "https://www.rfc-editor.org/rfc/rfc8422"
  };

  const TLS_STEPS = [
    {
      caption: "<b>ClientHello.</b> The client offers TLS 1.3, cipher suites, a key share and extensions. This is a plaintext Handshake record: a capture can read it.",
      client: "ClientHello sent", server: "listening", record: "Handshake", keys: "plaintext", capture: "readable",
      state: "plaintext", stateClass: "warn-text", active: ["client"], match: ["server"]
    },
    {
      caption: "<b>ServerHello.</b> The server selects the version, cipher suite and key share. ServerHello is the last plaintext handshake message; after it, both sides derive handshake traffic keys.",
      client: "ServerHello received", server: "keys derived", record: "Handshake", keys: "plaintext", capture: "readable",
      state: "boundary", stateClass: "warn-text", active: ["server"], match: ["client"]
    },
    {
      caption: "<b>EncryptedExtensions.</b> The server sends the extensions that must stay hidden until keys exist, including ALPN. This message is already inside an Application Data record protected with handshake keys.",
      client: "handshake keys", server: "extensions sent", record: "Application Data", keys: "handshake traffic keys", capture: "AEAD ciphertext",
      state: "encrypted", stateClass: "good-text", active: ["server"], match: ["client"]
    },
    {
      caption: "<b>Certificate.</b> The server's certificate chain is encrypted with handshake keys. A capture without the keys shows ciphertext, not a parseable certificate; this page's decoder cannot decrypt it.",
      client: "certificate", server: "certificate sent", record: "Application Data", keys: "handshake traffic keys", capture: "AEAD ciphertext",
      state: "encrypted", stateClass: "good-text", active: ["server"], match: ["client"]
    },
    {
      caption: "<b>CertificateVerify.</b> The server signs the handshake transcript with the private key for its certificate. The signature is encrypted like the certificate.",
      client: "signature verified", server: "signature sent", record: "Application Data", keys: "handshake traffic keys", capture: "AEAD ciphertext",
      state: "encrypted", stateClass: "good-text", active: ["server"], match: ["client"]
    },
    {
      caption: "<b>Finished (server).</b> The server sends an HMAC over the transcript using the finished key. The client verifies it before trusting the handshake; the message is still encrypted with handshake keys.",
      client: "server Finished verified", server: "Finished sent", record: "Application Data", keys: "handshake traffic keys", capture: "AEAD ciphertext",
      state: "encrypted", stateClass: "good-text", active: ["server"], match: ["client"]
    },
    {
      caption: "<b>Finished (client).</b> The client sends its own Finished. After this, application traffic keys are installed and HTTP or another application protocol can flow inside Application Data records.",
      client: "handshake complete", server: "application keys", record: "Application Data", keys: "handshake keys → app keys", capture: "AEAD ciphertext",
      state: "complete", stateClass: "good-text", active: ["client"], match: ["server"]
    }
  ];

  const TLS_TOKEN_HOME = {
    1: [220, 125], 2: [500, 165], 3: [500, 205], 4: [500, 245],
    5: [500, 285], 6: [500, 325], 7: [220, 365]
  };
  const TLS_TOKEN_TARGET = {
    1: [500, 125], 2: [220, 165], 3: [220, 205], 4: [220, 245],
    5: [220, 285], 6: [220, 325], 7: [500, 365]
  };

  const lanes = {};

  function initDiagrams() {
    lanes.record = PH.byteLane("#tls-record-lane", {
      title: "<b>TLS record</b> · 5-byte header", badge: "RFC 8446 §5.1",
      fields: [
        { id: "rec-type", name: "ContentType", bytes: 1, range: "20–24", desc: "What the fragment carries: ChangeCipherSpec, Alert, Handshake, Application Data or Heartbeat. The type is authenticated by the AEAD, not encrypted in TLS 1.3.", rfc: "RFC 8446 §5.1", rfcUrl: RFC.tls13, tone: "a" },
        { id: "rec-version", name: "legacy_record_version", bytes: 2, range: "0x0301 / 0x0303", desc: "Compatibility version. TLS 1.3 uses 0x0303 for most records; the initial ClientHello may use 0x0301. The negotiated version lives in supported_versions, not here.", rfc: "RFC 8446 §5.1", rfcUrl: RFC.tls13, tone: "b" },
        { id: "rec-length", name: "length", bytes: 2, range: "0–16384 (+256 ciphertext)", desc: "Length of the fragment that follows. Plaintext records are limited to 2^14 bytes; TLS 1.3 permits up to 2^14 + 256 bytes of ciphertext for expansion.", rfc: "RFC 8446 §5.1", rfcUrl: RFC.tls13, tone: "c" },
        { id: "rec-fragment", name: "fragment", bytes: "var", variable: true, range: "length bytes", desc: "The typed payload. A handshake record can contain several handshake messages or a fragment of one; application data is AEAD-protected after keys are installed.", rfc: "RFC 8446 §5.1", rfcUrl: RFC.tls13, tone: "d" }
      ],
      inspector: "#tls-record-inspector",
      note: "The header is always five bytes. The length field does not include the header itself."
    });

    lanes.handshake = PH.byteLane("#tls-handshake-lane", {
      title: "<b>Handshake</b> · type + 24-bit length", badge: "RFC 8446 §4",
      fields: [
        { id: "hs-type", name: "msg_type", bytes: 1, range: "0–255", desc: "Handshake message type: ClientHello (1), ServerHello (2), EncryptedExtensions (8), Certificate (11), CertificateVerify (15), Finished (20), KeyUpdate (24).", rfc: "RFC 8446 §4", rfcUrl: RFC.tls13, tone: "a" },
        { id: "hs-length", name: "length", bytes: 3, range: "0–16777215", desc: "Length of the handshake body, excluding this four-byte header. It is a 24-bit value, so one handshake message can span multiple records.", rfc: "RFC 8446 §4", rfcUrl: RFC.tls13, tone: "b" },
        { id: "hs-body", name: "body", bytes: "var", variable: true, range: "length bytes", desc: "Message-specific body. TLS 1.3 encrypts the body for every handshake message after ServerHello.", rfc: "RFC 8446 §4", rfcUrl: RFC.tls13, tone: "c" }
      ],
      inspector: "#tls-handshake-inspector",
      note: "Handshake messages are a byte stream, not a record-aligned unit. Buffer across records before parsing the next message."
    });

    lanes.clienthello = PH.byteLane("#tls-clienthello-lane", {
      title: "<b>ClientHello</b> · what the client offers", badge: "RFC 8446 §4.1.2",
      fields: [
        { id: "ch-version", name: "legacy_version", bytes: 2, range: "0x0303", desc: "TLS 1.2 compatibility value. The real supported versions are listed in the supported_versions extension.", rfc: "RFC 8446 §4.1.2", rfcUrl: RFC.tls13, tone: "a" },
        { id: "ch-random", name: "random", bytes: 32, range: "32 bytes", desc: "Client random. It is mixed into the key schedule and must not repeat across handshakes. Unlike the ServerHello random, it does not carry a downgrade sentinel.", rfc: "RFC 8446 §4.1.2", rfcUrl: RFC.tls13, tone: "b" },
        { id: "ch-session", name: "legacy_session_id", bytes: "var", variable: true, range: "0–32 B", desc: "Compatibility session ID. Middlebox compatibility mode uses a non-empty value; TLS 1.3 resumption uses the pre_shared_key extension instead.", rfc: "RFC 8446 §4.1.2", rfcUrl: RFC.tls13, tone: "c" },
        { id: "ch-suites", name: "cipher_suites", bytes: "var", variable: true, range: "2 + 2n B", desc: "Ordered list of cipher suites the client supports. TLS 1.3 suites are AEAD-only and named TLS_*; the first mutually acceptable suite is not automatically chosen by the server.", rfc: "RFC 8446 §4.1.2", rfcUrl: RFC.tls13, tone: "d" },
        { id: "ch-compression", name: "legacy_compression_methods", bytes: "var", variable: true, range: "1 + n B", desc: "Must contain the null compression method 0. TLS 1.3 removed compression because of CRIME-style attacks.", rfc: "RFC 8446 §4.1.2", rfcUrl: RFC.tls13, tone: "e" },
        { id: "ch-ext", name: "extensions", bytes: "var", variable: true, range: "2 + n B", desc: "SNI, supported_groups, signature_algorithms, ALPN, supported_versions, psk_key_exchange_modes, key_share and others. This is where the real negotiation lives.", rfc: "RFC 8446 §4.2", rfcUrl: RFC.tls13, tone: "f" }
      ],
      inspector: "#tls-clienthello-inspector",
      note: "ClientHello is the largest plaintext structure in a TLS 1.3 handshake. It is also the one middleboxes inspect most."
    });

    lanes.serverhello = PH.byteLane("#tls-serverhello-lane", {
      title: "<b>ServerHello</b> · what the server selected", badge: "RFC 8446 §4.1.3",
      fields: [
        { id: "sh-version", name: "legacy_version", bytes: 2, range: "0x0303", desc: "TLS 1.2 compatibility value. The selected version is in the supported_versions extension.", rfc: "RFC 8446 §4.1.3", rfcUrl: RFC.tls13, tone: "a" },
        { id: "sh-random", name: "random", bytes: 32, range: "32 bytes", desc: "Server random. Mixed into the key schedule; the last 8 bytes can carry the TLS 1.3 downgrade sentinel when a server negotiates an older version.", rfc: "RFC 8446 §4.1.3", rfcUrl: RFC.tls13, tone: "b" },
        { id: "sh-session", name: "legacy_session_id_echo", bytes: "var", variable: true, range: "0–32 B", desc: "Echo of the ClientHello session ID. It must match the client value byte for byte.", rfc: "RFC 8446 §4.1.3", rfcUrl: RFC.tls13, tone: "c" },
        { id: "sh-suite", name: "cipher_suite", bytes: 2, range: "0x1301–0x1305", desc: "The single cipher suite selected from the client's list. TLS 1.3 suites combine AEAD and hash; key exchange is separate.", rfc: "RFC 8446 §4.1.3", rfcUrl: RFC.tls13, tone: "d" },
        { id: "sh-compression", name: "legacy_compression_method", bytes: 1, range: "0", desc: "Must be 0 (null). TLS 1.3 has no compression methods.", rfc: "RFC 8446 §4.1.3", rfcUrl: RFC.tls13, tone: "e" },
        { id: "sh-ext", name: "extensions", bytes: "var", variable: true, range: "2 + n B", desc: "supported_versions, key_share and optionally pre_shared_key. ALPN is normally confirmed later in EncryptedExtensions.", rfc: "RFC 8446 §4.2", rfcUrl: RFC.tls13, tone: "f" }
      ],
      inspector: "#tls-serverhello-inspector",
      note: "ServerHello is the last plaintext handshake message. Everything after it is protected with handshake traffic keys."
    });

    lanes.extension = PH.byteLane("#tls-extension-lane", {
      title: "<b>Extension</b> · type + length + data", badge: "RFC 8446 §4.2",
      compact: true,
      fields: [
        { id: "ext-type", name: "extension_type", bytes: 2, range: "0–65535", desc: "Extension identifier: server_name (0), supported_groups (10), signature_algorithms (13), ALPN (16), supported_versions (43), key_share (51).", rfc: "RFC 8446 §4.2", rfcUrl: RFC.tls13, tone: "a" },
        { id: "ext-length", name: "extension_data length", bytes: 2, range: "0–65535", desc: "Length of the extension body. The body's shape depends on both the extension type and the message carrying it.", rfc: "RFC 8446 §4.2", rfcUrl: RFC.tls13, tone: "b" },
        { id: "ext-data", name: "extension_data", bytes: "var", variable: true, range: "length bytes", desc: "Opaque to the record layer. A ClientHello key_share is a list of shares; a ServerHello key_share is one group plus one key.", rfc: "RFC 8446 §4.2", rfcUrl: RFC.tls13, tone: "c" }
      ],
      inspector: "#tls-extension-inspector",
      note: "Extensions are repeated in every message that needs them. The same type can have a different internal layout in ClientHello, ServerHello and Certificate."
    });

    lanes.alert = PH.byteLane("#tls-alert-lane", {
      title: "<b>Alert</b> · level + description", badge: "RFC 8446 §6",
      compact: true,
      fields: [
        { id: "alert-level", name: "AlertLevel", bytes: 1, range: "1 warning · 2 fatal", desc: "In TLS 1.3 almost every alert is fatal. A warning-level close_notify is still meaningful for clean shutdown.", rfc: "RFC 8446 §6", rfcUrl: RFC.tls13, tone: "a" },
        { id: "alert-desc", name: "AlertDescription", bytes: 1, range: "0–255", desc: "What went wrong: handshake_failure (40), bad_certificate (42), decode_error (50), protocol_version (70), unrecognized_name (112).", rfc: "RFC 8446 §6", rfcUrl: RFC.tls13, tone: "b" }
      ],
      inspector: "#tls-alert-inspector",
      note: "An alert is a record fragment, not a handshake message. It has no four-byte handshake header."
    });
  }

  function updateLanes(result) {
    if (!result) return;
    const record = result.records && result.records[0];
    if (record && lanes.record) {
      lanes.record.setValues({
        "rec-type": record.typeName,
        "rec-version": record.legacyVersion,
        "rec-length": record.length + " B",
        "rec-fragment": record.fragment.length + " B"
      });
    }
    const hello = (result.handshakes || []).find((message) => message.type === 1 || message.type === 2);
    if (hello && lanes.handshake) {
      lanes.handshake.setValues({
        "hs-type": hello.typeName,
        "hs-length": hello.length + " B",
        "hs-body": hello.length + " B"
      });
    }
    const client = (result.handshakes || []).find((message) => message.type === 1);
    if (client && lanes.clienthello) {
      lanes.clienthello.setValues({
        "ch-version": "0x" + PH.hex(client.legacyVersion, 4),
        "ch-random": client.random ? client.random.length + " B" : "32 B",
        "ch-session": client.sessionId ? client.sessionId.length + " B" : "—",
        "ch-suites": client.suites ? client.suites.length + " suites" : "—",
        "ch-compression": client.compression ? (client.compression.join(", ") || "none") : "—",
        "ch-ext": client.extensions ? client.extensions.length + " ext" : "—"
      });
    }
    const server = (result.handshakes || []).find((message) => message.type === 2);
    if (server && lanes.serverhello) {
      lanes.serverhello.setValues({
        "sh-version": "0x" + PH.hex(server.legacyVersion, 4),
        "sh-random": server.random ? server.random.length + " B" : "32 B",
        "sh-session": server.sessionId ? server.sessionId.length + " B" : "—",
        "sh-suite": server.cipherSuite != null ? T.cipherName(server.cipherSuite) : "—",
        "sh-compression": server.compression != null ? String(server.compression) : "—",
        "sh-ext": server.extensions ? server.extensions.length + " ext" : "—"
      });
    }
    const extension = hello && hello.extensions && hello.extensions[0];
    if (extension && lanes.extension) {
      lanes.extension.setValues({
        "ext-type": extension.name,
        "ext-length": extension.length + " B",
        "ext-data": extension.length + " B"
      });
    }
    if (result.alerts && result.alerts.length && lanes.alert) {
      lanes.alert.setValues({
        "alert-level": result.alerts[0].levelName,
        "alert-desc": result.alerts[0].descriptionName
      });
    }
  }

  /* ---------- encoder ---------- */

  function parseList(text) {
    return String(text == null ? "" : text).split(/[,\n]+/).map((value) => value.trim()).filter(Boolean);
  }

  function checkedValue(id, fallback) {
    const el = document.getElementById(id);
    return el ? el.value : fallback;
  }

  function readEncoder() {
    return {
      mode: checkedValue("tls-enc-mode", "clienthello"),
      recordVersion: PH.parseNumber(checkedValue("tls-enc-record-version", "0x0301")),
      random: checkedValue("tls-enc-random", "").trim(),
      session: checkedValue("tls-enc-session", "").trim(),
      keyShareGroup: checkedValue("tls-enc-keyshare-group", "x25519"),
      keyShare: checkedValue("tls-enc-keyshare", "").trim(),
      sni: checkedValue("tls-enc-sni", "").trim(),
      alpn: checkedValue("tls-enc-alpn", "").trim(),
      versions: checkedValue("tls-enc-versions", "").trim(),
      suites: checkedValue("tls-enc-suites", "").trim(),
      groups: checkedValue("tls-enc-groups", "").trim(),
      sigalgs: checkedValue("tls-enc-sigalgs", "").trim(),
      serverSuite: checkedValue("tls-enc-server-suite", "TLS_AES_128_GCM_SHA256"),
      serverVersion: checkedValue("tls-enc-server-version", "0x0304").trim(),
      alertLevel: Number(checkedValue("tls-enc-alert-level", "2")),
      alertDescription: Number(checkedValue("tls-enc-alert-desc", "40")),
      appDataMode: checkedValue("tls-enc-appdata-mode", "ascii"),
      appData: checkedValue("tls-enc-appdata", "")
    };
  }

  function buildFromForm(showErrors) {
    const status = document.getElementById("tls-enc-status");
    const tag = document.getElementById("tls-enc-tag");
    try {
      const input = readEncoder();
      let built;
      if (input.mode === "clienthello") {
        built = T.buildClientHello({
          recordVersion: input.recordVersion,
          random: input.random || undefined,
          sessionId: input.session || undefined,
          sni: input.sni,
          alpn: parseList(input.alpn),
          cipherSuites: parseList(input.suites),
          supportedVersions: parseList(input.versions),
          groups: parseList(input.groups),
          signatureAlgorithms: parseList(input.sigalgs),
          keyShareGroup: input.keyShareGroup,
          keyShare: input.keyShare || undefined
        });
      } else if (input.mode === "serverhello") {
        built = T.buildServerHello({
          recordVersion: input.recordVersion,
          random: input.random || undefined,
          sessionId: input.session || undefined,
          cipherSuite: input.serverSuite,
          supportedVersion: input.serverVersion,
          keyShareGroup: input.keyShareGroup,
          keyShare: input.keyShare || undefined
        });
      } else if (input.mode === "alert") {
        built = { bytes: T.buildAlert(input.alertLevel, input.alertDescription, input.recordVersion), length: 7 };
      } else {
        const data = input.appDataMode === "hex"
          ? (input.appData.trim() ? PH.parseHex(input.appData) : new Uint8Array(0))
          : T.asciiBytes(input.appData);
        built = { bytes: T.buildApplicationData(data, input.recordVersion), length: data.length + 5 };
      }
      const decoded = T.decodeTls(built.bytes);
      lastBuild = { input, built, decoded };
      updateEncoder(input, built, decoded);
      return lastBuild;
    } catch (err) {
      tag.textContent = "error";
      PH.setStatus(status, "error: " + err.message, "bad");
      return null;
    }
  }

  function updateEncoder(input, built, decoded) {
    document.getElementById("tls-enc-output").textContent = PH.bytesToHex(built.bytes);
    document.getElementById("tls-enc-output").classList.remove("placeholder");
    document.getElementById("tls-enc-tag").textContent = built.bytes.length + " B";
    const handshake = decoded.handshakes && decoded.handshakes[0];
    const extensionCount = handshake && handshake.extensions ? handshake.extensions.length : 0;
    document.getElementById("tls-enc-length").textContent = decoded.records.length + " record(s)";
    document.getElementById("tls-enc-handshake").textContent = handshake ? handshake.typeName : (decoded.alerts.length ? "Alert" : "—");
    document.getElementById("tls-enc-extensions").textContent = String(extensionCount);
    const pills = [
      `<span class="pill">${PH.esc(input.mode)}</span>`,
      `<span class="pill">${decoded.records.length} record(s)</span>`,
      `<span class="pill">${built.bytes.length} B</span>`
    ];
    if (decoded.context && decoded.context.negotiatedVersion) pills.push(`<span class="pill pill--good">${T.versionName(decoded.context.negotiatedVersion)}</span>`);
    else if (decoded.context && decoded.context.clientVersions && decoded.context.clientVersions.length) pills.push(`<span class="pill">${T.versionName(decoded.context.clientVersions[0])}</span>`);
    if (decoded.context && decoded.context.sni) pills.push(`<span class="pill">SNI ${PH.esc(decoded.context.sni)}</span>`);
    if (decoded.context && decoded.context.alpn) pills.push(`<span class="pill">ALPN ${PH.esc(decoded.context.alpn.join("/"))}</span>`);
    if (decoded.alerts.length) pills.push(`<span class="pill pill--bad">${PH.esc(decoded.alerts[0].summary)}</span>`);
    if (decoded.warnings.length) pills.push(`<span class="pill pill--warn">${decoded.warnings.length} note(s)</span>`);
    document.getElementById("tls-enc-summary").innerHTML = pills.join("");
    updateLanes(decoded);
    PH.setStatus(document.getElementById("tls-enc-status"),
      `${decoded.summary} · ${built.bytes.length} B${decoded.warnings.length ? " · " + decoded.warnings.length + " note(s)" : ""}`,
      decoded.warnings.length ? "warn" : "ok");
  }

  function syncMode() {
    const mode = checkedValue("tls-enc-mode", "clienthello");
    document.querySelectorAll("[data-tls-group]").forEach((el) => {
      el.hidden = !el.getAttribute("data-tls-group").split(" ").includes(mode);
    });
    const version = document.getElementById("tls-enc-record-version");
    if (mode === "clienthello" && version.value === "0x0303") version.value = "0x0301";
    if (mode !== "clienthello" && version.value === "0x0301") version.value = "0x0303";
  }

  function applyPreset(key) {
    const mode = document.getElementById("tls-enc-mode");
    if (key === "serverhello") {
      try {
        const client = T.buildClientHello({
          sni: checkedValue("tls-enc-sni", "example.com"),
          alpn: parseList(checkedValue("tls-enc-alpn", "h2, http/1.1")),
          cipherSuites: parseList(checkedValue("tls-enc-suites", "TLS_AES_128_GCM_SHA256"))
        });
        document.getElementById("tls-enc-session").value = PH.bytesToHex(client.sessionId);
      } catch (_) {
        document.getElementById("tls-enc-session").value = "";
      }
    }
    mode.value = key;
    syncMode();
    if (key === "clienthello") document.getElementById("tls-enc-record-version").value = "0x0301";
    if (key === "serverhello" || key === "alert" || key === "appdata") document.getElementById("tls-enc-record-version").value = "0x0303";
    buildFromForm(true);
  }

  function encoderState() {
    return { page: "tls-enc", values: PH.captureFormState() };
  }

  function applyEncoderState(state) {
    if (!state || !state.values) return false;
    PH.applyFormState(state.values);
    syncMode();
    return true;
  }

  function initEncoder() {
    const build = document.getElementById("tls-enc-build");
    if (!build) return;
    document.getElementById("tls-enc-mode").addEventListener("change", () => {
      syncMode();
      buildFromForm(false);
    });
    ["tls-enc-record-version", "tls-enc-random", "tls-enc-session", "tls-enc-keyshare",
      "tls-enc-sni", "tls-enc-alpn", "tls-enc-versions", "tls-enc-suites", "tls-enc-groups",
      "tls-enc-sigalgs", "tls-enc-appdata"].forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.addEventListener("input", () => buildFromForm(false));
    });
    ["tls-enc-keyshare-group", "tls-enc-server-suite", "tls-enc-server-version",
      "tls-enc-alert-level", "tls-enc-alert-desc", "tls-enc-appdata-mode"].forEach((id) => {
      const el = document.getElementById(id);
      if (el) el.addEventListener("change", () => buildFromForm(false));
    });
    build.addEventListener("click", () => buildFromForm(true));
    document.getElementById("tls-enc-example").addEventListener("click", () => applyPreset("clienthello"));
    document.querySelectorAll("[data-tls-preset]").forEach((button) => {
      button.addEventListener("click", () => applyPreset(button.getAttribute("data-tls-preset")));
    });
    document.getElementById("tls-enc-permalink").addEventListener("click", () => {
      if (lastBuild || buildFromForm(true)) PH.shareState(encoderState(), "TLS encoder permalink copied");
    });
    document.getElementById("tls-enc-export").addEventListener("click", () => {
      const current = lastBuild || buildFromForm(true);
      if (!current) return;
      PH.downloadText("tls-message.json", JSON.stringify({
        hex: PH.bytesToHex(current.built.bytes),
        bytes: current.built.bytes.length,
        mode: current.input.mode,
        decoded: sanitize(current.decoded)
      }, null, 2), "application/json");
    });
    syncMode();
    buildFromForm(false);
  }

  /* decoder and rendering continue below */

  /* ---------- decoder ---------- */

  let lastBuild = null;
  let lastDecode = null;

  function decodeTcpPayload(bytes) {
    if (!window.TCPCodec) throw new Error("TCP codec is not loaded");
    const tcp = window.TCPCodec.decodeSegment(bytes, {});
    if (!tcp.payload.length) throw new Error("TCP segment has no payload");
    return {
      tlsBytes: tcp.payload,
      context: {
        transport: "TCP", srcPort: tcp.sport, dstPort: tcp.dport,
        checksumState: tcp.checksumStatus
      }
    };
  }

  function decodeIpv4(bytes) {
    if (!window.IPv4Codec || !window.TCPCodec) throw new Error("IPv4/TCP codecs are not loaded");
    const ip = window.IPv4Codec.decode(bytes);
    if (ip.protocol !== 6) {
      throw new Error("IPv4 Protocol is " + ip.protocol + " (" + ip.protocolLabel + "), not TCP (6)");
    }
    if (ip.fragmentOffset > 0) throw new Error("TCP is not present in a non-initial IPv4 fragment");
    const tcp = window.TCPCodec.decodeSegment(ip.payloadBytes, { src: ip.src, dst: ip.dst });
    return {
      tlsBytes: tcp.payload,
      context: {
        transport: "TCP", ip, src: ip.src, dst: ip.dst, ipVersion: 4,
        srcPort: tcp.sport, dstPort: tcp.dport, checksumState: tcp.checksumStatus
      }
    };
  }

  function decodeIpv6(bytes) {
    if (!window.IPv6Codec || !window.TCPCodec) throw new Error("IPv6/TCP codecs are not loaded");
    const packet = window.IPv6Codec.decodePacket(bytes);
    const terminal = packet.chain.terminal;
    if (terminal.nextHeader !== 6) {
      throw new Error("IPv6 terminal Next Header is " + terminal.nextHeader + " (" + terminal.name + "), not TCP (6)");
    }
    const fragment = packet.chain.headers.find((header) => header.type === 44);
    if (fragment && fragment.fragmentOffset > 0) {
      throw new Error("TCP is not present in a non-initial IPv6 fragment");
    }
    const tcp = window.TCPCodec.decodeSegment(terminal.bytes, {});
    return {
      tlsBytes: tcp.payload,
      context: {
        transport: "TCP", ipv6: packet, src: packet.ip.src, dst: packet.ip.dst, ipVersion: 6,
        srcPort: tcp.sport, dstPort: tcp.dport, checksumState: tcp.checksumStatus
      }
    };
  }

  function decodeEthernet(bytes) {
    if (!window.EthernetCodec) throw new Error("Ethernet codec is not loaded");
    const frame = window.EthernetCodec.decodeFrame(bytes, { fcs: "auto" });
    const end = frame.offset + frame.headerLen + frame.payload.length;
    const payload = bytes.subarray(frame.offset + frame.headerLen, end);
    let envelope;
    if (frame.etherType === 0x0800) envelope = decodeIpv4(payload);
    else if (frame.etherType === 0x86dd) envelope = decodeIpv6(payload);
    else throw new Error("Ethernet EtherType is 0x" + PH.hex(frame.etherType, 4) + " (" + frame.etherTypeName + "), not IPv4 or IPv6");
    envelope.context.ethernet = {
      srcMac: frame.srcMac, dstMac: frame.dstMac, vlanTags: frame.vlanTags,
      fcsPresent: frame.fcsPresent, fcsOk: frame.fcsOk
    };
    return envelope;
  }

  function decodeAuto(bytes) {
    if (bytes.length >= 5 && T.CONTENT_TYPES[bytes[0]] != null && bytes[1] === 3) {
      return { tlsBytes: bytes, context: { transport: "raw" }, direct: true };
    }
    if (bytes.length >= 4 && T.HANDSHAKE_TYPES[bytes[0]] != null && T.u24(bytes, 1) === bytes.length - 4) {
      return { tlsBytes: bytes, context: { transport: "raw" }, direct: true };
    }
    if ((bytes[0] >> 4) === 4) return decodeIpv4(bytes);
    if ((bytes[0] >> 4) === 6) return decodeIpv6(bytes);
    try { return decodeEthernet(bytes); } catch (_) { /* continue */ }
    try { return decodeTcpPayload(bytes); } catch (_) { /* continue */ }
    throw new Error("Could not find a TLS record stream in this input");
  }

  function decodeEnvelope(bytes, kind) {
    if (kind === "tls" || kind === "handshake") return { tlsBytes: bytes, context: { transport: "raw" } };
    if (kind === "tcp") return decodeTcpPayload(bytes);
    if (kind === "ipv4") return decodeIpv4(bytes);
    if (kind === "ipv6") return decodeIpv6(bytes);
    if (kind === "ethernet") return decodeEthernet(bytes);
    return decodeAuto(bytes);
  }

  function fieldsTable(fields) {
    if (!fields || !fields.length) return '<p class="dim">No field breakdown for this message.</p>';
    return '<div class="table-wrap"><table class="data-table"><thead><tr><th>Field</th><th>Value</th><th>Note</th></tr></thead><tbody>' +
      fields.map((field) => `<tr><td><b>${PH.esc(field.name)}</b></td><td><code>${PH.esc(field.value)}</code></td><td class="small">${PH.esc(field.note || "")}</td></tr>`).join("") +
      "</tbody></table></div>";
  }

  function extensionsBlock(extensions) {
    if (!extensions || !extensions.length) return "";
    const rows = extensions.map((ext) => {
      const detail = ext.fields && ext.fields.length
        ? '<details><summary>' + PH.esc(ext.summary) + "</summary>" +
          '<div class="table-wrap"><table class="data-table"><tbody>' +
          ext.fields.map((field) => `<tr><th>${PH.esc(field.name)}</th><td><code>${PH.esc(field.value)}</code></td><td class="small">${PH.esc(field.note || "")}</td></tr>`).join("") +
          "</tbody></table></div>" +
          (ext.data && ext.data.length ? `<div class="output" style="margin-top:6px"><div class="output__label">extension_data · ${ext.data.length} B</div><pre>${PH.esc(PH.bytesToHex(ext.data))}</pre></div>` : "") +
          "</details>"
        : PH.esc(ext.summary);
      return `<tr><td><b>${PH.esc(ext.name)}</b></td><td class="num">${ext.type}</td><td class="num">${ext.length}</td><td>${detail}</td></tr>`;
    }).join("");
    return '<div class="decoded-head"><h3>Extensions</h3><span class="dim">' + extensions.length + " extension(s)</span></div>" +
      '<div class="table-wrap"><table class="data-table"><thead><tr><th>Extension</th><th>Code</th><th>Length</th><th>Contents</th></tr></thead><tbody>' + rows + "</tbody></table></div>";
  }

  function certificatesBlock(message) {
    if (!message.certs || !message.certs.length) return "";
    const rows = message.certs.map((cert, index) => {
      const extensions = cert.extensions && cert.extensions.length
        ? '<details><summary>' + cert.extensions.length + " extension(s)</summary>" +
          '<div class="table-wrap"><table class="data-table"><tbody>' +
          cert.extensions.map((ext) => `<tr><th>${PH.esc(ext.name)}</th><td><code>${PH.esc(ext.summary)}</code></td></tr>`).join("") +
          "</tbody></table></div></details>"
        : "—";
      return `<tr><td>${index + 1}</td><td class="num">${cert.length}</td><td><code>${PH.esc(PH.bytesToHex(cert.der.subarray(0, Math.min(24, cert.der.length))))}${cert.der.length > 24 ? " …" : ""}</code></td><td>${extensions}</td></tr>`;
    }).join("");
    return '<div class="decoded-head"><h3>Certificate chain</h3><span class="dim">' + message.certs.length + " certificate(s)</span></div>" +
      '<div class="table-wrap"><table class="data-table"><thead><tr><th>#</th><th>DER length</th><th>First bytes</th><th>Extensions</th></tr></thead><tbody>' + rows + "</tbody></table></div>";
  }

  function handshakeCard(message) {
    const warnings = message.warnings && message.warnings.length
      ? '<div class="callout callout--warn" style="margin-top:10px"><div class="callout__title">message notes</div><ul class="dashed" style="margin:0">' +
        message.warnings.map((warning) => `<li>${PH.esc(warning)}</li>`).join("") + "</ul></div>"
      : "";
    const extensionBlock = message.extensions && message.extensions.length ? extensionsBlock(message.extensions) : "";
    const certBlock = message.certs && message.certs.length ? certificatesBlock(message) : "";
    return '<div class="tls-message"><div class="decoded-head"><h3>' + PH.esc(message.typeName) + '</h3><span class="dim">' +
      message.length + " B body · offset +" + message.offset + " · record " + (message.recordIndex + 1) + "</span></div>" +
      fieldsTable(message.fields) + extensionBlock + certBlock + warnings + "</div>";
  }

  function transportCallout(context) {
    if (!context || context.transport === "raw") {
      return '<div class="callout callout--warn"><div class="callout__title">raw TLS bytes</div><p>No IP or TCP wrapper was supplied. The records decode, but addresses, ports, TCP checksum and stream context cannot be verified from this input alone.</p></div>';
    }
    const parts = [];
    if (context.src && context.dst) parts.push(PH.esc(context.src) + " → " + PH.esc(context.dst));
    if (context.srcPort != null) parts.push("port " + context.srcPort + " → " + context.dstPort);
    parts.push(context.transport);
    if (context.checksumState) parts.push("checksum " + PH.esc(context.checksumState));
    if (context.ethernet) {
      parts.push("Ethernet " + PH.esc(context.ethernet.srcMac) + " → " + PH.esc(context.ethernet.dstMac) +
        (context.ethernet.vlanTags && context.ethernet.vlanTags.length ? " · " + context.ethernet.vlanTags.length + " VLAN tag(s)" : ""));
    }
    const links = [];
    if (context.ipVersion === 4) links.push('<a href="ipv4.html">IPv4 explorer</a>');
    if (context.ipVersion === 6) links.push('<a href="ipv6.html">IPv6 explorer</a>');
    if (context.transport === "TCP") links.push('<a href="tcp.html">TCP explorer</a>');
    return '<div class="callout"><div class="callout__title">transport context</div><p>' + parts.join(" · ") +
      (links.length ? ". " + links.join(" · ") : "") + ".</p></div>";
  }

  function renderDecoded(result, context, bytes) {
    const host = document.getElementById("tls-decode-result");
    const tlsContext = result.context || {};
    const versionCode = tlsContext.negotiatedVersion ||
      (tlsContext.clientVersions && tlsContext.clientVersions[0]) ||
      (result.records[0] && result.records[0].versionCode);
    const pills = [];
    if (versionCode) pills.push(`<span class="pill pill--good">${T.versionName(versionCode)}</span>`);
    pills.push(`<span class="pill">${result.records.length} record(s)</span>`);
    if (result.handshakes.length) pills.push(`<span class="pill">${result.handshakes.map((message) => message.typeName).join(" → ")}</span>`);
    if (tlsContext.sni) pills.push(`<span class="pill">SNI ${PH.esc(tlsContext.sni)}</span>`);
    if (tlsContext.alpn) pills.push(`<span class="pill">ALPN ${PH.esc(tlsContext.alpn.join("/"))}</span>`);
    if (result.alerts.length) pills.push(`<span class="pill pill--bad">${PH.esc(result.alerts[0].summary)}</span>`);
    if (result.warnings.length) pills.push(`<span class="pill pill--warn">${result.warnings.length} note(s)</span>`);

    const recordRows = result.records.map((record) => `<tr><td>${record.index + 1}</td><td><b>${PH.esc(record.typeName)}</b></td><td><code>${record.legacyVersion}</code></td><td class="num">${record.length}</td><td class="num">+${record.offset}</td><td>${record.truncated ? "truncated" : (record.type === 23 ? "opaque / AEAD" : "complete")}</td></tr>`).join("");
    const recordTable = result.records.length
      ? '<div class="decoded-head"><h3>Records</h3><span class="dim">' + result.length + " B parsed</span></div>" +
        '<div class="table-wrap"><table class="data-table"><thead><tr><th>#</th><th>Content type</th><th>Legacy version</th><th>Length</th><th>Offset</th><th>Status</th></tr></thead><tbody>' + recordRows + "</tbody></table></div>"
      : "";

    const alertRows = result.alerts.length
      ? '<div class="decoded-head"><h3>Alerts</h3><span class="dim">' + result.alerts.length + " alert(s)</span></div>" +
        '<div class="table-wrap"><table class="data-table"><thead><tr><th>Level</th><th>Description</th><th>Offset</th></tr></thead><tbody>' +
        result.alerts.map((alert) => `<tr><td>${PH.esc(alert.levelName)}</td><td><b>${PH.esc(alert.descriptionName)}</b> (${alert.description})</td><td class="num">+${alert.offset}</td></tr>`).join("") +
        "</tbody></table></div>"
      : "";

    const cipherRows = tlsContext.cipherSuites && tlsContext.cipherSuites.length
      ? '<div class="decoded-head"><h3>Offered cipher suites</h3><span class="dim">' + tlsContext.cipherSuites.length + " suite(s)</span></div>" +
        '<div class="table-wrap"><table class="data-table"><thead><tr><th>Code</th><th>Suite</th></tr></thead><tbody>' +
        tlsContext.cipherSuites.map((suite) => `<tr><td><code>0x${PH.hex(suite.code, 4)}</code></td><td>${PH.esc(suite.name)}</td></tr>`).join("") +
        "</tbody></table></div>"
      : "";

    const handshakeBlock = result.handshakes.length
      ? '<div class="decoded-head"><h3>Handshake messages</h3><span class="dim">' + result.handshakes.length + " message(s)</span></div>" +
        result.handshakes.map(handshakeCard).join("")
      : '<div class="callout"><div class="callout__title">no plaintext handshake</div><p>This capture contains records but no complete plaintext handshake message. In TLS 1.3, handshake messages after ServerHello are encrypted inside Application Data records.</p></div>';

    const encrypted = result.records.filter((record) => record.type === 23).length;
    const boundary = encrypted
      ? '<div class="callout callout--warn"><div class="callout__title">encrypted boundary</div><p>' + encrypted +
        " Application Data record(s) are AEAD-protected. Without the traffic keys, the only visible fields are the content type, legacy version, length and record timing. This decoder deliberately does not attempt decryption.</p></div>"
      : "";

    const warnings = result.warnings.length
      ? '<div class="callout callout--warn" style="margin-top:14px"><div class="callout__title">parser notes</div><ul class="dashed" style="margin:0">' +
        result.warnings.map((warning) => `<li>${PH.esc(warning)}</li>`).join("") + "</ul></div>"
      : '<div class="callout" style="margin-top:14px"><div class="callout__title">clean parse</div><p>Record lengths, handshake lengths and extension lengths all agree. A clean parse is not authentication; the certificate chain and Finished messages are what prove the peer.</p></div>';

    host.innerHTML = '<div class="decode-summary">' + pills.join("") + "</div>" +
      '<div class="hexdump-wrap"><div class="hexdump-head"><span>TLS bytes</span><span>' + bytes.length + " B · first record at +0</span></div>" +
      PH.hexdump(bytes, { highlight: [{ start: 0, end: Math.min(5, bytes.length) }] }) + "</div>" +
      recordTable + transportCallout(context) + handshakeBlock + cipherRows + alertRows + boundary + warnings;
  }

  function runDecode(showErrors) {
    const input = document.getElementById("tls-decode-input");
    const status = document.getElementById("tls-decode-status");
    const host = document.getElementById("tls-decode-result");
    let bytes;
    try {
      bytes = PH.parseHex(input.value);
    } catch (err) {
      if (showErrors !== false) PH.setStatus(status, "hex error: " + err.message, "bad");
      host.innerHTML = "";
      return null;
    }
    try {
      const envelope = decodeEnvelope(bytes, document.getElementById("tls-decode-kind").value);
      const result = T.decodeTls(envelope.tlsBytes);
      renderDecoded(result, envelope.context, envelope.tlsBytes);
      updateLanes(result);
      lastDecode = { result, envelope, hex: PH.bytesToHex(bytes) };
      PH.setStatus(status,
        result.summary + " · " + envelope.tlsBytes.length + " B" +
        (result.warnings.length ? " · " + result.warnings.length + " note(s)" : ""),
        result.warnings.length ? "warn" : "ok");
      return lastDecode;
    } catch (err) {
      host.innerHTML = "";
      lastDecode = null;
      if (showErrors !== false) PH.setStatus(status, "decode error: " + err.message, "bad");
      return null;
    }
  }

  function loadExample(key) {
    const example = T.examples()[key];
    if (!example) return;
    document.getElementById("tls-decode-input").value = PH.bytesToHex(example.bytes);
    document.getElementById("tls-decode-kind").value = "tls";
    runDecode(true);
  }

  function decoderState() {
    return {
      page: "tls-dec",
      kind: document.getElementById("tls-decode-kind").value,
      hex: document.getElementById("tls-decode-input").value
    };
  }

  function sanitize(value, depth) {
    const level = depth || 0;
    if (level > 8) return "…";
    if (value instanceof Uint8Array) return PH.bytesToHex(value);
    if (Array.isArray(value)) return value.map((item) => sanitize(item, level + 1));
    if (value && typeof value === "object") {
      const out = {};
      Object.keys(value).forEach((key) => {
        if (key === "body" || key === "bytes" || key === "fragment" || key === "payload" || key === "der") {
          if (value[key] instanceof Uint8Array) out[key + "Hex"] = PH.bytesToHex(value[key]);
          return;
        }
        out[key] = sanitize(value[key], level + 1);
      });
      return out;
    }
    return value;
  }

  function initDecoder() {
    const run = document.getElementById("tls-decode");
    if (!run) return;
    run.addEventListener("click", () => runDecode(true));
    document.getElementById("tls-decode-example").addEventListener("click", () => loadExample("clientHello"));
    document.getElementById("tls-decode-server").addEventListener("click", () => loadExample("serverHello"));
    document.getElementById("tls-decode-alert").addEventListener("click", () => loadExample("alert"));
    document.getElementById("tls-decode-app").addEventListener("click", () => loadExample("appData"));
    document.getElementById("tls-decode-clear").addEventListener("click", () => {
      document.getElementById("tls-decode-input").value = "";
      document.getElementById("tls-decode-result").innerHTML = "";
      lastDecode = null;
      PH.setStatus(document.getElementById("tls-decode-status"), "No TLS records decoded yet.", "");
    });
    document.getElementById("tls-decode-permalink").addEventListener("click", () => {
      if (lastDecode || runDecode(true)) PH.shareState(decoderState(), "TLS decoder permalink copied");
    });
    document.getElementById("tls-decode-export").addEventListener("click", () => {
      const current = lastDecode || runDecode(true);
      if (!current) return;
      PH.downloadText("tls-decoded.json", JSON.stringify({
        hex: current.hex,
        transport: sanitize(current.envelope.context),
        decoded: sanitize(current.result)
      }, null, 2), "application/json");
    });
    document.getElementById("tls-decode-input").addEventListener("keydown", (event) => {
      if ((event.metaKey || event.ctrlKey) && event.key === "Enter") runDecode(true);
    });
  }

  function restoreState() {
    const state = PH.readHashState();
    if (!state) return false;
    if (state.page === "tls-enc" && applyEncoderState(state)) {
      buildFromForm(true);
      return true;
    }
    if (state.page === "tls-dec") {
      document.getElementById("tls-decode-kind").value = state.kind || "auto";
      document.getElementById("tls-decode-input").value = state.hex || "";
      runDecode(true);
      return true;
    }
    return false;
  }

  function initSequence() {
    const flow = document.getElementById("tls-flow");
    if (!flow) return;

    const caption = document.getElementById("tls-flow-caption");
    const state = document.getElementById("tls-flow-state");
    const table = document.getElementById("tls-flow-table");
    const clientState = document.getElementById("tls-node-client-state");
    const serverState = document.getElementById("tls-node-server-state");
    const clientNode = flow.querySelector('[data-node="client"]');
    const serverNode = flow.querySelector('[data-node="server"]');
    const rows = Array.from(flow.querySelectorAll("[data-row]"));
    const tokens = Array.from(flow.querySelectorAll("[data-token]"));

    function applyStep(index) {
      const step = TLS_STEPS[index - 1];
      caption.innerHTML = step.caption;
      clientState.textContent = step.client;
      serverState.textContent = step.server;
      state.textContent = step.state;
      state.className = step.stateClass;
      table.innerHTML =
        `<tr><td>record</td><td>${step.record}</td></tr>` +
        `<tr><td>protection</td><td>${step.keys}</td></tr>` +
        `<tr><td>capture</td><td>${step.capture}</td></tr>`;
      flow.classList.toggle("is-encrypted", index >= 2);

      rows.forEach((row, i) => {
        const number = i + 1;
        row.classList.toggle("is-done", number < index);
        row.classList.toggle("is-active", number === index);
      });

      clientNode.classList.toggle("is-active", step.active.includes("client"));
      clientNode.classList.toggle("is-match", step.match.includes("client"));
      serverNode.classList.toggle("is-active", step.active.includes("server"));
      serverNode.classList.toggle("is-match", step.match.includes("server"));

      tokens.forEach((token, i) => {
        const number = i + 1;
        if (number <= index) {
          token.style.transform = `translate(${TLS_TOKEN_TARGET[number][0]}px, ${TLS_TOKEN_TARGET[number][1]}px)`;
          token.classList.add("is-visible");
        } else {
          token.classList.remove("is-visible");
          token.style.transform = `translate(${TLS_TOKEN_HOME[number][0]}px, ${TLS_TOKEN_HOME[number][1]}px)`;
        }
      });
    }

    PH.stepFlow({ root: flow, count: TLS_STEPS.length, onStep: applyStep });
  }

  function init() {
    if (!document.getElementById("tls-record-lane")) return;
    initDiagrams();
    initEncoder();
    initDecoder();
    initSequence();
    if (!restoreState()) buildFromForm(false);
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
