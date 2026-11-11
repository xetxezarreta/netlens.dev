/* Optional capture parser worker.
 *
 * The static site must also work from file://, where workers are not always
 * available. The page probes this worker and falls back to the main-thread
 * indexer if construction or the first message fails.
 *
 * The DOM is stubbed with readyState "loading" so the page-wiring half of the
 * codec files never runs. Only the pure codecs, dissector, flow engine and
 * index builder are used here.
 */
"use strict";

self.window = self;
self.document = {
  readyState: "loading",
  addEventListener: function () {},
  removeEventListener: function () {},
  getElementById: function () { return null; },
  querySelector: function () { return null; },
  querySelectorAll: function () { return []; },
  createElement: function () {
    return {
      style: {}, classList: { add: function () {}, remove: function () {}, toggle: function () {} },
      setAttribute: function () {}, removeAttribute: function () {}, appendChild: function () {},
      addEventListener: function () {}, focus: function () {}
    };
  },
  createTextNode: function () { return {}; },
  documentElement: { removeAttribute: function () {}, setAttribute: function () {}, getAttribute: function () { return null; } },
  body: { appendChild: function () {}, classList: { add: function () {}, remove: function () {}, toggle: function () {} } }
};
try { self.localStorage = { getItem: function () { return null; }, setItem: function () {} }; } catch (_) {}
try { self.history = { replaceState: function () {} }; } catch (_) {}
self.requestAnimationFrame = function (fn) { return setTimeout(fn, 0); };
self.cancelAnimationFrame = function (id) { clearTimeout(id); };
self.matchMedia = function () { return { matches: false, addEventListener: function () {}, removeEventListener: function () {}, addListener: function () {}, removeListener: function () {} }; };
self.IntersectionObserver = function () { return { observe: function () {}, disconnect: function () {}, unobserve: function () {} }; };
try { self.CSS = { escape: function (value) { return value; } }; } catch (_) {}

importScripts(
  "core.js",
  "ethernet-codec.js",
  "arp-codec.js",
  "ipv4.js",
  "ipv6-codec.js",
  "tcp.js",
  "udp-codec.js",
  "icmp-codec.js",
  "dns-codec.js",
  "dhcp-codec.js",
  "tls-codec.js",
  "http-codec.js",
  "dissect-codec.js",
  "pcap-codec.js",
  "bgp.js",
  "flows.js",
  "index-builder.js"
);

function compactMessage(entry) {
  if (!entry || !entry.message) return entry;
  const message = entry.message;
  const copy = {};
  ["messageKind", "kind", "method", "target", "version", "status", "reason", "headers",
    "body", "bodyOffset", "bodyEnd", "framing", "contentLength", "chunked", "summary",
    "warnings", "header", "counts", "questions", "answers", "authority", "opcode", "opcodeName"
  ].forEach((key) => {
    if (message[key] !== undefined) copy[key] = message[key];
  });
  return {
    direction: entry.direction, ts: entry.ts, packets: entry.packets,
    offset: entry.offset, length: entry.length, message: copy
  };
}

function compactFlow(flow) {
  if (!flow) return null;
  const messages = flow.app && flow.app.messages ? flow.app.messages.map(compactMessage) : [];
  return {
    index: flow.index, key: flow.key, proto: flow.proto,
    a: flow.a, b: flow.b, client: flow.client,
    summary: flow.summary, app: flow.app ? {
      kind: flow.app.kind, summary: flow.app.summary,
      context: flow.app.context || null,
      messages: messages,
      requests: flow.app.requests ? flow.app.requests.length : 0,
      responses: flow.app.responses ? flow.app.responses.length : 0,
      decoded: flow.app.kind === "tls" ? {
        aToB: flow.app.decoded.aToB ? { records: flow.app.decoded.aToB.records } : null,
        bToA: flow.app.decoded.bToA ? { records: flow.app.decoded.bToA.records } : null
      } : undefined
    } : null,
    packetCount: flow.packetCount, bytes: flow.bytes,
    firstNumber: flow.firstNumber, lastNumber: flow.lastNumber,
    expert: flow.expert, diagnosis: flow.diagnosis, warnings: flow.warnings
  };
}

function compactInfo(info) {
  return {
    flow: compactFlow(info.flow),
    direction: info.direction,
    appKind: info.appKind,
    summary: info.summary,
    flowFields: info.flowFields,
    tcpAnalysis: info.tcpAnalysis,
    experts: info.experts,
    expert: info.expert,
    layers: info.layers,
    fragmentOf: info.fragmentOf,
    diagnosis: info.diagnosis
  };
}

self.onmessage = function (event) {
  const data = event.data || {};
  if (data.type !== "parse") return;
  try {
    const capture = PCapCodec.parse(data.buffer);
    const maxPackets = Number(data.maxPackets) || 250000;
    const records = capture.records.slice(0, maxPackets);
    const engine = PHFlows.create();
    const indexes = [];
    for (let i = 0; i < records.length; i += 1) {
      const record = records[i];
      const bytes = PCapCodec.recordBytes(capture, record);
      let result;
      try {
        result = Dissector.dissectLink(bytes, record.linkType, { headersOnly: true });
      } catch (err) {
        result = Dissector.dissect(bytes, { kind: "raw", note: "decode failed: " + err.message, headersOnly: true });
        result.warnings.push("Workbench decode failed: " + err.message);
      }
      const index = PHIndexBuilder.makeIndex(record, bytes, result);
      delete index.frameBytes;
      indexes.push(index);
      engine.add(record, result);
      if (i % 800 === 0 || i === records.length - 1) {
        self.postMessage({ type: "progress", done: i + 1, total: records.length });
      }
    }
    const flowData = engine.finish();
    const byNumber = [];
    flowData.byNumber.forEach((info, number) => {
      byNumber.push([number, compactInfo(info)]);
    });
    const flows = flowData.flows.map(compactFlow);
    const summary = PCapCodec.summary(capture);
    self.postMessage({
      type: "done",
      indexes: indexes,
      byNumber: byNumber,
      flows: flows,
      warnings: flowData.warnings,
      stats: flowData.stats,
      experts: flowData.experts,
      fieldCatalog: flowData.fieldCatalog,
      captureSummary: summary,
      interfaces: capture.interfaces,
      captureWarnings: capture.warnings,
      format: capture.format,
      truncated: capture.records.length > maxPackets,
      totalRecords: capture.records.length
    });
  } catch (err) {
    self.postMessage({ type: "error", message: err.message, stack: err.stack });
  }
};
