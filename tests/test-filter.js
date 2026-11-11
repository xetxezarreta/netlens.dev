"use strict";

const { createRuntime, run } = require("./harness");

const runtime = createRuntime();
runtime.load("filter.js");
const Filter = runtime.sandbox.PHFilter;

function evaluate(expression, index) {
  return Filter.evaluate(Filter.parse(expression), index);
}

const tcpIndex = {
  protos: ["ethernet", "ipv4", "tcp", "http"],
  frame: { number: 4, len: 120, time: 1.5 },
  eth: { src: "02:00:00:00:00:0a", dst: "02:00:00:00:00:01", type: 0x0800 },
  ipv4: { src: "192.0.2.10", dst: "198.51.100.20", proto: 6, ttl: 64, len: 120 },
  tcp: { sport: 50000, dport: 80, seq: 1001, ack: 5001, flags: 0x18, syn: false, ackFlag: true, fin: false, rst: false, psh: true, urg: false, ece: false, cwr: false, payloadLen: 42 },
  http: { kind: "h1", method: "GET", target: "/index.html", status: null, host: "example.com" }
};

const dnsIndex = {
  protos: ["ethernet", "ipv4", "udp", "dns"],
  frame: { number: 7, len: 75, time: 2 },
  ipv4: { src: "192.0.2.10", dst: "198.51.100.20", proto: 17, ttl: 64, len: 75 },
  udp: { sport: 53000, dport: 53, len: 55, payloadLen: 47 },
  dns: { id: 0x1234, qname: "example.com", response: false }
};

const v6Index = {
  protos: ["ethernet", "ipv6", "tcp"],
  frame: { number: 9, len: 90, time: 3 },
  ipv6: { src: "2001:db8::1", dst: "2001:db8::2", next: 6, hopLimit: 64, len: 90 },
  tcp: { sport: 443, dport: 50000, flags: 0x10, syn: false, ackFlag: true, payloadLen: 0 }
};

run("filter", (test, assert) => {
  test("bare protocols match presence", () => {
    assert.strictEqual(evaluate("tcp", tcpIndex), true);
    assert.strictEqual(evaluate("udp", tcpIndex), false);
    assert.strictEqual(evaluate("http", tcpIndex), true);
    assert.strictEqual(evaluate("ip", v6Index), false);
    assert.strictEqual(evaluate("ipv6", v6Index), true);
  });

  test("boolean and numeric fields", () => {
    assert.strictEqual(evaluate("tcp.flags.ack == 1", tcpIndex), true);
    assert.strictEqual(evaluate("tcp.flags.syn == 1", tcpIndex), false);
    assert.strictEqual(evaluate("tcp.port == 80", tcpIndex), true);
    assert.strictEqual(evaluate("tcp.port != 80", tcpIndex), false);
    assert.strictEqual(evaluate("frame.len > 100", tcpIndex), true);
    assert.strictEqual(evaluate("frame.number == 4", tcpIndex), true);
  });

  test("IPv4 and IPv6 CIDR", () => {
    assert.strictEqual(evaluate("ip.addr == 192.0.2.0/24", tcpIndex), true);
    assert.strictEqual(evaluate("ip.addr == 198.51.100.0/24", tcpIndex), true);
    assert.strictEqual(evaluate("ip.addr == 203.0.113.0/24", tcpIndex), false);
    assert.strictEqual(evaluate("net.addr == 2001:db8::/32", v6Index), true);
    assert.strictEqual(evaluate("net.addr == 2001:db9::/32", v6Index), false);
  });

  test("string fields and contains", () => {
    assert.strictEqual(evaluate("dns.qname == example.com", dnsIndex), true);
    assert.strictEqual(evaluate("dns.qname contains ample", dnsIndex), true);
    assert.strictEqual(evaluate("http.method == GET", tcpIndex), true);
    assert.strictEqual(evaluate("http.method contains ET", tcpIndex), true);
  });

  test("byte slices, frame contains and flow analysis fields", () => {
    const withBytes = Object.assign({}, tcpIndex, {
      frameBytes: Uint8Array.from([0x16, 0x03, 0x01, 0x00, 0x2f]),
      flowFields: { "tcp.analysis.retransmission": true, "flow.app": "tls" }
    });
    assert.strictEqual(evaluate("frame[0:2] == 16:03", withBytes), true);
    assert.strictEqual(evaluate('frame contains "16 03 01"', withBytes), true);
    assert.strictEqual(evaluate("tcp.analysis.retransmission == 1", withBytes), true);
    assert.strictEqual(evaluate("flow.app == tls", withBytes), true);
  });

  test("precedence and parentheses", () => {
    assert.strictEqual(evaluate("udp or tcp and frame.len > 100", tcpIndex), true);
    assert.strictEqual(evaluate("(udp or tcp) and frame.len > 100", tcpIndex), true);
    assert.strictEqual(evaluate("not arp", tcpIndex), true);
    assert.strictEqual(evaluate("not (tcp and http)", tcpIndex), false);
  });

  test("bare boolean field", () => {
    assert.strictEqual(evaluate("tcp.flags.ack", tcpIndex), true);
    assert.strictEqual(evaluate("tcp.flags.syn", tcpIndex), false);
  });

  test("unknown fields fail loudly", () => {
    assert.throws(() => Filter.parse("nosuchfield == 1"), /Unknown field/);
    assert.throws(() => Filter.parse("tcp.port"), /Expected an operator/);
    assert.throws(() => Filter.parse("tcp and"), /Expected a protocol or field|Expected an expression/);
  });

  test("IPv6 parsing", () => {
    assert.strictEqual(Filter.parseIPv6("2001:db8::1").length, 16);
    assert.strictEqual(Filter.parseIPv6("::1").length, 16);
    assert.strictEqual(Filter.parseIPv6("::ffff:192.0.2.1").length, 16);
    assert.strictEqual(Filter.parseIPv6("not-an-address"), null);
  });
});
