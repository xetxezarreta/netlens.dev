"use strict";

/* Manual acceptance benchmark: 100,000 indexed packets, compiled filter.
 * Run with: node tests/bench-filter.js
 * It prints the elapsed time rather than failing CI on a slow machine. */

const { createRuntime, loadCodecs } = require("./harness");

const runtime = createRuntime();
loadCodecs(runtime, ["core.js", "filter.js"]);
const Filter = runtime.sandbox.PHFilter;
const total = 100000;
const indexes = [];
for (let i = 0; i < total; i += 1) {
  indexes.push({
    protos: ["ethernet", "ipv4", "tcp", "http"],
    frame: { number: i + 1, len: 120, time: i / 1000 },
    frameBytes: new Uint8Array(64),
    ipv4: { src: "192.0.2.10", dst: "198.51.100.20", proto: 6, ttl: 64, len: 120 },
    tcp: { sport: 50000, dport: 80, seq: i, ack: 0, flags: 0x18, payloadLen: 10 },
    flowFields: { "http.request.method": "GET", "http.host": "example.com" }
  });
}

const expression = "tcp and tcp.port == 80 and http.request.method == GET";
const fn = Filter.compile(Filter.parse(expression));
for (let i = 0; i < total; i += 1) fn(indexes[i]);
const started = process.hrtime.bigint();
let matched = 0;
for (const index of indexes) if (fn(index)) matched += 1;
const milliseconds = Number(process.hrtime.bigint() - started) / 1e6;
console.log("filtered " + matched + " / " + total + " packets in " + milliseconds.toFixed(2) + " ms");
console.log(milliseconds < 100 ? "PASS under 100 ms" : "NOTE over 100 ms on this machine");
