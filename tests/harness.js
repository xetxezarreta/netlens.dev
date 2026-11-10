/* Minimal Node harness for the browser codecs.
 *
 * The published site has no package manager or build step. These tests run with
 * plain Node (`node tests/test-pcap.js`) and load the same files the browser
 * loads through a vm context with a tiny DOM stub.
 */
"use strict";

const fs = require("fs");
const path = require("path");
const vm = require("vm");

const ROOT = path.resolve(__dirname, "..");
const noop = () => {};

function makeDocument() {
  const element = () => ({
    style: {},
    classList: { add: noop, remove: noop, toggle: noop },
    setAttribute: noop,
    removeAttribute: noop,
    appendChild: noop,
    remove: noop,
    addEventListener: noop,
    focus: noop
  });
  return {
    readyState: "loading",
    addEventListener: noop,
    removeEventListener: noop,
    getElementById: () => null,
    querySelector: () => null,
    querySelectorAll: () => [],
    createElement: element,
    createTextNode: () => ({}),
    documentElement: { removeAttribute: noop, setAttribute: noop, getAttribute: () => null },
    body: { appendChild: noop, classList: { add: noop, remove: noop, toggle: noop } }
  };
}

function createRuntime() {
  const sandbox = {
    console,
    document: makeDocument(),
    Uint8Array,
    ArrayBuffer,
    DataView,
    TextEncoder,
    TextDecoder,
    Date,
    Math,
    Number,
    String,
    Boolean,
    parseInt,
    parseFloat,
    isFinite,
    isNaN,
    Array,
    Object,
    JSON,
    RegExp,
    Error,
    setTimeout,
    clearTimeout,
    navigator: { clipboard: null },
    location: { hash: "", pathname: "/", search: "", origin: "null", href: "file:///" },
    localStorage: { getItem: () => null, setItem: noop },
    history: { replaceState: noop },
    requestAnimationFrame: noop,
    cancelAnimationFrame: noop,
    CSS: { escape: (value) => value }
  };
  sandbox.window = sandbox;
  sandbox.globalThis = sandbox;
  sandbox.self = sandbox;
  vm.createContext(sandbox);

  function load(name) {
    const file = path.join(ROOT, "js", name);
    vm.runInContext(fs.readFileSync(file, "utf8"), sandbox, { filename: file });
  }

  return { sandbox, load };
}

function loadCodecs(runtime, names) {
  names.forEach((name) => runtime.load(name));
}

const DISSECT_SCRIPTS = [
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
  "pcap-codec.js"
];

function run(name, fn) {
  let passed = 0;
  const failures = [];
  const assert = require("assert");
  function test(label, body) {
    try {
      body();
      passed += 1;
      process.stdout.write("  ok   " + label + "\n");
    } catch (error) {
      failures.push({ label, error });
      process.stdout.write("  FAIL " + label + ": " + error.message + "\n");
    }
  }
  process.stdout.write("\n" + name + "\n");
  fn(test, assert);
  process.stdout.write("  " + passed + " passed, " + failures.length + " failed\n");
  if (failures.length) process.exitCode = 1;
}

module.exports = { createRuntime, loadCodecs, run, DISSECT_SCRIPTS, ROOT };
