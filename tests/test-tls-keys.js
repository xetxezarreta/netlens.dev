"use strict";

const assert = require("assert");
const { createRuntime, loadCodecs } = require("./harness");

async function main() {
  const runtime = createRuntime();
  loadCodecs(runtime, ["core.js", "tls-codec.js", "tls-keys.js"]);
  const PH = runtime.sandbox.PH;
  const Keys = runtime.sandbox.PHTLSKeys;
  const subtle = require("crypto").webcrypto.subtle;

  const cipher = Keys.cipherInfo(0x1301);
  const secret = new Uint8Array(32).fill(7);
  const clientRandom = Uint8Array.from({ length: 32 }, (value, index) => index);
  const derived = await Keys.deriveKeys(secret, cipher);
  const inner = PH.concatBytes(new TextEncoder().encode("hello tls"), Uint8Array.from([23]));
  const aad = Keys.recordHeader({ length: inner.length + 16 });
  const key = await subtle.importKey("raw", derived.key, { name: "AES-GCM" }, false, ["encrypt"]);
  const ciphertext = new Uint8Array(await subtle.encrypt({
    name: "AES-GCM", iv: Keys.nonceFor(derived.iv, 0), additionalData: aad, tagLength: 128
  }, key, inner));

  const flow = {
    app: {
      kind: "tls",
      context: { clientRandom, cipherSuite: 0x1301 },
      decoded: {
        aToB: { records: [{ offset: 0, length: ciphertext.length, fragment: ciphertext }] },
        bToA: null
      }
    }
  };
  const keylog = Keys.parse("CLIENT_HANDSHAKE_TRAFFIC_SECRET " + Keys.bytesToHex(clientRandom) + " " + Keys.bytesToHex(secret));
  assert.strictEqual(keylog.count, 1);

  const result = await Keys.decryptFlow(flow, keylog);
  assert.ok(!result.error, result.error);
  assert.strictEqual(result.cipher.name, "TLS_AES_128_GCM_SHA256");
  assert.strictEqual(result.directions.aToB.application.length, 1);
  assert.strictEqual(Buffer.from(result.directions.aToB.application[0].data).toString("utf8"), "hello tls");
  assert.strictEqual(Keys.applicationBytes(result, "aToB").length, 9);

  const missing = await Keys.decryptFlow(flow, Keys.parse(""));
  assert.ok(missing.error);

  const unsupported = await Keys.decryptFlow({
    app: { kind: "tls", context: { clientRandom, cipherSuite: 0x1303 }, decoded: { aToB: { records: [] }, bToA: null } }
  }, keylog);
  assert.ok(/not supported/i.test(unsupported.error));

  process.stdout.write("  ok   TLS 1.3 key-log record decrypts\n");
  process.stdout.write("  ok   missing key-log entry is reported\n");
  process.stdout.write("  ok   unsupported cipher is reported\n");
}

main().catch((error) => {
  process.stdout.write("  FAIL " + error.message + "\n");
  process.exitCode = 1;
});
