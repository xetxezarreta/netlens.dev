/* Checksum and hash primitives used by the checksum lab and codec tests.
   All functions are pure and operate on Uint8Array values. */
(function (global) {
  "use strict";

  const PH = global.PH || (global.window && global.window.PH);

  function internetChecksum(bytes) {
    return PH.checksum16(bytes);
  }

  function checksumValid(bytes) {
    return PH.checksumValid(bytes);
  }

  function makeTable(poly) {
    const table = new Uint32Array(256);
    for (let n = 0; n < 256; n++) {
      let c = n;
      for (let k = 0; k < 8; k++) c = (c & 1) ? (poly ^ (c >>> 1)) : (c >>> 1);
      table[n] = c >>> 0;
    }
    return table;
  }

  const CRC32_TABLE = makeTable(0xedb88320);
  const CRC32C_TABLE = makeTable(0x82f63b78);

  function crc32(bytes) {
    let crc = 0xffffffff;
    for (let i = 0; i < bytes.length; i++) crc = (CRC32_TABLE[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8)) >>> 0;
    return (crc ^ 0xffffffff) >>> 0;
  }

  function crc32c(bytes) {
    let crc = 0xffffffff;
    for (let i = 0; i < bytes.length; i++) crc = (CRC32C_TABLE[(crc ^ bytes[i]) & 0xff] ^ (crc >>> 8)) >>> 0;
    return (crc ^ 0xffffffff) >>> 0;
  }

  function fnv1a32(bytes) {
    let hash = 0x811c9dc5;
    for (let i = 0; i < bytes.length; i++) {
      hash ^= bytes[i];
      hash = Math.imul(hash, 0x01000193) >>> 0;
    }
    return hash >>> 0;
  }

  function fnv1a64(bytes) {
    let hash = 0xcbf29ce484222325n;
    const prime = 0x100000001b3n;
    for (let i = 0; i < bytes.length; i++) {
      hash ^= BigInt(bytes[i]);
      hash = (hash * prime) & 0xffffffffffffffffn;
    }
    return hash;
  }

  function adler32(bytes) {
    let a = 1;
    let b = 0;
    for (let i = 0; i < bytes.length; i++) {
      a = (a + bytes[i]) % 65521;
      b = (b + a) % 65521;
    }
    return ((b << 16) | a) >>> 0;
  }

  function sum8(bytes) {
    let sum = 0;
    for (let i = 0; i < bytes.length; i++) sum = (sum + bytes[i]) & 0xff;
    return sum;
  }

  function xor8(bytes) {
    let value = 0;
    for (let i = 0; i < bytes.length; i++) value ^= bytes[i];
    return value & 0xff;
  }

  function lrc(bytes) {
    let sum = 0;
    for (let i = 0; i < bytes.length; i++) sum = (sum + bytes[i]) & 0xff;
    return (-sum) & 0xff;
  }

  function analyse(bytes) {
    return {
      length: bytes.length,
      internet: internetChecksum(bytes),
      crc32: crc32(bytes),
      crc32c: crc32c(bytes),
      fnv1a32: fnv1a32(bytes),
      fnv1a64: fnv1a64(bytes),
      adler32: adler32(bytes),
      sum8: sum8(bytes),
      xor8: xor8(bytes),
      lrc: lrc(bytes)
    };
  }

  function hex32(value) { return "0x" + (Number(value) >>> 0).toString(16).toUpperCase().padStart(8, "0"); }
  function hex16(value) { return "0x" + (Number(value) & 0xffff).toString(16).toUpperCase().padStart(4, "0"); }
  function hex64(value) { return "0x" + BigInt(value).toString(16).toUpperCase().padStart(16, "0"); }
  function hex8(value) { return "0x" + (Number(value) & 0xff).toString(16).toUpperCase().padStart(2, "0"); }

  global.ChecksumCodec = {
    internetChecksum, checksumValid, crc32, crc32c, fnv1a32, fnv1a64,
    adler32, sum8, xor8, lrc, analyse, hex8, hex16, hex32, hex64
  };
})(typeof window !== "undefined" ? window : globalThis);
