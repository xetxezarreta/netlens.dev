/* ARP (RFC 826) codec — shared by the ARP and Ethernet pages. */
(function (global) {
  "use strict";

  const PH = global.PH || (global.window && global.window.PH);

  const OPCODES = {
    1: "REQUEST",
    2: "REPLY",
    3: "RARP REQUEST",
    4: "RARP REPLY",
    5: "DRARP REQUEST",
    6: "DRARP REPLY",
    7: "DRARP ERROR",
    8: "InARP REQUEST",
    9: "InARP REPLY"
  };
  const HARDWARE = { 1: "Ethernet" };
  const PROTOCOLS = { 0x0800: "IPv4", 0x86dd: "IPv6" };

  function be16(n) { return new Uint8Array([(n >>> 8) & 255, n & 255]); }
  function concat(parts) {
    const arrays = parts.filter(Boolean);
    const out = new Uint8Array(arrays.reduce((n, a) => n + a.length, 0));
    let off = 0;
    for (const a of arrays) { out.set(a, off); off += a.length; }
    return out;
  }

  function buildArp(input) {
    const htype = Number(input.htype == null ? 1 : input.htype);
    const ptype = Number(input.ptype == null ? 0x0800 : input.ptype);
    const opcode = Number(input.opcode);
    if (!Number.isInteger(htype) || htype < 0 || htype > 65535) throw new Error("Hardware type must be 0–65535");
    if (!Number.isInteger(ptype) || ptype < 0 || ptype > 65535) throw new Error("Protocol type must be 0–65535");
    if (!Number.isInteger(opcode) || opcode < 0 || opcode > 65535) throw new Error("Opcode must be 0–65535");
    if (htype !== 1) throw new Error("This builder supports Ethernet hardware type 1 only");
    if (ptype !== 0x0800) throw new Error("This builder supports IPv4 protocol type 0x0800 only");
    const sha = global.EthernetCodec.parseMac(input.senderMac);
    const tha = global.EthernetCodec.parseMac(input.targetMac);
    const spa = PH.parseIPv4(input.senderIp);
    const tpa = PH.parseIPv4(input.targetIp);
    const bytes = concat([
      be16(htype), be16(ptype), new Uint8Array([6, 4]), be16(opcode),
      sha, spa, tha, tpa
    ]);
    return {
      bytes, htype, ptype, opcode, hlen: 6, plen: 4, sha, spa, tha, tpa, messageLength: bytes.length,
      opcodeName: OPCODES[opcode] || "opcode " + opcode
    };
  }

  function ipString(bytes) { return Array.from(bytes).join("."); }

  function decodeArp(bytes, opts) {
    const options = opts || {};
    if (bytes.length < 8) throw new Error("ARP needs at least 8 bytes");
    const htype = PH.u16be(bytes, 0);
    const ptype = PH.u16be(bytes, 2);
    const hlen = bytes[4];
    const plen = bytes[5];
    if (hlen === 0 || plen === 0) throw new Error(`ARP HLEN/PLEN are ${hlen}/${plen}; both must be nonzero`);
    if (hlen > 32 || plen > 32) throw new Error("ARP address fields are unreasonably large");
    const need = 8 + hlen * 2 + plen * 2;
    if (bytes.length < need) throw new Error(`ARP declares ${hlen}-byte hardware and ${plen}-byte protocol addresses; ${need} bytes needed, ${bytes.length} available`);
    const opcode = PH.u16be(bytes, 6);
    let off = 8;
    const sha = bytes.slice(off, off + hlen); off += hlen;
    const spa = bytes.slice(off, off + plen); off += plen;
    const tha = bytes.slice(off, off + hlen); off += hlen;
    const tpa = bytes.slice(off, off + plen); off += plen;
    const warnings = [];
    if (hlen !== 6 || plen !== 4) warnings.push(`Unusual address lengths: HLEN ${hlen}, PLEN ${plen}; this is not Ethernet/IPv4 ARP`);
    if (bytes.length > need) {
      const trailing = bytes.slice(need);
      const onlyZero = trailing.every((b) => b === 0);
      if (!onlyZero) warnings.push(`${trailing.length} non-zero trailing byte(s) after the ARP message`);
    }
    return {
      bytes, htype, ptype, hlen, plen, opcode, opcodeName: OPCODES[opcode] || "opcode " + opcode,
      sha, spa, tha, tpa,
      senderMac: hlen === 6 ? global.EthernetCodec.macString(sha) : PH.bytesToHex(sha),
      senderIp: plen === 4 ? ipString(spa) : PH.bytesToHex(spa),
      targetMac: hlen === 6 ? global.EthernetCodec.macString(tha) : PH.bytesToHex(tha),
      targetIp: plen === 4 ? ipString(tpa) : PH.bytesToHex(tpa),
      hardwareName: HARDWARE[htype] || "type " + htype,
      protocolName: PROTOCOLS[ptype] || "0x" + PH.hex(ptype, 4),
      messageLength: need, paddingLength: Math.max(0, bytes.length - need),
      warnings
    };
  }

  function buildEthernetWrapper(arpBytes, input) {
    return global.EthernetCodec.buildFrame({
      dst: input.dstMac,
      src: input.senderMac,
      etherType: 0x0806,
      payload: arpBytes,
      pad: input.pad !== false,
      fcs: input.fcs !== false,
      vlan: input.vlan || null
    });
  }

  global.ARPCodec = {
    OPCODES, HARDWARE, PROTOCOLS, buildArp, decodeArp, buildEthernetWrapper,
    etherType: 0x0806
  };
})(window);
