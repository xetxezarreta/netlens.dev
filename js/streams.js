/* Best-effort TCP stream reassembly for the workbench.
 *
 * It groups one 5-tuple, orders payload by sequence number, drops exact
 * retransmissions and marks gaps. It is not a TCP state machine: out-of-order
 * segments are reordered, but missing bytes are shown as gaps rather than
 * invented.
 */
(function (global) {
  "use strict";

  function endpoint(index) {
    const net = index.ipv4 || index.ipv6;
    if (!net) return null;
    return { addr: net.src, port: index.tcp.sport };
  }

  function peer(index) {
    const net = index.ipv4 || index.ipv6;
    if (!net) return null;
    return { addr: net.dst, port: index.tcp.dport };
  }

  function keyFor(addr, port) { return addr + ":" + port; }

  function streamKey(index) {
    const a = endpoint(index);
    const b = peer(index);
    if (!a || !b) return null;
    return [keyFor(a.addr, a.port), keyFor(b.addr, b.port)].sort().join("|");
  }

  function payloadOf(frame, index) {
    if (!index.tcp || !index.tcp.payloadLen) return new Uint8Array(0);
    const start = Math.max(0, Math.min(index.tcp.payloadOffset || 0, frame.length));
    const end = Math.max(start, Math.min(start + index.tcp.payloadLen, frame.length));
    return frame.subarray(start, end);
  }

  function build(records, selected, getFrame, getIndex) {
    const selectedIndex = getIndex(selected);
    if (!selectedIndex || !selectedIndex.tcp) {
      return { error: "This packet does not carry TCP." };
    }
    const key = streamKey(selectedIndex);
    if (!key) return { error: "This packet has no IP addresses." };

    const members = [];
    records.forEach((record) => {
      const index = getIndex(record);
      if (!index || !index.tcp) return;
      if (streamKey(index) !== key) return;
      members.push({ record, index, frame: getFrame(record) });
    });
    if (!members.length) return { error: "No packets found for this stream." };

    // Identify the client if a SYN without ACK is present; otherwise keep the
    // direction of the packet the user selected.
    let client = null;
    members.forEach((member) => {
      if (member.index.tcp.syn && !member.index.tcp.ackFlag) client = endpoint(member.index);
    });
    const a = client || endpoint(selectedIndex);
    let b = peer(selectedIndex);
    if (client) {
      const match = members.find((member) => {
        const e = endpoint(member.index);
        return e && e.addr === client.addr && e.port === client.port;
      });
      if (match) b = peer(match.index);
    }
    if (!a || !b) return { error: "Could not determine both stream endpoints." };

    const directions = {
      aToB: { from: a, to: b, segments: [], bytes: 0, retransmits: 0, gaps: 0, gapBytes: 0 },
      bToA: { from: b, to: a, segments: [], bytes: 0, retransmits: 0, gaps: 0, gapBytes: 0 }
    };

    members.forEach((member) => {
      const tcp = member.index.tcp;
      if (!tcp.payloadLen) return;
      const source = endpoint(member.index);
      const direction = source && a && source.addr === a.addr && source.port === a.port ? directions.aToB : directions.bToA;
      const payload = payloadOf(member.frame, member.index);
      if (!payload.length) return;
      direction.segments.push({
        record: member.record,
        number: member.record.number,
        seq: (tcp.seq + (tcp.syn ? 1 : 0)) >>> 0,
        bytes: payload
      });
    });

    Object.keys(directions).forEach((name) => {
      const direction = directions[name];
      direction.segments.sort((left, right) => left.seq - right.seq || left.number - right.number);
      const chunks = [];
      let expected = null;
      direction.segments.forEach((segment) => {
        if (expected == null) expected = segment.seq;
        if (segment.seq > expected) {
          const gap = segment.seq - expected;
          chunks.push({ gap });
          direction.gaps += 1;
          direction.gapBytes += gap;
          expected = segment.seq;
        } else if (segment.seq < expected) {
          const skip = expected - segment.seq;
          if (skip >= segment.bytes.length) {
            direction.retransmits += 1;
            return;
          }
          segment = {
            record: segment.record,
            number: segment.number,
            seq: expected,
            bytes: segment.bytes.subarray(skip)
          };
          direction.retransmits += 1;
        }
        if (!segment.bytes.length) return;
        chunks.push({ bytes: segment.bytes, seq: segment.seq, number: segment.number });
        expected += segment.bytes.length;
        direction.bytes += segment.bytes.length;
      });
      direction.chunks = chunks;
    });

    const ports = [a.port, b.port];
    const app = ports.indexOf(80) !== -1 || ports.indexOf(8080) !== -1 || ports.indexOf(8000) !== -1
      ? "http"
      : ports.indexOf(53) !== -1
        ? "dns"
        : ports.indexOf(443) !== -1
          ? "tls"
          : ports.indexOf(179) !== -1
            ? "bgp"
            : "unknown";

    return {
      key,
      a,
      b,
      directions,
      app,
      packets: members.length,
      totalBytes: directions.aToB.bytes + directions.bToA.bytes,
      warnings: []
    };
  }

  function textAndHex(stream, directionName) {
    const direction = stream.directions[directionName];
    if (!direction) return { text: "", hex: "" };
    let text = "";
    let binary = [];
    direction.chunks.forEach((chunk) => {
      if (chunk.gap != null) {
        text += "\n[gap " + chunk.gap + " byte" + (chunk.gap === 1 ? "" : "s") + "]\n";
        return;
      }
      for (let i = 0; i < chunk.bytes.length; i += 1) binary.push(chunk.bytes[i]);
      text += decodeText(chunk.bytes);
    });
    return { text, hex: bytesToHex(Uint8Array.from(binary)) };
  }

  function decodeText(bytes) {
    if (!bytes || !bytes.length) return "";
    if (typeof TextDecoder !== "undefined") {
      try {
        return new TextDecoder("utf-8", { fatal: false }).decode(bytes);
      } catch (_) { /* fall through */ }
    }
    let out = "";
    for (let i = 0; i < bytes.length; i += 1) out += String.fromCharCode(bytes[i]);
    return out;
  }

  function bytesToHex(bytes) {
    let out = [];
    for (let i = 0; i < bytes.length; i += 1) {
      const value = bytes[i];
      out.push((value < 16 ? "0" : "") + value.toString(16));
    }
    return out.join(" ");
  }

  global.PHStreams = {
    build,
    streamKey,
    textAndHex
  };
})(typeof window !== "undefined" ? window : globalThis);
