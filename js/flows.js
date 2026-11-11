/* Connection-aware packet analysis for the workbench.
 *
 * The dissector answers "what is in this frame?". This module answers "what is
 * this conversation doing?". It builds a 5-tuple flow table, reassembles IPv4
 * and IPv6 fragments, tracks TCP sequence state, rebuilds both byte streams and
 * feeds the application decoders with the reassembled bytes instead of a
 * single frame payload.
 *
 * Defensive by design: a broken flow or a hostile length becomes a warning on
 * the flow, never an exception that stops the capture walk.
 */
(function (global) {
  "use strict";

  const PH = global.PH;
  const MAX_FRAGMENT_BYTES = 1024 * 1024;
  const MAX_FRAGMENT_PARTS = 256;
  const FRAGMENT_TIMEOUT = 30;
  const MAX_FLOWS = 250000;
  const MAX_STREAM_BYTES = 32 * 1024 * 1024;
  const MAX_MESSAGES = 5000;

  function findLayer(layers, proto) {
    return (layers || []).find((layer) => layer.proto === proto) || null;
  }

  function endpoint(addr, port) {
    return { addr: String(addr == null ? "" : addr), port: Number(port) || 0 };
  }

  function endpointText(ep) {
    return ep ? ep.addr + (ep.port ? ":" + ep.port : "") : "—";
  }

  function sameEndpoint(addr, port, ep) {
    return Boolean(ep) && String(addr) === ep.addr && Number(port) === ep.port;
  }

  function canonicalKey(proto, version, a, b) {
    const left = version + "|" + a.addr + "|" + a.port;
    const right = version + "|" + b.addr + "|" + b.port;
    return proto + "|" + (left < right ? left + "|" + right : right + "|" + left);
  }

  function fragmentKey(version, src, dst, proto, id) {
    return version + "|" + src + "|" + dst + "|" + proto + "|" + id;
  }

  function unwrapSeq(seq, base) {
    const value = Number(seq) >>> 0;
    const origin = Number(base) >>> 0;
    return origin + ((value - origin) | 0);
  }

  function unique(values) {
    const out = [];
    const seen = new Set();
    values.forEach((value) => {
      if (value == null || seen.has(value)) return;
      seen.add(value);
      out.push(value);
    });
    return out;
  }

  function concat(parts) {
    return PH.concatBytes.apply(null, parts.filter((part) => part && part.length));
  }

  function firstNumber(numbers) {
    return numbers && numbers.length ? numbers[0] : null;
  }

  function packetFrom(record, result) {
    const layers = result && result.layers ? result.layers : [];
    const packet = {
      record, result, layers,
      ip: null, tcp: null, udp: null, icmp: null, icmpv6: null,
      fragmentPackets: null
    };
    const ipv4 = findLayer(layers, "ipv4");
    if (ipv4 && ipv4.meta && ipv4.meta.ip) {
      const ip = ipv4.meta.ip;
      packet.ip = {
        version: 4, src: ip.src, dst: ip.dst,
        proto: ip.protocol, protocolName: ip.protocolLabel,
        id: ip.id, fragmentOffset: ip.fragmentOffset || 0,
        mf: Boolean(ip.mf), headerLen: ip.headerLen,
        payload: ip.payloadBytes, payloadOffset: ipv4.offset + ip.headerLen,
        checksumStatus: ip.checksumOk ? "good" : "bad",
        warnings: ip.warnings ? ip.warnings.slice() : [],
        layer: ipv4
      };
    }
    const ipv6 = findLayer(layers, "ipv6");
    if (ipv6 && ipv6.meta && ipv6.meta.ip) {
      const ip = ipv6.meta.ip;
      const chain = ipv6.meta.chain;
      const fragment = chain.headers.find((header) => header.type === 44) || null;
      packet.ip = {
        version: 6, src: ip.src, dst: ip.dst,
        proto: fragment ? fragment.nextHeader : chain.terminal.nextHeader,
        protocolName: ip.nextHeaderName,
        id: fragment ? fragment.identification : null,
        fragmentOffset: fragment ? fragment.fragmentOffset : 0,
        mf: fragment ? Boolean(fragment.moreFragments) : false,
        headerLen: 40,
        payload: fragment ? chain.terminal.bytes : chain.terminal.bytes,
        payloadOffset: chain.terminal.offset,
        checksumStatus: "unverified",
        warnings: (ip.warnings || []).concat(chain.warnings || []),
        layer: ipv6, chain, fragment
      };
    }
    const tcp = findLayer(layers, "tcp");
    if (tcp && tcp.meta && tcp.meta.parsed) packet.tcp = tcp.meta.parsed;
    const udp = findLayer(layers, "udp");
    if (udp && udp.meta && udp.meta.parsed) packet.udp = udp.meta.parsed;
    const icmp = findLayer(layers, "icmp");
    if (icmp && icmp.meta && icmp.meta.parsed) packet.icmp = icmp.meta.parsed;
    const icmpv6 = findLayer(layers, "icmpv6");
    if (icmpv6) packet.icmpv6 = { type: icmpv6.offset != null && result.bytes ? result.bytes[icmpv6.offset] : 0, code: 0 };
    return packet;
  }

  function newDirection() {
    return {
      packets: [], segments: [], chunks: [], runs: [],
      assembled: new Uint8Array(0), bytes: 0,
      baseSeq: null, arrivalNext: null,
      retransmissions: 0, outOfOrder: 0, gaps: 0, gapBytes: 0,
      duplicateAcks: 0, zeroWindow: false, zeroWindowPackets: [],
      keepalives: 0, rst: false, fin: false, syn: false,
      mss: null, windowScale: null, sackPermitted: false, timestamps: false,
      firstTs: 0, lastTs: 0,
      rttSamples: [], rttLast: null, rttMin: null, rttMax: null, rttAvg: null
    };
  }

  function addExpert(flow, severity, message, packets) {
    flow.expert.push({ severity, message, packets: unique(packets || []) });
  }

  function severityRank(severity) {
    return severity === "bad" ? 2 : severity === "warn" ? 1 : 0;
  }

  function create() {
    const flows = new Map();
    const fragments = new Map();
    const warnings = [];
    const packetInfo = new Map();
    let flowCounter = 0;
    let packetCount = 0;

    function infoFor(record) {
      let info = packetInfo.get(record.number);
      if (!info) {
        info = {
          flow: null, direction: null, appKind: "", summary: "",
          flowFields: {}, tcpAnalysis: null, experts: [], expert: "",
          layers: [], fragmentOf: null, diagnosis: []
        };
        packetInfo.set(record.number, info);
      }
      return info;
    }

    function mergeFields(info, fields) {
      Object.keys(fields || {}).forEach((key) => {
        if (fields[key] == null || fields[key] === "") return;
        info.flowFields[key] = fields[key];
      });
    }

    function getFlow(key, proto, version, a, b) {
      let flow = flows.get(key);
      if (flow) return flow;
      if (flows.size >= MAX_FLOWS) {
        warnings.push("Flow table limit reached; later conversations are kept as packets without flow analysis");
        return null;
      }
      flow = {
        index: flowCounter++, key, proto, version,
        a, b, client: null, server: null,
        packets: [], members: [], dirs: { aToB: newDirection(), bToA: newDirection() },
        app: null, expert: [], warnings: [], diagnosis: [],
        firstTs: 0, lastTs: 0, bytes: 0, packetCount: 0,
        firstNumber: null, lastNumber: null, state: {}
      };
      flows.set(key, flow);
      return flow;
    }

    function addFragment(record, packet) {
      const ip = packet.ip;
      if (!ip || !ip.payload || !ip.payload.length) return null;
      const key = fragmentKey(ip.version, ip.src, ip.dst, ip.proto, ip.id);
      let entry = fragments.get(key);
      if (!entry) {
        entry = {
          key, version: ip.version, src: ip.src, dst: ip.dst, proto: ip.proto,
          id: ip.id, parts: [], total: null, firstTs: record.ts || 0,
          records: [], warnings: []
        };
        fragments.set(key, entry);
      }
      if (record.ts && entry.firstTs && record.ts - entry.firstTs > FRAGMENT_TIMEOUT) {
        entry.warnings.push("Fragment set exceeded the " + FRAGMENT_TIMEOUT + " s reassembly timeout; starting a new set");
        fragments.delete(key);
        entry = {
          key, version: ip.version, src: ip.src, dst: ip.dst, proto: ip.proto,
          id: ip.id, parts: [], total: null, firstTs: record.ts || 0,
          records: [], warnings: []
        };
        fragments.set(key, entry);
      }
      entry.records.push(record);
      entry.parts.push({
        offset: (ip.fragmentOffset || 0) * 8,
        bytes: ip.payload,
        more: ip.mf,
        record
      });
      if (!ip.mf) entry.total = (ip.fragmentOffset || 0) * 8 + ip.payload.length;
      if (entry.parts.length > MAX_FRAGMENT_PARTS) {
        entry.warnings.push("Fragment set exceeds " + MAX_FRAGMENT_PARTS + " pieces; dropping");
        fragments.delete(key);
        return null;
      }
      if (entry.total != null && entry.total > MAX_FRAGMENT_BYTES) {
        entry.warnings.push("Reassembled datagram would exceed " + MAX_FRAGMENT_BYTES + " bytes; dropping");
        fragments.delete(key);
        return null;
      }
      if (entry.total == null) return null;
      return completeFragment(entry);
    }

    function completeFragment(entry) {
      const parts = entry.parts.slice().sort((left, right) => left.offset - right.offset || left.record.number - right.record.number);
      const total = entry.total;
      const data = new Uint8Array(total);
      const covered = new Uint8Array(total);
      let overlaps = 0;
      parts.forEach((part) => {
        const start = Math.max(0, part.offset);
        const end = Math.min(total, start + part.bytes.length);
        for (let i = start; i < end; i += 1) {
          if (covered[i] && data[i] !== part.bytes[i - start]) overlaps += 1;
          if (!covered[i]) { data[i] = part.bytes[i - start]; covered[i] = 1; }
        }
      });
      let missing = 0;
      for (let i = 0; i < total; i += 1) if (!covered[i]) missing += 1;
      if (missing) {
        entry.warnings.push(missing + " byte(s) missing from the reassembled datagram");
        return null;
      }
      fragments.delete(entry.key);
      if (overlaps) entry.warnings.push(overlaps + " overlapping byte(s); first fragment wins");
      return {
        bytes: data, entry,
        records: entry.records.slice(),
        warnings: entry.warnings.slice()
      };
    }

    function transportForReassembled(packet, assembled) {
      const ip = packet.ip;
      const context = ip.version === 4 ? { src: ip.src, dst: ip.dst } : {};
      try {
        if (ip.proto === 6) {
          return { tcp: global.TCPCodec.decodeSegment(assembled, context) };
        }
        if (ip.proto === 17) {
          return { udp: global.UDPCodec.decodeUdp(assembled, {
            ipVersion: ip.version, srcIp: ip.src, dstIp: ip.dst
          }) };
        }
        if (ip.proto === 1 && global.ICMPCodec) return { icmp: global.ICMPCodec.decodeIcmp(assembled) };
      } catch (err) {
        return { error: err.message };
      }
      return {};
    }

    function processPacket(record, packet) {
      const ip = packet.ip;
      if (!ip) return;
      let transport = null;
      let fragmentPackets = null;
      if (ip.version === 4 && (ip.fragmentOffset > 0 || ip.mf)) {
        const assembled = addFragment(record, packet);
        if (!assembled) return;
        transport = transportForReassembled(packet, assembled.bytes);
        fragmentPackets = assembled.records;
        if (assembled.warnings.length) warnings.push.apply(warnings, assembled.warnings);
        if (transport.error) {
          warnings.push("Reassembled packet " + record.number + ": " + transport.error);
          return;
        }
      } else if (ip.version === 6 && packet.fragment && (packet.fragment.fragmentOffset > 0 || packet.fragment.moreFragments)) {
        const assembled = addFragment(record, packet);
        if (!assembled) return;
        transport = transportForReassembled(packet, assembled.bytes);
        fragmentPackets = assembled.records;
        if (assembled.warnings.length) warnings.push.apply(warnings, assembled.warnings);
        if (transport.error) {
          warnings.push("Reassembled packet " + record.number + ": " + transport.error);
          return;
        }
      } else {
        transport = { tcp: packet.tcp, udp: packet.udp, icmp: packet.icmp };
      }
      if (!transport) return;
      if (transport.tcp) addTcp(record, packet, transport.tcp, fragmentPackets);
      else if (transport.udp) addUdp(record, packet, transport.udp, fragmentPackets);
      else if (transport.icmp) addIcmp(record, packet, transport.icmp);
    }

    function addTcp(record, packet, tcp, fragmentPackets) {
      const ip = packet.ip;
      const a = endpoint(ip.src, tcp.sport);
      const b = endpoint(ip.dst, tcp.dport);
      const flow = getFlow(canonicalKey("tcp", ip.version, a, b), "tcp", ip.version, a, b);
      if (!flow) return;
      flow.packets.push({ packet, tcp, record });
      flow.members.push(record);
      (fragmentPackets || []).forEach((fragment) => {
        if (flow.members.indexOf(fragment) === -1) flow.members.push(fragment);
        infoFor(fragment).fragmentOf = record.number;
        infoFor(fragment).flow = flow;
      });
      infoFor(record).flow = flow;
    }

    function addUdp(record, packet, udp, fragmentPackets) {
      const ip = packet.ip;
      const a = endpoint(ip.src, udp.srcPort);
      const b = endpoint(ip.dst, udp.dstPort);
      const flow = getFlow(canonicalKey("udp", ip.version, a, b), "udp", ip.version, a, b);
      if (!flow) return;
      flow.packets.push({ packet, udp, record });
      flow.members.push(record);
      (fragmentPackets || []).forEach((fragment) => {
        if (flow.members.indexOf(fragment) === -1) flow.members.push(fragment);
        infoFor(fragment).fragmentOf = record.number;
        infoFor(fragment).flow = flow;
      });
      infoFor(record).flow = flow;
    }

    function addIcmp(record, packet, icmp) {
      const ip = packet.ip;
      const a = endpoint(ip.src, 0);
      const b = endpoint(ip.dst, 0);
      const flow = getFlow(canonicalKey("icmp", ip.version, a, b), "icmp", ip.version, a, b);
      if (!flow) return;
      flow.packets.push({ packet, icmp, record });
      flow.members.push(record);
      infoFor(record).flow = flow;
    }

    function add(record, result) {
      packetCount += 1;
      const packet = packetFrom(record, result);
      try {
        processPacket(record, packet);
      } catch (err) {
        warnings.push("Packet " + record.number + " flow analysis failed: " + err.message);
      }
    }

    /* ---------- TCP state and stream reassembly ---------- */

    function findClient(flow) {
      let client = null;
      flow.packets.forEach((entry) => {
        if (client) return;
        const tcp = entry.tcp;
        if ((tcp.flags & 0x02) && !(tcp.flags & 0x10)) client = endpoint(entry.packet.ip.src, tcp.sport);
      });
      if (!client && flow.packets.length) {
        const first = flow.packets[0];
        const a = endpoint(first.packet.ip.src, first.tcp.sport);
        const b = endpoint(first.packet.ip.dst, first.tcp.dport);
        const wellKnown = [20, 21, 22, 25, 53, 80, 110, 143, 179, 443, 465, 587, 853, 993, 995, 3306, 5432, 6379, 8080, 8443];
        if (wellKnown.indexOf(b.port) !== -1 && wellKnown.indexOf(a.port) === -1) client = a;
        else if (wellKnown.indexOf(a.port) !== -1 && wellKnown.indexOf(b.port) === -1) client = b;
        else client = a;
      }
      return client;
    }

    function otherEndpoint(flow, ep) {
      if (sameEndpoint(ep.addr, ep.port, flow.a)) return flow.b;
      return flow.a;
    }

    function finalizeTcp(flow) {
      const client = findClient(flow);
      if (client) {
        const server = sameEndpoint(client.addr, client.port, flow.a) ? flow.b : flow.a;
        flow.client = client;
        flow.a = client;
        flow.b = server;
      } else {
        flow.client = flow.a;
      }
      const dirs = flow.dirs;
      const sent = { aToB: [], bToA: [] };
      const ack = {
        aToB: { last: null, window: null, duplicates: 0 },
        bToA: { last: null, window: null, duplicates: 0 }
      };
      const state = flow.state;
      flow.packets.forEach((entry) => {
        const packet = entry.packet;
        const tcp = entry.tcp;
        const record = entry.record;
        const fromClient = sameEndpoint(packet.ip.src, tcp.sport, flow.a);
        const dir = fromClient ? "aToB" : "bToA";
        const opposite = fromClient ? "bToA" : "aToB";
        const d = dirs[dir];
        const syn = Boolean(tcp.flags & 0x02);
        const ackFlag = Boolean(tcp.flags & 0x10);
        const fin = Boolean(tcp.flags & 0x01);
        const rst = Boolean(tcp.flags & 0x04);
        const payload = tcp.payload || new Uint8Array(0);
        const seq = (tcp.seq + (syn ? 1 : 0)) >>> 0;
        const info = infoFor(record);
        info.direction = dir;
        info.flowFields["tcp.stream"] = flow.index;
        info.flowFields["tcp.srcport"] = tcp.sport;
        info.flowFields["tcp.dstport"] = tcp.dport;
        info.flowFields["tcp.flags"] = tcp.flags;
        info.flowFields["tcp.window"] = tcp.window;
        info.flowFields["tcp.analysis.retransmission"] = false;
        info.flowFields["tcp.analysis.out_of_order"] = false;
        info.flowFields["tcp.analysis.fast_retransmission"] = false;
        info.flowFields["tcp.analysis.duplicate_ack"] = false;
        info.flowFields["tcp.analysis.zero_window"] = false;
        info.flowFields["tcp.analysis.keepalive"] = false;
        info.flowFields["tcp.analysis.rst"] = rst;
        d.packets.push(record);
        if (!d.firstTs || record.ts) d.firstTs = d.firstTs || record.ts || 0;
        if (record.ts) d.lastTs = record.ts;
        if (syn) {
          d.syn = true;
          state.syn = state.syn || record.number;
          state.synTs = state.synTs || record.ts || 0;
          const mss = (tcp.options || []).find((option) => option.kind === 2);
          const scale = (tcp.options || []).find((option) => option.kind === 3);
          const sack = (tcp.options || []).find((option) => option.kind === 4);
          const ts = (tcp.options || []).find((option) => option.kind === 8);
          if (mss && mss.mss != null) d.mss = mss.mss;
          if (scale && scale.shift != null) d.windowScale = scale.shift;
          if (sack) d.sackPermitted = true;
          if (ts) d.timestamps = true;
          if (syn && ackFlag) state.synAck = state.synAck || record.number;
        }
        if (ackFlag && !syn && state.syn && !state.handshakeComplete) {
          state.handshakeComplete = record.number;
        }
        if (fin) { d.fin = true; state.fin = state.fin || record.number; }
        if (rst) { d.rst = true; state.rst = state.rst || record.number; }

        if (d.baseSeq == null) d.baseSeq = seq;
        if (d.arrivalNext == null) d.arrivalNext = seq;
        const seqU = unwrapSeq(seq, d.baseSeq);
        if (payload.length) {
          if (seqU > d.arrivalNext) {
            d.outOfOrder += 1;
            info.flowFields["tcp.analysis.out_of_order"] = true;
          } else if (seqU < d.arrivalNext) {
            const overlap = d.arrivalNext - seqU;
            if (overlap >= payload.length) {
              d.retransmissions += 1;
              info.flowFields["tcp.analysis.retransmission"] = true;
            } else {
              d.retransmissions += 1;
              info.flowFields["tcp.analysis.retransmission"] = true;
            }
          } else {
            d.arrivalNext = seqU + payload.length;
          }
          d.segments.push({
            seq: seqU, bytes: payload, number: record.number,
            ts: record.ts || 0, flags: tcp.flags,
            retransmitted: Boolean(info.flowFields["tcp.analysis.retransmission"])
          });
          d.bytes += payload.length;
          sent[dir].push({
            seq: seqU, end: seqU + payload.length, ts: record.ts || 0,
            number: record.number, retransmitted: Boolean(info.flowFields["tcp.analysis.retransmission"])
          });
        }

        const windowValue = tcp.window == null ? 0 : tcp.window;
        if (windowValue === 0 && ackFlag) {
          d.zeroWindow = true;
          d.zeroWindowPackets.push(record.number);
          info.flowFields["tcp.analysis.zero_window"] = true;
        }
        if (ackFlag && !payload.length && !syn && !fin && !rst) {
          const ackState = ack[dir];
          if (ackState.last != null && tcp.ack === ackState.last && windowValue === ackState.window) {
            ackState.duplicates += 1;
            d.duplicateAcks = ackState.duplicates;
            info.flowFields["tcp.analysis.duplicate_ack"] = true;
            if (ackState.duplicates >= 3 && info.flowFields["tcp.analysis.retransmission"]) {
              info.flowFields["tcp.analysis.fast_retransmission"] = true;
            }
          } else {
            ackState.duplicates = 0;
          }
          ackState.last = tcp.ack;
          ackState.window = windowValue;
          const oppositeDir = dirs[opposite];
          if (oppositeDir.arrivalNext != null && seqU === d.arrivalNext - 1 && payload.length <= 1) {
            d.keepalives += 1;
            info.flowFields["tcp.analysis.keepalive"] = true;
          }
        }

        if (ackFlag && sent[opposite].length) {
          const sender = dirs[opposite];
          const ackBase = sender.baseSeq == null ? tcp.ack : sender.baseSeq;
          const ackU = unwrapSeq(tcp.ack, ackBase);
          let best = null;
          sent[opposite].forEach((item) => {
            if (item.retransmitted) return;
            if (item.end <= ackU && (!best || item.end > best.end)) best = item;
          });
          if (best && best.ts && record.ts && record.ts >= best.ts) {
            const rtt = record.ts - best.ts;
            if (rtt >= 0 && rtt < 3600) {
              const force = false;
              if (!force) {
                d.rttSamples.push(rtt);
                d.rttLast = rtt;
                d.rttMin = d.rttMin == null ? rtt : Math.min(d.rttMin, rtt);
                d.rttMax = d.rttMax == null ? rtt : Math.max(d.rttMax, rtt);
                const sum = d.rttSamples.reduce((total, value) => total + value, 0);
                d.rttAvg = sum / d.rttSamples.length;
                info.flowFields["tcp.analysis.rtt"] = rtt;
              }
            }
          }
        }
        if (d.mss != null) info.flowFields["tcp.options.mss"] = d.mss;
        if (d.windowScale != null) info.flowFields["tcp.options.wscale"] = d.windowScale;
        if (d.sackPermitted) info.flowFields["tcp.options.sack_perm"] = true;
        if (d.timestamps) info.flowFields["tcp.options.timestamp"] = true;
      });
      Object.keys(dirs).forEach((name) => {
        const d = dirs[name];
        d.assembled = reassembleDirection(d);
      });
      flow.bytes = dirs.aToB.bytes + dirs.bToA.bytes;
      flow.packetCount = flow.packets.length;
      flow.firstTs = flow.packets.length ? flow.packets[0].record.ts || 0 : 0;
      flow.lastTs = flow.packets.length ? flow.packets[flow.packets.length - 1].record.ts || 0 : 0;
      flow.firstNumber = flow.packets.length ? flow.packets[0].record.number : null;
      flow.lastNumber = flow.packets.length ? flow.packets[flow.packets.length - 1].record.number : null;
      flow.dirs = dirs;
      return flow;
    }

    function reassembleDirection(direction) {
      const segments = direction.segments.slice().sort((left, right) => left.seq - right.seq || left.number - right.number);
      const chunks = [];
      const runs = [];
      let expected = segments.length ? segments[0].seq : 0;
      let assembledBytes = 0;
      segments.forEach((segment) => {
        let bytes = segment.bytes;
        if (segment.seq > expected) {
          const gap = segment.seq - expected;
          chunks.push({ gap });
          direction.gaps += 1;
          direction.gapBytes += gap;
          expected = segment.seq;
        } else if (segment.seq < expected) {
          const skip = expected - segment.seq;
          if (skip >= bytes.length) {
            direction.retransmissions += 1;
            return;
          }
          bytes = bytes.subarray(skip);
          direction.retransmissions += 1;
        }
        if (!bytes.length) return;
        const start = assembledBytes;
        chunks.push({ bytes, seq: segment.seq, number: segment.number, start });
        runs.push({ start, end: start + bytes.length, number: segment.number, bytes });
        assembledBytes += bytes.length;
        expected = segment.seq + segment.bytes.length;
      });
      direction.chunks = chunks;
      direction.runs = runs;
      if (assembledBytes > MAX_STREAM_BYTES) {
        direction.chunks = [];
        direction.runs = [];
        direction.assembled = new Uint8Array(0);
        return direction.assembled;
      }
      const data = new Uint8Array(assembledBytes);
      let cursor = 0;
      chunks.forEach((chunk) => {
        if (chunk.gap != null) return;
        data.set(chunk.bytes, cursor);
        cursor += chunk.bytes.length;
      });
      direction.assembled = data;
      return data;
    }

    function packetsForRange(direction, offset, length) {
      if (!direction || !direction.runs || !direction.runs.length) return [];
      const start = Math.max(0, offset || 0);
      const end = start + Math.max(1, length || 1);
      const out = [];
      direction.runs.forEach((run) => {
        if (run.end > start && run.start < end) out.push(run.number);
      });
      return unique(out);
    }

    function infoByNumber(number) {
      let info = packetInfo.get(number);
      if (!info) {
        info = {
          flow: null, direction: null, appKind: "", summary: "",
          flowFields: {}, tcpAnalysis: null, experts: [], expert: "",
          layers: [], fragmentOf: null, diagnosis: []
        };
        packetInfo.set(number, info);
      }
      return info;
    }

    function flowFieldsForAll(flow, fields) {
      flow.members.forEach((record) => mergeFields(infoByNumber(record.number), fields));
    }

    function addLayer(info, layer) {
      if (!info || !layer) return;
      if (info.layers.length >= 24) return;
      info.layers.push(layer);
    }

    function markRange(flow, direction, offset, length, fields, layer) {
      const numbers = packetsForRange(direction, offset, length);
      if (!numbers.length) return;
      numbers.forEach((number) => {
        const info = infoByNumber(number);
        mergeFields(info, fields);
        addLayer(info, layer);
      });
      return numbers;
    }

    function safeDecode(flow, label, fn) {
      try {
        return fn();
      } catch (err) {
        flow.warnings.push(label + ": " + err.message);
        return null;
      }
    }

    function appSummary(kind, detail) {
      return kind + (detail ? " · " + detail : "");
    }

    /* ---------- TLS ---------- */

    function decodeTlsFlow(flow) {
      if (!global.TLSCodec) return null;
      const ctx = {};
      const decoded = {};
      ["aToB", "bToA"].forEach((dir) => {
        const direction = flow.dirs[dir];
        if (!direction.assembled.length) return;
        const value = safeDecode(flow, "TLS " + dir, () => global.TLSCodec.decodeTls(direction.assembled, { context: ctx }));
        if (value) decoded[dir] = value;
      });
      const keys = Object.keys(decoded);
      if (!keys.length) return null;
      const first = decoded[keys[0]];
      const context = ctx;
      const fields = {};
      if (context.negotiatedVersion) fields["tls.version"] = global.TLSCodec.versionName(context.negotiatedVersion);
      else if (context.clientVersions && context.clientVersions.length) fields["tls.version"] = global.TLSCodec.versionName(context.clientVersions[0]);
      if (context.sni) fields["tls.handshake.extensions_server_name"] = context.sni;
      if (context.alpn && context.alpn.length) fields["tls.alpn"] = context.alpn.join(",");
      if (context.cipherSuite != null) fields["tls.cipher"] = global.TLSCodec.cipherName(context.cipherSuite);
      flowFieldsForAll(flow, fields);

      const messages = [];
      keys.forEach((dir) => {
        const value = decoded[dir];
        const direction = flow.dirs[dir];
        (value.handshakes || []).forEach((handshake) => {
          const numbers = packetsForRange(direction, handshake.offset || 0, (handshake.length || 0) + 4);
          const local = {
            "tls.handshake.type": handshake.typeName || String(handshake.type),
            "tls.handshake.length": handshake.length
          };
          if (context.sni) local["tls.handshake.extensions_server_name"] = context.sni;
          if (context.alpn && context.alpn.length) local["tls.alpn"] = context.alpn.join(",");
          if (context.negotiatedVersion) local["tls.version"] = global.TLSCodec.versionName(context.negotiatedVersion);
          if (context.cipherSuite != null) local["tls.cipher"] = global.TLSCodec.cipherName(context.cipherSuite);
          numbers.forEach((number) => mergeFields(infoByNumber(number), local));
          const layer = {
            proto: "tls-stream", name: "TLS " + (handshake.typeName || "Handshake"),
            offset: 0, length: 0,
            summary: handshake.summary + (numbers.length > 1 ? " · reassembled across " + numbers.length + " packets" : ""),
            fields: (handshake.fields || []).slice(0, 12),
            warnings: (handshake.warnings || []).slice(0, 6), depth: 6, href: "tls.html"
          };
          numbers.forEach((number) => addLayer(infoByNumber(number), layer));
          messages.push({ dir, handshake, packets: numbers });
        });
        (value.records || []).forEach((record) => {
          const numbers = packetsForRange(direction, record.offset || 0, (record.length || 0) + 5);
          const local = {
            "tls.record.type": record.typeName || String(record.type),
            "tls.record.version": record.versionName || record.legacyVersion
          };
          numbers.forEach((number) => mergeFields(infoByNumber(number), local));
        });
        (value.alerts || []).forEach((alert) => {
          const numbers = packetsForRange(direction, alert.offset || 0, 2);
          numbers.forEach((number) => mergeFields(infoByNumber(number), { "tls.alert": alert.summary }));
        });
      });
      const summaryParts = [];
      if (context.negotiatedVersion) summaryParts.push(global.TLSCodec.versionName(context.negotiatedVersion));
      if (context.sni) summaryParts.push("SNI " + context.sni);
      if (context.alpn && context.alpn.length) summaryParts.push("ALPN " + context.alpn.join("/"));
      const names = messages.map((entry) => entry.handshake.typeName).filter(Boolean);
      if (names.length) summaryParts.push(names.slice(0, 6).join(" → ") + (names.length > 6 ? " …" : ""));
      summaryParts.push((decoded.aToB ? decoded.aToB.records.length : 0) + (decoded.bToA ? decoded.bToA.records.length : 0) + " record(s)");
      const app = {
        kind: "tls", decoded, context, messages,
        summary: "TLS " + summaryParts.join(" · "),
        warnings: keys.reduce((out, dir) => out.concat(decoded[dir].warnings || []), []).slice(0, 20)
      };
      if (context.sni) flowFieldsForAll(flow, { "tls.handshake.extensions_server_name": context.sni });
      return app;
    }

    /* ---------- HTTP/1 and HTTP/2 ---------- */

    function decodeHttp1Direction(flow, directionName) {
      const direction = flow.dirs[directionName];
      if (!direction.assembled.length || !global.HTTPCodec) return [];
      const messages = [];
      let offset = 0;
      let guard = 0;
      while (offset < direction.assembled.length && guard++ < 2000) {
        const slice = direction.assembled.subarray(offset);
        let decoded = null;
        try {
          decoded = global.HTTPCodec.decodeHttp1(slice);
        } catch (err) {
          flow.warnings.push("HTTP/1 " + directionName + " at byte " + offset + ": " + err.message);
          break;
        }
        if (!decoded || !decoded.messageLength || decoded.messageLength <= 0) break;
        const length = Math.min(decoded.messageLength, slice.length);
        const numbers = packetsForRange(direction, offset, length);
        const entry = {
          direction: directionName, message: decoded, offset, length, packets: numbers,
          ts: numbers.length ? (infoByNumber(numbers[0]).flow ? traceTimestamp(flow, numbers[0]) : 0) : 0
        };
        messages.push(entry);
        offset += length;
        const warnings = decoded.warnings || [];
        if (warnings.some((warning) => /No blank line|only .* captured|close-delimited|incomplete|truncated/i.test(warning))) break;
        if (length === 0) break;
      }
      return messages;
    }

    function traceTimestamp(flow, number) {
      const entry = flow.packets.find((item) => item.record.number === number);
      return entry ? entry.record.ts || 0 : 0;
    }

    function httpHeaderValue(headers, name) {
      const lower = String(name).toLowerCase();
      const found = (headers || []).find((header) => String(header.lower || header.name || "").toLowerCase() === lower);
      return found ? found.value : "";
    }

    function decodeHttpFlow(flow) {
      if (!global.HTTPCodec) return null;
      const client = flow.dirs.aToB;
      const preface = client.assembled.length >= global.HTTPCodec.H2_PREFACE.length &&
        global.HTTPCodec.asciiString(client.assembled.subarray(0, global.HTTPCodec.H2_PREFACE.length)) === global.HTTPCodec.H2_PREFACE;
      if (preface || (client.assembled.length >= 9 && global.HTTPCodec.looksLikeHttp2(client.assembled))) {
        return decodeHttp2Flow(flow);
      }
      const requests = decodeHttp1Direction(flow, "aToB");
      const responses = decodeHttp1Direction(flow, "bToA");
      const messages = requests.concat(responses).sort((left, right) => left.ts - right.ts || left.offset - right.offset);
      if (!messages.length) return null;
      requests.forEach((request, index) => {
        const response = responses[index];
        if (response) {
          request.response = response;
          response.request = request;
        }
      });
      const fields = {};
      messages.forEach((entry) => {
        const message = entry.message;
        const base = {
          "http.request.method": message.method || "",
          "http.request.uri": message.target || "",
          "http.host": httpHeaderValue(message.headers, "host") || httpHeaderValue(message.headers, ":authority"),
          "http.response.status": message.status == null ? "" : message.status,
          "http.user_agent": httpHeaderValue(message.headers, "user-agent"),
          "http.content_type": httpHeaderValue(message.headers, "content-type"),
          "http.content_length": message.contentLength == null ? "" : message.contentLength
        };
        Object.keys(base).forEach((key) => {
          if (base[key] === "" || base[key] == null) delete base[key];
        });
        entry.packets.forEach((number) => mergeFields(infoByNumber(number), base));
        const layer = {
          proto: "http-stream", name: message.kind === "h2" ? "HTTP/2 stream" : "HTTP " + (message.messageKind === "request" ? "request" : "response"),
          offset: 0, length: 0, summary: message.summary + (entry.packets.length > 1 ? " · reassembled across " + entry.packets.length + " packets" : ""),
          fields: (message.headers || []).slice(0, 10).map((header) => ({ name: header.name, value: header.value, note: "" })),
          warnings: (message.warnings || []).slice(0, 6), depth: 6, href: "http.html"
        };
        entry.packets.forEach((number) => addLayer(infoByNumber(number), layer));
        if (message.messageKind === "request") {
          fields["http.request.method"] = fields["http.request.method"] || message.method;
          fields["http.host"] = fields["http.host"] || httpHeaderValue(message.headers, "host");
        } else {
          fields["http.response.status"] = fields["http.response.status"] || message.status;
        }
      });
      const firstRequest = requests[0];
      const firstResponse = responses[0];
      let detail = "";
      if (firstRequest && firstRequest.message) {
        detail = firstRequest.message.method + " " + firstRequest.message.target;
        const host = httpHeaderValue(firstRequest.message.headers, "host");
        if (host) detail += " · " + host;
      }
      if (firstResponse && firstResponse.message) {
        detail += (detail ? " → " : "") + firstResponse.message.status + " " + (firstResponse.message.reason || "");
      }
      const doh = requests.some((entry) => {
        const target = entry.message.target || "";
        const contentType = httpHeaderValue(entry.message.headers, "content-type").toLowerCase();
        return target.indexOf("dns-query") !== -1 || contentType.indexOf("application/dns-message") !== -1;
      });
      return {
        kind: "http", messages, requests, responses, doh,
        summary: appSummary(doh ? "DoH (HTTP)" : "HTTP/1.1", detail || messages.length + " message(s)"),
        warnings: flow.warnings.slice()
      };
    }

    function decodeHttp2Flow(flow) {
      const decoded = {};
      ["aToB", "bToA"].forEach((dir) => {
        const direction = flow.dirs[dir];
        if (!direction.assembled.length) return;
        const value = safeDecode(flow, "HTTP/2 " + dir, () => global.HTTPCodec.decodeHttp2(direction.assembled));
        if (value) decoded[dir] = value;
      });
      const keys = Object.keys(decoded);
      if (!keys.length) return null;
      const messages = [];
      const streams = {};
      keys.forEach((dir) => {
        const value = decoded[dir];
        const direction = flow.dirs[dir];
        (value.frames || []).forEach((frame) => {
          const numbers = packetsForRange(direction, frame.offset || 0, (frame.length || 0) + 9);
          if (frame.streamId) {
            const key = "s" + frame.streamId;
            streams[key] = streams[key] || { id: frame.streamId, headers: [], data: new Uint8Array(0), packets: [], clientFrame: null, serverFrame: null };
            const entry = streams[key];
            entry.packets = unique(entry.packets.concat(numbers));
            if (dir === "aToB") entry.clientFrame = entry.clientFrame || frame;
            else entry.serverFrame = entry.serverFrame || frame;
            if (frame.headers) entry.headers = entry.headers.concat(frame.headers);
            if (frame.data) entry.data = concat([entry.data, frame.data]);
          }
          const local = { "http2.type": frame.typeName, "http2.stream": frame.streamId, "http2.flags": frame.flags };
          numbers.forEach((number) => mergeFields(infoByNumber(number), local));
          if (frame.headers) {
            const headers = {};
            frame.headers.forEach((header) => { headers[String(header.name).toLowerCase()] = header.value; });
            if (headers[":method"]) local["http.request.method"] = headers[":method"];
            if (headers[":path"]) local["http.request.uri"] = headers[":path"];
            if (headers[":authority"]) local["http.host"] = headers[":authority"];
            if (headers[":status"]) local["http.response.status"] = Number(headers[":status"]);
            numbers.forEach((number) => mergeFields(infoByNumber(number), local));
          }
          if (numbers.length) {
            const layer = {
              proto: "http2-stream", name: "HTTP/2 " + frame.typeName,
              offset: 0, length: 0, summary: frame.summary + (numbers.length > 1 ? " · reassembled across " + numbers.length + " packets" : ""),
              fields: (frame.fields || []).slice(0, 10), warnings: (frame.warnings || []).slice(0, 6), depth: 6, href: "http.html"
            };
            numbers.forEach((number) => addLayer(infoByNumber(number), layer));
          }
        });
      });
      Object.keys(streams).forEach((key) => {
        const stream = streams[key];
        const headers = {};
        stream.headers.forEach((header) => { headers[String(header.name).toLowerCase()] = header.value; });
        stream.method = headers[":method"] || "";
        stream.path = headers[":path"] || "";
        stream.authority = headers[":authority"] || "";
        stream.status = headers[":status"] ? Number(headers[":status"]) : null;
        stream.body = stream.data;
        messages.push(stream);
      });
      const first = messages.find((message) => message.method) || messages[0];
      const detail = first
        ? (first.method ? first.method + " " + first.path + (first.authority ? " · " + first.authority : "") : "stream " + first.id) +
          (first.status != null ? " → " + first.status : "")
        : messages.length + " stream(s)";
      const app = {
        kind: "h2", decoded, messages, streams,
        summary: appSummary("HTTP/2", detail),
        warnings: keys.reduce((out, dir) => out.concat(decoded[dir].warnings || []), []).slice(0, 20)
      };
      flowFieldsForAll(flow, { "http.request.method": first && first.method ? first.method : undefined, "http.host": first && first.authority ? first.authority : undefined });
      return app;
    }

    /* ---------- DNS ---------- */

    function dnsMessageFields(message, directionName) {
      const question = message.questions && message.questions[0];
      const answer = message.answers && message.answers[0];
      return {
        "dns.qry.name": question ? question.name : "",
        "dns.qry.type": question ? question.typeName : "",
        "dns.flags.response": Boolean(message.header && message.header.qr),
        "dns.flags.rcode": message.header ? message.header.effectiveRcodeName : "",
        "dns.count.answers": message.counts ? message.counts.answers : 0,
        "dns.answer": answer ? (answer.rdata && answer.rdata.value != null ? answer.rdata.value : answer.typeName) : "",
        "dns.id": message.header ? message.header.id : null,
        "dns.direction": directionName
      };
    }

    function decodeDnsMessages(flow, directionName, messages) {
      const list = [];
      messages.forEach((entry) => {
        const numbers = entry.packets || [];
        const fields = dnsMessageFields(entry.message, directionName);
        Object.keys(fields).forEach((key) => { if (fields[key] === "" || fields[key] == null) delete fields[key]; });
        numbers.forEach((number) => mergeFields(infoByNumber(number), fields));
        const question = entry.message.questions && entry.message.questions[0];
        const layer = {
          proto: "dns-stream", name: "DNS " + (entry.message.header.qr ? "response" : "query"),
          offset: 0, length: 0, summary: (question ? question.name + " " + question.typeName + " · " : "") +
            (entry.message.header.effectiveRcodeName || "NOERROR") + " · " + entry.message.counts.answers + " answer(s)" +
            (numbers.length > 1 ? " · reassembled across " + numbers.length + " packets" : ""),
          fields: [
            { name: "Transaction ID", value: "0x" + PH.hex(entry.message.header.id, 4) },
            { name: "RCODE", value: entry.message.header.effectiveRcodeName },
            { name: "Questions", value: entry.message.counts.questions },
            { name: "Answers", value: entry.message.counts.answers }
          ],
          warnings: (entry.message.warnings || []).slice(0, 6), depth: 6, href: "dns.html"
        };
        numbers.forEach((number) => addLayer(infoByNumber(number), layer));
        list.push(entry);
      });
      return list;
    }

    function decodeDnsTcpFlow(flow) {
      if (!global.DNSCodec) return null;
      const messages = [];
      ["aToB", "bToA"].forEach((dir) => {
        const direction = flow.dirs[dir];
        let offset = 0;
        let guard = 0;
        while (offset + 2 <= direction.assembled.length && guard++ < 2000) {
          const length = PH.u16be(direction.assembled, offset);
          if (length < 12 || offset + 2 + length > direction.assembled.length) break;
          const slice = direction.assembled.subarray(offset + 2, offset + 2 + length);
          const message = safeDecode(flow, "DNS/TCP " + dir, () => global.DNSCodec.decodeMessage(slice, { allowLarge: true }));
          if (!message) break;
          messages.push({
            direction: dir, message, offset, length: length + 2,
            packets: packetsForRange(direction, offset, length + 2)
          });
          offset += 2 + length;
        }
      });
      if (!messages.length) return null;
      decodeDnsMessages(flow, "tcp", messages);
      const first = messages[0].message;
      const question = first.questions && first.questions[0];
      const dot = flow.a.port === 853 || flow.b.port === 853;
      return {
        kind: "dns", messages,
        summary: appSummary("DNS", (question ? question.name + " " + question.typeName + " · " : "") +
          first.header.effectiveRcodeName + " · " + messages.length + " message(s) " +
          (dot ? "over TLS (DoT)" : "over TCP")),
        warnings: flow.warnings.slice()
      };
    }

    function decodeDnsDatagramFlow(flow) {
      if (!global.DNSCodec) return null;
      const messages = [];
      flow.packets.forEach((entry) => {
        const udp = entry.udp;
        const payload = udp.payload || new Uint8Array(0);
        if (!payload.length) return;
        const message = safeDecode(flow, "DNS " + entry.record.number, () => global.DNSCodec.decodeMessage(payload, { allowLarge: true }));
        if (!message) return;
        const direction = sameEndpoint(entry.packet.ip.src, udp.srcPort, flow.a) ? "aToB" : "bToA";
        const numbers = [entry.record.number];
        messages.push({ direction, message, offset: 0, length: payload.length, packets: numbers, ts: entry.record.ts || 0 });
      });
      if (!messages.length) return null;
      decodeDnsMessages(flow, "udp", messages);
      const first = messages[0].message;
      const question = first.questions && first.questions[0];
      return {
        kind: "dns", messages,
        summary: appSummary("DNS", (question ? question.name + " " + question.typeName + " · " : "") +
          first.header.effectiveRcodeName + " · " + messages.length + " message(s)"),
        warnings: flow.warnings.slice()
      };
    }

    /* ---------- BGP ---------- */

    function decodeBgpFlow(flow) {
      if (!global.BGPCodec) return null;
      const messages = [];
      ["aToB", "bToA"].forEach((dir) => {
        const direction = flow.dirs[dir];
        let offset = 0;
        let guard = 0;
        while (offset + 19 <= direction.assembled.length && guard++ < 2000) {
          const marker = direction.assembled.subarray(offset, offset + 16);
          if (!marker.every((byte) => byte === 0xff)) break;
          const length = PH.u16be(direction.assembled, offset + 16);
          if (length < 19 || offset + length > direction.assembled.length) break;
          const slice = direction.assembled.subarray(offset, offset + length);
          const parsed = safeDecode(flow, "BGP " + dir, () => global.BGPCodec.parseInput(slice, 4));
          if (!parsed) break;
          const numbers = packetsForRange(direction, offset, length);
          const envelope = parsed.envelope || {};
          const fields = {
            "bgp.type": envelope.typeName || "unknown",
            "bgp.length": length,
            "bgp.notification": envelope.type === 3 ? "NOTIFICATION" : ""
          };
          if (!fields["bgp.notification"]) delete fields["bgp.notification"];
          numbers.forEach((number) => mergeFields(infoByNumber(number), fields));
          const layer = {
            proto: "bgp-stream", name: "BGP " + (envelope.typeName || "message"),
            offset: 0, length: 0,
            summary: "BGP " + (envelope.typeName || "message") + " · " + length + " B" +
              (parsed.attrs && parsed.attrs.length ? " · " + parsed.attrs.length + " attribute(s)" : "") +
              (numbers.length > 1 ? " · reassembled across " + numbers.length + " packets" : ""),
            fields: (parsed.attrs || []).slice(0, 10).map((attr) => ({ name: attr.name, value: attr.length + " B", note: attr.parsed && attr.parsed.summary ? attr.parsed.summary : "" })),
            warnings: (parsed.warnings || []).slice(0, 8), depth: 6, href: "bgp.html"
          };
          numbers.forEach((number) => addLayer(infoByNumber(number), layer));
          messages.push({ dir, parsed, offset, length, packets: numbers });
          offset += length;
        }
      });
      if (!messages.length) return null;
      const first = messages[0].parsed.envelope || {};
      return {
        kind: "bgp", messages,
        summary: appSummary("BGP", (first.typeName || "message") + " · " + messages.length + " message(s) over TCP"),
        warnings: flow.warnings.slice()
      };
    }

    /* ---------- UDP application decoders ---------- */

    function decodeDhcpFlow(flow) {
      if (!global.DHCPCodec) return null;
      const messages = [];
      flow.packets.forEach((entry) => {
        const payload = entry.udp.payload || new Uint8Array(0);
        if (!payload.length) return;
        const message = safeDecode(flow, "DHCP " + entry.record.number, () => global.DHCPCodec.decodeDhcp(payload));
        if (!message) return;
        const direction = sameEndpoint(entry.packet.ip.src, entry.udp.srcPort, flow.a) ? "aToB" : "bToA";
        const fields = {
          "dhcp.type": message.messageTypeName,
          "dhcp.xid": message.xid,
          "dhcp.client": message.chaddrText,
          "dhcp.yiaddr": message.yiaddr,
          "dhcp.lease": (message.options || []).find((option) => option.code === 51 && !option.control) ? true : false
        };
        if (!fields["dhcp.lease"]) delete fields["dhcp.lease"];
        mergeFields(infoByNumber(entry.record.number), fields);
        addLayer(infoByNumber(entry.record.number), {
          proto: "dhcp-stream", name: "DHCP " + message.messageTypeName,
          offset: 0, length: 0, summary: message.messageTypeName + " · xid 0x" + PH.hex(message.xid, 8) +
            " · " + message.chaddrText + (message.yiaddr && message.yiaddr !== "0.0.0.0" ? " · yiaddr " + message.yiaddr : ""),
          fields: (message.options || []).slice(0, 10).map((option) => ({ name: option.name || ("option " + option.code), value: option.valueText || "", note: option.control ? "control" : "" })),
          warnings: (message.warnings || []).slice(0, 8), depth: 6, href: "dhcp.html"
        });
        messages.push({ direction, message, packets: [entry.record.number] });
      });
      if (!messages.length) return null;
      const first = messages[0].message;
      return {
        kind: "dhcp", messages,
        summary: appSummary("DHCP", first.messageTypeName + " · xid 0x" + PH.hex(first.xid, 8) + " · " + messages.length + " message(s)"),
        warnings: flow.warnings.slice()
      };
    }

    function decodeQuicFlow(flow) {
      const payload = flow.packets.length ? flow.packets[0].udp.payload : null;
      if (!payload || !payload.length) return null;
      const first = payload[0];
      const longHeader = (first & 0x80) !== 0;
      const version = payload.length >= 5 ? PH.u32be(payload, 1) : 0;
      const names = { 0: "Initial", 1: "0-RTT", 2: "Handshake", 3: "Retry" };
      const summary = longHeader
        ? "QUIC long header · " + (names[(first >> 4) & 3] || "type " + ((first >> 4) & 3)) + " · version 0x" + PH.hex(version, 8)
        : "QUIC short header · encrypted payload";
      flow.packets.forEach((entry) => {
        mergeFields(infoByNumber(entry.record.number), {
          "quic.long": longHeader, "quic.version": "0x" + PH.hex(version, 8)
        });
      });
      return { kind: "quic", messages: [], summary: appSummary("QUIC", summary), warnings: flow.warnings.slice() };
    }

    function finalizeUdp(flow) {
      const ports = [flow.a.port, flow.b.port];
      let app = null;
      if (ports.indexOf(53) !== -1 || ports.indexOf(5353) !== -1) app = decodeDnsDatagramFlow(flow);
      if (!app && (ports.indexOf(67) !== -1 || ports.indexOf(68) !== -1)) app = decodeDhcpFlow(flow);
      if (!app && (ports.indexOf(443) !== -1 || ports.indexOf(8443) !== -1)) app = decodeQuicFlow(flow);
      if (!app) {
        app = {
          kind: "udp", messages: [],
          summary: "UDP " + endpointText(flow.a) + " ↔ " + endpointText(flow.b) + " · " + flow.packets.length + " datagram(s)",
          warnings: []
        };
      }
      flow.app = app;
      flow.bytes = flow.packets.reduce((sum, entry) => sum + (entry.record.caplen || 0), 0);
      flow.packetCount = flow.packets.length;
      flow.firstTs = flow.packets.length ? flow.packets[0].record.ts || 0 : 0;
      flow.lastTs = flow.packets.length ? flow.packets[flow.packets.length - 1].record.ts || 0 : 0;
      flow.firstNumber = flow.packets.length ? flow.packets[0].record.number : null;
      flow.lastNumber = flow.packets.length ? flow.packets[flow.packets.length - 1].record.number : null;
      return flow;
    }

    function finalizeIcmp(flow) {
      const first = flow.packets[0];
      const type = first && first.icmp ? first.icmp.type : null;
      const name = first && first.icmp ? (first.icmp.typeName || ("type " + type)) : "ICMP";
      flow.app = {
        kind: "icmp", messages: [],
        summary: "ICMP " + name + " · " + flow.packets.length + " packet(s)",
        warnings: []
      };
      flow.bytes = flow.packets.reduce((sum, entry) => sum + (entry.record.caplen || 0), 0);
      flow.packetCount = flow.packets.length;
      flow.firstTs = flow.packets.length ? flow.packets[0].record.ts || 0 : 0;
      flow.lastTs = flow.packets.length ? flow.packets[flow.packets.length - 1].record.ts || 0 : 0;
      flow.firstNumber = flow.packets.length ? flow.packets[0].record.number : null;
      flow.lastNumber = flow.packets.length ? flow.packets[flow.packets.length - 1].record.number : null;
      return flow;
    }

    /* ---------- expert info and diagnosis ---------- */

    function addTcpExperts(flow) {
      const dirs = flow.dirs;
      const byNumber = new Map();
      flow.packets.forEach((entry) => byNumber.set(entry.record.number, entry));
      ["aToB", "bToA"].forEach((name) => {
        const d = dirs[name];
        const packets = d.packets;
        if (d.retransmissions) addExpert(flow, "warn", d.retransmissions + " TCP retransmission(s) in " + name, packets);
        if (d.outOfOrder) addExpert(flow, "warn", d.outOfOrder + " out-of-order TCP segment(s) in " + name, packets);
        if (d.gaps) addExpert(flow, "warn", d.gaps + " TCP gap(s), " + d.gapBytes + " missing byte(s) in " + name, packets);
        if (d.zeroWindow) addExpert(flow, "warn", "TCP zero window advertised in " + name, d.zeroWindowPackets);
        if (d.rst) addExpert(flow, "warn", "TCP RST in " + name, packets);
        if (d.keepalives > 1) addExpert(flow, "info", d.keepalives + " TCP keepalive probe(s) in " + name, packets);
        d.packets.forEach((number) => {
          const entry = byNumber.get(number);
          if (entry && entry.tcp && entry.tcp.checksumStatus === "invalid") {
            addExpert(flow, "warn", "TCP checksum is invalid in packet #" + number, [number]);
          }
        });
      });
      if (flow.state.syn && !flow.state.synAck && !flow.state.handshakeComplete) {
        addExpert(flow, "bad", "SYN was sent but no SYN/ACK or completing ACK was observed", [flow.state.syn]);
      }
    }

    function addAppExperts(flow) {
      const app = flow.app;
      if (!app) return;
      if (app.kind === "tls") {
        Object.keys(app.decoded).forEach((dir) => {
          (app.decoded[dir].alerts || []).forEach((alert) => {
            addExpert(flow, alert.level === 2 ? "bad" : "warn", "TLS alert: " + alert.summary,
              packetsForRange(flow.dirs[dir], alert.offset || 0, 2));
          });
        });
        if (app.context && app.context.negotiatedVersion && app.context.negotiatedVersion < 0x0303) {
          addExpert(flow, "warn", "TLS negotiated an obsolete protocol version", [flow.firstNumber]);
        }
      }
      if (app.kind === "http") {
        (app.responses || []).forEach((entry) => {
          const status = entry.message.status;
          if (status >= 500) addExpert(flow, "bad", "HTTP " + status + " response: " + entry.message.reason, entry.packets);
          else if (status >= 400) addExpert(flow, "warn", "HTTP " + status + " response: " + entry.message.reason, entry.packets);
          (entry.message.warnings || []).forEach((warning) => {
            if (/both Transfer-Encoding: chunked and Content-Length|framing error/i.test(warning)) {
              addExpert(flow, "bad", "HTTP framing error: " + warning, entry.packets);
            }
          });
        });
      }
      if (app.kind === "h2") {
        Object.keys(app.decoded).forEach((dir) => {
          (app.decoded[dir].frames || []).forEach((frame) => {
            if (frame.type === 7) addExpert(flow, "warn", "HTTP/2 GOAWAY · " + (frame.errorCode == null ? "error" : frame.errorCode), packetsForRange(flow.dirs[dir], frame.offset || 0, (frame.length || 0) + 9));
            if (frame.type === 3) addExpert(flow, "warn", "HTTP/2 RST_STREAM on stream " + frame.streamId, packetsForRange(flow.dirs[dir], frame.offset || 0, (frame.length || 0) + 9));
          });
        });
      }
      if (app.kind === "dns") {
        const queries = app.messages.filter((entry) => !entry.message.header.qr);
        const responses = app.messages.filter((entry) => entry.message.header.qr);
        if (queries.length && !responses.length) addExpert(flow, "warn", "DNS query has no response in this capture", queries[0].packets);
        responses.forEach((entry) => {
          const rcode = entry.message.header.effectiveRcode;
          if (rcode === 2 || rcode === 5) addExpert(flow, "bad", "DNS " + entry.message.header.effectiveRcodeName, entry.packets);
          else if (rcode !== 0) addExpert(flow, "warn", "DNS " + entry.message.header.effectiveRcodeName, entry.packets);
          if (entry.message.header.tc) addExpert(flow, "warn", "DNS response is truncated (TC=1)", entry.packets);
        });
      }
      if (app.kind === "dhcp") {
        app.messages.forEach((entry) => {
          if (/NAK/i.test(entry.message.messageTypeName)) addExpert(flow, "bad", "DHCP NAK · " + entry.message.messageTypeName, entry.packets);
        });
      }
      if (app.kind === "bgp") {
        app.messages.forEach((entry) => {
          const type = entry.parsed.envelope && entry.parsed.envelope.type;
          if (type === 3) addExpert(flow, "bad", "BGP NOTIFICATION received", entry.packets);
        });
      }
    }

    function buildDiagnosis(flow) {
      const out = [];
      const add = (severity, title, detail, packets) => out.push({ severity, title, detail, packets: unique(packets || []) });
      if (flow.proto === "tcp") {
        if (flow.state.syn && !flow.state.synAck && !flow.state.handshakeComplete) {
          add("bad", "No SYN/ACK", "The SYN was sent but no SYN/ACK or completing ACK was seen. Check routing, firewall policy, a listener on the destination port and whether the capture point sees the reply.", [flow.state.syn]);
        }
        if (flow.state.rst) add("warn", "Connection reset", "A RST was observed. The peer or an intermediary refused, aborted or timed out the connection.", [flow.state.rst]);
        if (flow.dirs.aToB.zeroWindow || flow.dirs.bToA.zeroWindow) {
          add("warn", "Zero window", "A receiver advertised a zero window. The sender should stop until a window update arrives; a persistent zero window means the application is not reading.", flow.dirs.aToB.zeroWindowPackets.concat(flow.dirs.bToA.zeroWindowPackets));
        }
        const retrans = flow.dirs.aToB.retransmissions + flow.dirs.bToA.retransmissions;
        if (retrans) add("warn", "Retransmissions", retrans + " TCP segment(s) were retransmitted. Packet loss, reordering or a middlebox may be involved.", flow.members.map((record) => record.number));
      }
      if (flow.app && flow.app.kind === "tls") {
        Object.keys(flow.app.decoded).forEach((dir) => {
          (flow.app.decoded[dir].alerts || []).forEach((alert) => {
            add(alert.level === 2 ? "bad" : "warn", "TLS alert " + alert.descriptionName,
              "The TLS peer sent a " + alert.levelName + " alert (" + alert.descriptionName + "). Check certificates, protocol versions, cipher suites and SNI/ALPN.", packetsForRange(flow.dirs[dir], alert.offset || 0, 2));
          });
        });
      }
      if (flow.app && flow.app.kind === "http") {
        (flow.app.responses || []).forEach((entry) => {
          if (entry.message.status >= 400) {
            add(entry.message.status >= 500 ? "bad" : "warn", "HTTP " + entry.message.status,
              entry.message.reason + ". Inspect the request, server logs and any intermediary.", entry.packets);
          }
        });
      }
      if (flow.app && flow.app.kind === "dns") {
        const queries = flow.app.messages.filter((entry) => !entry.message.header.qr);
        const responses = flow.app.messages.filter((entry) => entry.message.header.qr);
        if (queries.length && !responses.length) add("warn", "No DNS response", "The query has no matching response in this capture. Check the resolver, UDP filtering and whether the response took a different path.", queries[0].packets);
        responses.forEach((entry) => {
          if (entry.message.header.effectiveRcode !== 0) {
            add("warn", "DNS " + entry.message.header.effectiveRcodeName,
              "The resolver returned " + entry.message.header.effectiveRcodeName + ". Check the name, delegation and DNSSEC state.", entry.packets);
          }
        });
      }
      if (flow.app && flow.app.kind === "dhcp") {
        flow.app.messages.forEach((entry) => {
          if (/NAK/i.test(entry.message.messageTypeName)) add("bad", "DHCP NAK", "The server refused the requested address. Check the pool, lease state and whether another server is authoritative.", entry.packets);
        });
      }
      return out;
    }

    function finalizeMeta(flow) {
      if (flow.proto === "tcp") addTcpExperts(flow);
      addAppExperts(flow);
      flow.diagnosis = buildDiagnosis(flow);
      if (flow.app && flow.app.summary) flow.summary = flow.app.summary;
      else flow.summary = flow.proto.toUpperCase() + " " + endpointText(flow.a) + " ↔ " + endpointText(flow.b) + " · " + flow.packetCount + " packet(s)";
      const expertRank = flow.expert.reduce((rank, entry) => Math.max(rank, severityRank(entry.severity)), 0);
      const severity = expertRank === 2 ? "bad" : expertRank === 1 ? "warn" : "";
      flow.members.forEach((record) => {
        const info = infoByNumber(record.number);
        info.flow = flow;
        info.appKind = flow.app ? flow.app.kind : flow.proto;
        info.summary = info.fragmentOf ? "Fragment of #" + info.fragmentOf + " · reassembled" : flow.summary;
        info.experts = flow.expert.slice(0, 12);
        info.expert = severity;
        info.diagnosis = flow.diagnosis.slice(0, 8);
        if (!info.layers.length) {
          addLayer(info, {
            proto: "flow", name: flow.proto.toUpperCase() + " flow",
            offset: 0, length: 0, summary: flow.summary,
            fields: [
              { name: "Endpoints", value: endpointText(flow.a) + " ↔ " + endpointText(flow.b) },
              { name: "Application", value: flow.app ? flow.app.kind : flow.proto },
              { name: "Packets", value: flow.packetCount },
              { name: "Payload bytes", value: flow.bytes }
            ],
            warnings: (flow.expert || []).map((entry) => entry.message).slice(0, 8),
            depth: 6, href: ""
          });
        }
        mergeFields(info, {
          "flow.proto": flow.proto,
          "flow.app": flow.app ? flow.app.kind : flow.proto,
          "flow.src": endpointText(flow.a),
          "flow.dst": endpointText(flow.b),
          "flow.packets": flow.packetCount,
          "flow.bytes": flow.bytes,
          "flow.index": flow.index
        });
      });
    }

    function finish() {
      flows.forEach((flow) => {
        try {
          if (flow.proto === "tcp") {
            finalizeTcp(flow);
            const ports = [flow.a.port, flow.b.port];
            let app = null;
            if (ports.indexOf(443) !== -1 || ports.indexOf(8443) !== -1) app = decodeTlsFlow(flow);
            if (!app) app = decodeHttpFlow(flow);
            if (!app && (ports.indexOf(53) !== -1 || ports.indexOf(853) !== -1)) app = decodeDnsTcpFlow(flow);
            if (!app && ports.indexOf(179) !== -1) app = decodeBgpFlow(flow);
            if (!app && (ports.indexOf(80) !== -1 || ports.indexOf(8080) !== -1 || ports.indexOf(8000) !== -1)) app = decodeHttpFlow(flow);
            flow.app = app;
          } else if (flow.proto === "udp") {
            finalizeUdp(flow);
          } else if (flow.proto === "icmp") {
            finalizeIcmp(flow);
          }
          finalizeMeta(flow);
        } catch (err) {
          warnings.push("Flow " + flow.index + " analysis failed: " + err.message);
          flow.warnings.push(err.message);
        }
      });
      fragments.forEach((entry) => {
        warnings.push("Incomplete " + (entry.version === 4 ? "IPv4" : "IPv6") + " fragment set " +
          entry.src + " → " + entry.dst + " id " + entry.id + " (" + entry.parts.length + " part(s))");
        entry.records.forEach((record) => {
          const info = infoByNumber(record.number);
          info.expert = "warn";
          info.experts = [{ severity: "warn", message: "Incomplete fragment set; transport header is unavailable", packets: entry.records.map((item) => item.number) }];
        });
      });
      const flowList = Array.from(flows.values());
      const expertList = [];
      flowList.forEach((flow) => {
        flow.expert.forEach((entry) => expertList.push({ flow: flow.index, severity: entry.severity, message: entry.message, packets: entry.packets }));
      });
      return {
        flows: flowList,
        byNumber: packetInfo,
        warnings,
        stats: {
          packets: packetCount,
          flows: flowList.length,
          tcp: flowList.filter((flow) => flow.proto === "tcp").length,
          udp: flowList.filter((flow) => flow.proto === "udp").length,
          experts: expertList.length
        },
        experts: expertList,
        fieldCatalog: fieldCatalog()
      };
    }

    function fieldCatalog() {
      const catalog = {};
      packetInfo.forEach((info) => {
        Object.keys(info.flowFields || {}).forEach((key) => {
          if (catalog[key]) return;
          const value = info.flowFields[key];
          catalog[key] = typeof value === "boolean" ? "bool" : typeof value === "number" ? "number" : "string";
        });
      });
      return catalog;
    }

    return {
      add,
      finish,
      fieldCatalog,
      getPacketInfo: (number) => packetInfo.get(number) || null
    };
  }

  function build(records, getResult) {
    const engine = create();
    (records || []).forEach((record) => {
      let result = null;
      try {
        result = getResult(record);
      } catch (err) {
        result = { layers: [], bytes: new Uint8Array(0), warnings: [err.message] };
      }
      engine.add(record, result);
    });
    return engine.finish();
  }

  global.PHFlows = {
    create,
    build,
    endpointText,
    canonicalKey,
    unwrapSeq,
    MAX_FLOWS,
    MAX_FRAGMENT_BYTES,
    MAX_STREAM_BYTES
  };
})(typeof window !== "undefined" ? window : globalThis);
