/* A deliberately small display-filter language for the packet workbench.
 *
 * It is not Wireshark's filter engine. It parses a documented subset with a
 * real tokenizer/parser (no eval), evaluates against the tiny per-packet index
 * built by the workbench, and returns a precise error for anything unknown.
 */
(function (global) {
  "use strict";

  const PROTOCOLS = [
    "eth", "ethernet", "vlan", "arp", "ip", "ipv4", "ipv6", "tcp", "udp",
    "icmp", "icmpv6", "icmp6", "dns", "dhcp", "http", "tls", "bgp", "quic",
    "fcs"
  ];

  const PROTOCOL_ALIASES = {
    ethernet: "eth",
    ipv4: "ip",
    icmp6: "icmpv6"
  };

  const FIELDS = {
    "frame.number": { type: "number", get: (i) => i.frame && i.frame.number },
    "frame.len": { type: "number", get: (i) => i.frame && i.frame.len },
    "frame.time": { type: "number", get: (i) => i.frame && i.frame.time },
    "eth.src": { type: "string", get: (i) => i.eth && i.eth.src },
    "eth.dst": { type: "string", get: (i) => i.eth && i.eth.dst },
    "eth.type": { type: "number", get: (i) => i.eth && i.eth.type },
    "vlan.id": { type: "number", get: (i) => i.vlan && i.vlan.id },
    "vlan.pcp": { type: "number", get: (i) => i.vlan && i.vlan.pcp },
    "arp.opcode": { type: "number", get: (i) => i.arp && i.arp.opcode },
    "arp.src": { type: "ip", get: (i) => i.arp && i.arp.senderIp },
    "arp.dst": { type: "ip", get: (i) => i.arp && i.arp.targetIp },
    "ip.addr": { type: "ip", many: true, get: (i) => i.ipv4 && [i.ipv4.src, i.ipv4.dst] },
    "ip.src": { type: "ip", get: (i) => i.ipv4 && i.ipv4.src },
    "ip.dst": { type: "ip", get: (i) => i.ipv4 && i.ipv4.dst },
    "ip.proto": { type: "number", get: (i) => i.ipv4 && i.ipv4.proto },
    "ip.ttl": { type: "number", get: (i) => i.ipv4 && i.ipv4.ttl },
    "ip.len": { type: "number", get: (i) => i.ipv4 && i.ipv4.len },
    "ipv6.addr": { type: "ip", many: true, get: (i) => i.ipv6 && [i.ipv6.src, i.ipv6.dst] },
    "ipv6.src": { type: "ip", get: (i) => i.ipv6 && i.ipv6.src },
    "ipv6.dst": { type: "ip", get: (i) => i.ipv6 && i.ipv6.dst },
    "ipv6.next": { type: "number", get: (i) => i.ipv6 && i.ipv6.next },
    "ipv6.hlim": { type: "number", get: (i) => i.ipv6 && i.ipv6.hopLimit },
    "net.addr": { type: "ip", many: true, get: (i) => {
      const out = [];
      if (i.ipv4) out.push(i.ipv4.src, i.ipv4.dst);
      if (i.ipv6) out.push(i.ipv6.src, i.ipv6.dst);
      return out.length ? out : undefined;
    } },
    "tcp.port": { type: "number", many: true, get: (i) => i.tcp && [i.tcp.sport, i.tcp.dport] },
    "tcp.srcport": { type: "number", get: (i) => i.tcp && i.tcp.sport },
    "tcp.dstport": { type: "number", get: (i) => i.tcp && i.tcp.dport },
    "tcp.seq": { type: "number", get: (i) => i.tcp && i.tcp.seq },
    "tcp.ack": { type: "number", get: (i) => i.tcp && i.tcp.ack },
    "tcp.len": { type: "number", get: (i) => i.tcp && i.tcp.payloadLen },
    "tcp.flags": { type: "number", get: (i) => i.tcp && i.tcp.flags },
    "tcp.flags.syn": { type: "bool", get: (i) => i.tcp && i.tcp.syn },
    "tcp.flags.ack": { type: "bool", get: (i) => i.tcp && i.tcp.ackFlag },
    "tcp.flags.fin": { type: "bool", get: (i) => i.tcp && i.tcp.fin },
    "tcp.flags.rst": { type: "bool", get: (i) => i.tcp && i.tcp.rst },
    "tcp.flags.psh": { type: "bool", get: (i) => i.tcp && i.tcp.psh },
    "tcp.flags.urg": { type: "bool", get: (i) => i.tcp && i.tcp.urg },
    "tcp.flags.ece": { type: "bool", get: (i) => i.tcp && i.tcp.ece },
    "tcp.flags.cwr": { type: "bool", get: (i) => i.tcp && i.tcp.cwr },
    "udp.port": { type: "number", many: true, get: (i) => i.udp && [i.udp.sport, i.udp.dport] },
    "udp.srcport": { type: "number", get: (i) => i.udp && i.udp.sport },
    "udp.dstport": { type: "number", get: (i) => i.udp && i.udp.dport },
    "udp.len": { type: "number", get: (i) => i.udp && i.udp.len },
    "icmp.type": { type: "number", get: (i) => i.icmp && i.icmp.type },
    "icmp.code": { type: "number", get: (i) => i.icmp && i.icmp.code },
    "icmpv6.type": { type: "number", get: (i) => i.icmpv6 && i.icmpv6.type },
    "icmpv6.code": { type: "number", get: (i) => i.icmpv6 && i.icmpv6.code },
    "dns.id": { type: "number", get: (i) => i.dns && i.dns.id },
    "dns.qname": { type: "string", get: (i) => i.dns && i.dns.qname },
    "dns.response": { type: "bool", get: (i) => i.dns && i.dns.response },
    "tls.sni": { type: "string", get: (i) => i.tls && i.tls.sni },
    "tls.handshake.type": { type: "number", get: (i) => i.tls && i.tls.handshakeType },
    "tls.version": { type: "number", get: (i) => i.tls && i.tls.version },
    "http.method": { type: "string", get: (i) => i.http && i.http.method },
    "http.host": { type: "string", get: (i) => i.http && i.http.host },
    "http.status": { type: "number", get: (i) => i.http && i.http.status },
    "dhcp.type": { type: "string", get: (i) => i.dhcp && i.dhcp.type },
    "bgp.type": { type: "number", get: (i) => i.bgp && i.bgp.type }
  };

  const EXAMPLES = [
    "tcp",
    "udp.port == 53",
    "tcp and tcp.flags.syn == 1",
    "ip.addr == 192.0.2.10",
    "net.addr == 2001:db8::/32",
    "frame.len > 1000",
    "http or tls",
    "not arp"
  ];

  function FilterError(message, position) {
    this.name = "FilterError";
    this.message = message;
    this.position = position;
    if (Error.captureStackTrace) Error.captureStackTrace(this, FilterError);
  }
  FilterError.prototype = Object.create(Error.prototype);
  FilterError.prototype.constructor = FilterError;

  function tokenize(text) {
    const tokens = [];
    let i = 0;
    while (i < text.length) {
      const ch = text[i];
      if (/\s/.test(ch)) { i += 1; continue; }
      if (ch === "(" || ch === ")") { tokens.push({ type: ch, value: ch, pos: i }); i += 1; continue; }
      if (ch === '"' || ch === "'") {
        const quote = ch;
        let j = i + 1;
        let value = "";
        while (j < text.length && text[j] !== quote) { value += text[j]; j += 1; }
        if (j >= text.length) throw new FilterError("Unterminated string", i);
        tokens.push({ type: "value", value, quoted: true, pos: i });
        i = j + 1;
        continue;
      }
      const two = text.substr(i, 2);
      if (two === "==" || two === "!=" || two === ">=" || two === "<=" || two === "&&" || two === "||" || two === "~=") {
        tokens.push({ type: "op", value: two, pos: i });
        i += 2;
        continue;
      }
      if (ch === ">" || ch === "<" || ch === "!") {
        tokens.push({ type: "op", value: ch, pos: i });
        i += 1;
        continue;
      }
      let j = i;
      while (j < text.length && !/[\s()=!<>~]/.test(text[j])) j += 1;
      const word = text.slice(i, j);
      if (!word) throw new FilterError("Unexpected character '" + ch + "'", i);
      tokens.push({ type: "word", value: word, pos: i });
      i = j;
    }
    return tokens;
  }

  function protocolFor(word) {
    const lower = word.toLowerCase();
    const canonical = PROTOCOL_ALIASES[lower] || lower;
    return PROTOCOLS.indexOf(lower) !== -1 ? canonical : null;
  }

  function parseValue(token) {
    if (token.quoted) return { type: "string", value: token.value };
    const word = token.value;
    if (/^0x[0-9a-f]+$/i.test(word)) return { type: "number", value: parseInt(word.slice(2), 16) };
    if (/^-?\d+$/.test(word)) return { type: "number", value: Number(word) };
    if (/^-?\d+\.\d+$/.test(word)) return { type: "number", value: Number(word) };
    if (/^true$/i.test(word)) return { type: "bool", value: true };
    if (/^false$/i.test(word)) return { type: "bool", value: false };
    return { type: "string", value: word };
  }

  function parse(text) {
    const tokens = tokenize(String(text || ""));
    let pos = 0;

    function peek() { return tokens[pos]; }
    function next() { return tokens[pos++]; }
    function matchOp(value) {
      const token = peek();
      if (token && token.type === "op" && token.value === value) { pos += 1; return true; }
      return false;
    }
    function matchWord(value) {
      const token = peek();
      if (token && token.type === "word" && token.value.toLowerCase() === value) { pos += 1; return true; }
      return false;
    }

    function parseOr() {
      let left = parseAnd();
      while (matchWord("or") || matchOp("||")) {
        left = { type: "or", left, right: parseAnd() };
      }
      return left;
    }
    function parseAnd() {
      let left = parseUnary();
      while (matchWord("and") || matchOp("&&")) {
        left = { type: "and", left, right: parseUnary() };
      }
      return left;
    }
    function parseUnary() {
      if (matchWord("not") || matchOp("!")) return { type: "not", expr: parseUnary() };
      return parsePrimary();
    }
    function parsePrimary() {
      const token = peek();
      if (!token) throw new FilterError("Expected an expression", text.length);
      if (token.type === "(") {
        pos += 1;
        const expr = parseOr();
        if (!peek() || peek().type !== ")") throw new FilterError("Missing closing parenthesis", token.pos);
        pos += 1;
        return expr;
      }
      if (token.type !== "word") throw new FilterError("Expected a protocol or field, found '" + token.value + "'", token.pos);
      const word = token.value;
      const proto = protocolFor(word);
      pos += 1;
      if (proto && (!peek() || peek().type !== "op")) {
        return { type: "proto", name: proto };
      }
      const lower = word.toLowerCase();
      const field = FIELDS[lower];
      if (!field) {
        if (proto) {
          // e.g. "tcp == 1" is not a field comparison
          throw new FilterError("'" + word + "' is a protocol, not a field. Use a field such as tcp.port.", token.pos);
        }
        throw new FilterError("Unknown field '" + word + "'. Try " + Object.keys(FIELDS).slice(0, 6).join(", ") + ", …", token.pos);
      }
      let op = null;
      const opToken = peek();
      if (opToken && opToken.type === "op") { op = opToken.value; pos += 1; }
      else if (matchWord("contains")) { op = "contains"; }
      if (!op) {
        // Bare boolean field, e.g. tcp.flags.syn
        if (field.type === "bool") return { type: "compare", field: lower, op: "==", value: { type: "bool", value: true } };
        throw new FilterError("Expected an operator after '" + word + "'", token.pos);
      }
      if (op === "~=") op = "contains";
      const valueToken = peek();
      if (!valueToken || valueToken.type === "op" || valueToken.type === "(" || valueToken.type === ")") {
        throw new FilterError("Expected a value after '" + word + " " + op + "'", token.pos);
      }
      pos += 1;
      return { type: "compare", field: lower, op, value: parseValue(valueToken) };
    }

    if (!tokens.length) return { type: "all" };
    const ast = parseOr();
    if (pos < tokens.length) {
      const extra = tokens[pos];
      throw new FilterError("Unexpected '" + extra.value + "'", extra.pos);
    }
    return ast;
  }

  function parseIPv4(text) {
    const parts = String(text).split(".");
    if (parts.length !== 4) return null;
    const out = new Uint8Array(4);
    for (let i = 0; i < 4; i += 1) {
      if (!/^\d+$/.test(parts[i])) return null;
      const n = Number(parts[i]);
      if (n < 0 || n > 255) return null;
      out[i] = n;
    }
    return out;
  }

  function parseIPv6(text) {
    let input = String(text).trim();
    if (input.indexOf("%") !== -1) input = input.slice(0, input.indexOf("%"));
    if (!input || input.indexOf(":") === -1) return null;
    if (input === "::") return new Uint8Array(16);
    let ipv4Tail = null;
    if (input.indexOf(".") !== -1) {
      const lastColon = input.lastIndexOf(":");
      const tail = input.slice(lastColon + 1);
      ipv4Tail = parseIPv4(tail);
      if (!ipv4Tail) return null;
      input = input.slice(0, lastColon + 1) + "0:0";
      if (input.endsWith("::0:0")) input = input.slice(0, -4) + "::";
    }
    const halves = input.split("::");
    if (halves.length > 2) return null;
    const left = halves[0] ? halves[0].split(":") : [];
    const right = halves.length === 2 ? (halves[1] ? halves[1].split(":") : []) : null;
    const groups = [];
    const parseGroups = (list) => {
      list.forEach((group) => {
        if (!/^[0-9a-f]{1,4}$/i.test(group)) throw new Error("bad group");
        groups.push(parseInt(group, 16));
      });
    };
    try {
      parseGroups(left);
      const leftCount = groups.length;
      if (right) {
        const rightGroups = [];
        right.forEach((group) => {
          if (!/^[0-9a-f]{1,4}$/i.test(group)) throw new Error("bad group");
          rightGroups.push(parseInt(group, 16));
        });
        const missing = 8 - leftCount - rightGroups.length;
        if (missing < 0) return null;
        for (let i = 0; i < missing; i += 1) groups.push(0);
        groups.push.apply(groups, rightGroups);
      } else if (leftCount !== 8) {
        return null;
      }
    } catch (_) {
      return null;
    }
    if (groups.length !== 8) return null;
    const out = new Uint8Array(16);
    groups.forEach((group, i) => {
      out[i * 2] = (group >> 8) & 255;
      out[i * 2 + 1] = group & 255;
    });
    if (ipv4Tail) {
      out[12] = ipv4Tail[0]; out[13] = ipv4Tail[1]; out[14] = ipv4Tail[2]; out[15] = ipv4Tail[3];
    }
    return out;
  }

  function ipBytes(text) {
    return parseIPv4(text) || parseIPv6(text);
  }

  function cidrMatch(address, cidr) {
    const slash = String(cidr).indexOf("/");
    if (slash === -1) return String(address).toLowerCase() === String(cidr).toLowerCase();
    const base = ipBytes(String(cidr).slice(0, slash));
    const bits = Number(String(cidr).slice(slash + 1));
    const addressBytes = ipBytes(address);
    if (!base || !addressBytes || base.length !== addressBytes.length) return false;
    if (!Number.isFinite(bits) || bits < 0 || bits > base.length * 8) return false;
    const full = Math.floor(bits / 8);
    const rest = bits % 8;
    for (let i = 0; i < full; i += 1) if (base[i] !== addressBytes[i]) return false;
    if (rest) {
      const mask = (0xff << (8 - rest)) & 0xff;
      if ((base[full] & mask) !== (addressBytes[full] & mask)) return false;
    }
    return true;
  }

  function compare(actual, op, expected, fieldType) {
    if (actual == null) return false;
    if (fieldType === "ip" && typeof expected === "string" && expected.indexOf("/") !== -1) {
      const hit = cidrMatch(actual, expected);
      return op === "!=" ? !hit : op === "==" ? hit : false;
    }
    if (fieldType === "bool") {
      const left = Boolean(actual);
      const right = expected === true || expected === 1 || expected === "1" || String(expected).toLowerCase() === "true";
      return op === "!=" ? left !== right : left === right;
    }
    if (fieldType === "number") {
      const left = Number(actual);
      const right = Number(expected);
      if (!Number.isFinite(left) || !Number.isFinite(right)) return op === "!=";
      if (op === "==") return left === right;
      if (op === "!=") return left !== right;
      if (op === ">") return left > right;
      if (op === ">=") return left >= right;
      if (op === "<") return left < right;
      if (op === "<=") return left <= right;
      return false;
    }
    const left = String(actual).toLowerCase();
    const right = String(expected).toLowerCase();
    if (op === "contains") return left.indexOf(right) !== -1;
    if (op === "==") return left === right;
    if (op === "!=") return left !== right;
    return false;
  }

  function evaluate(ast, index) {
    if (!ast || ast.type === "all") return true;
    if (ast.type === "and") return evaluate(ast.left, index) && evaluate(ast.right, index);
    if (ast.type === "or") return evaluate(ast.left, index) || evaluate(ast.right, index);
    if (ast.type === "not") return !evaluate(ast.expr, index);
    if (ast.type === "proto") {
      const protos = (index && index.protos) || [];
      if (ast.name === "ip") return protos.indexOf("ipv4") !== -1;
      if (ast.name === "eth") return protos.indexOf("ethernet") !== -1;
      return protos.indexOf(ast.name) !== -1;
    }
    if (ast.type === "compare") {
      const field = FIELDS[ast.field];
      if (!field) return false;
      let actual = field.get(index);
      if (field.many) {
        if (!Array.isArray(actual) || !actual.length) return false;
        if (ast.op === "!=") return actual.every((value) => compare(value, "!=", ast.value.value, field.type));
        return actual.some((value) => compare(value, ast.op, ast.value.value, field.type));
      }
      return compare(actual, ast.op, ast.value.value, field.type);
    }
    return false;
  }

  function fields() {
    return Object.keys(FIELDS).map((name) => ({ name, type: FIELDS[name].type }));
  }

  function describe() {
    return {
      protocols: PROTOCOLS.slice(),
      fields: fields(),
      examples: EXAMPLES.slice()
    };
  }

  global.PHFilter = {
    parse,
    evaluate,
    tokenize,
    fields,
    describe,
    examples: EXAMPLES.slice(),
    FilterError,
    parseIPv4,
    parseIPv6
  };
})(typeof window !== "undefined" ? window : globalThis);
