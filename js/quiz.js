/* Packet quiz: a static, offline question bank. No scores leave the tab. */
(function () {
  "use strict";

  const PH = window.PH;

  const QUESTIONS = [
    { topic: "Ethernet", q: "Which EtherType marks an IPv6 payload?", options: ["0x0800", "0x0806", "0x86DD", "0x8100"], a: 2, explain: "0x86DD is IPv6. 0x0800 is IPv4, 0x0806 is ARP and 0x8100 is an 802.1Q VLAN tag.", link: "ethernet.html" },
    { topic: "Ethernet", q: "How many bits are in an 802.1Q VLAN ID?", options: ["8", "12", "16", "24"], a: 1, explain: "The VID is 12 bits (0–4095). The PCP is 3 bits and the DEI is 1 bit.", link: "ethernet.html#vlan" },
    { topic: "Ethernet", q: "What is the minimum Ethernet frame size, excluding the preamble and SFD?", options: ["46 bytes", "60 bytes", "64 bytes", "68 bytes"], a: 2, explain: "64 bytes from destination MAC through FCS. The payload is padded to at least 46 bytes.", link: "ethernet.html" },
    { topic: "ARP", q: "Which ARP opcode is a request?", options: ["1", "2", "3", "8"], a: 0, explain: "1 is request, 2 is reply, 3 is RARP request and 8 is Inverse ARP.", link: "arp.html#opcodes" },
    { topic: "IPv4", q: "What does the IHL field count?", options: ["Bytes", "16-bit words", "32-bit words", "64-bit words"], a: 2, explain: "IHL is the header length in 32-bit words. A value of 5 means 20 bytes.", link: "ipv4.html" },
    { topic: "IPv4", q: "Which IP protocol number is UDP?", options: ["1", "6", "17", "47"], a: 2, explain: "1 ICMP, 6 TCP, 17 UDP, 47 GRE.", link: "ipv4.html" },
    { topic: "IPv4", q: "The IPv4 Fragment Offset field counts units of…", options: ["1 byte", "2 bytes", "4 bytes", "8 bytes"], a: 3, explain: "Fragment Offset is in 8-byte units. The low three bits of the flags field are separate.", link: "ipv4.html#flags" },
    { topic: "IPv4", q: "Which bit pattern is the IPv4 Don't Fragment flag?", options: ["0x8000", "0x4000", "0x2000", "0x1000"], a: 1, explain: "DF is 0x4000 in the flags/fragment-offset word; MF is 0x2000.", link: "ipv4.html#flags" },
    { topic: "ICMP", q: "Which ICMPv4 type is Echo Request?", options: ["0", "3", "8", "11"], a: 2, explain: "Type 8 is Echo Request; type 0 is Echo Reply. Type 3 is unreachable and 11 is time exceeded.", link: "icmp.html" },
    { topic: "ICMP", q: "What does ICMPv4 type 3 code 4 mean?", options: ["Port unreachable", "Fragmentation needed and DF set", "TTL exceeded", "Redirect"], a: 1, explain: "Type 3 code 4 is the PMTUD signal: fragmentation is needed but DF is set.", link: "icmp.html#types" },
    { topic: "IPv6", q: "How large is the fixed IPv6 base header?", options: ["20 bytes", "32 bytes", "40 bytes", "48 bytes"], a: 2, explain: "The base header is exactly 40 bytes. Extension headers follow it.", link: "ipv6.html" },
    { topic: "IPv6", q: "Which Next Header value is ICMPv6?", options: ["1", "6", "58", "89"], a: 2, explain: "58 is ICMPv6. 89 is OSPF and 1 is ICMPv4.", link: "ipv6.html#extensions" },
    { topic: "IPv6", q: "IPv6 has no broadcast. What replaces it?", options: ["Anycast only", "Multicast", "A special unicast address", "ARP"], a: 1, explain: "IPv6 uses multicast groups such as ff02::1 (all nodes) and solicited-node multicast for neighbor discovery.", link: "icmpv6.html#ndp" },
    { topic: "ICMPv6", q: "Which ICMPv6 type is Neighbor Solicitation?", options: ["133", "134", "135", "136"], a: 2, explain: "133 RS, 134 RA, 135 NS, 136 NA. 137 is Redirect.", link: "icmpv6.html" },
    { topic: "ICMPv6", q: "Which ICMPv6 type reports Packet Too Big?", options: ["1", "2", "3", "4"], a: 1, explain: "Type 2 carries the next-hop MTU. It is the IPv6 PMTUD signal.", link: "icmpv6.html#types" },
    { topic: "ICMPv6", q: "In a Router Advertisement, the M flag tells hosts to…", options: ["Use multicast", "Use DHCPv6 for addresses", "Use SLAAC only", "Disable ND"], a: 1, explain: "M = managed address configuration (DHCPv6). O = other configuration; A/L bits live in the Prefix Information option.", link: "icmpv6.html#ndp" },
    { topic: "TCP", q: "At which byte offset does the TCP flags octet start?", options: ["12", "13", "14", "16"], a: 1, explain: "Data Offset and Reserved occupy byte 12; CWR/ECE/URG/ACK/PSH/RST/SYN/FIN are byte 13.", link: "tcp.html#flags" },
    { topic: "TCP", q: "What is the minimum TCP header length?", options: ["8 bytes", "12 bytes", "20 bytes", "24 bytes"], a: 2, explain: "20 bytes with no options; Data Offset 5. Options can extend it to 60 bytes.", link: "tcp.html" },
    { topic: "TCP", q: "Which TCP option kind is Window Scale?", options: ["2", "3", "4", "8"], a: 1, explain: "Kind 2 is MSS, 3 window scale, 4 SACK-permitted, 8 timestamps.", link: "tcp.html#options" },
    { topic: "TCP", q: "A TCP checksum without the IP addresses is…", options: ["Still fully verifiable", "Unverifiable", "Always zero", "Encrypted"], a: 1, explain: "TCP covers a pseudo-header containing the IP addresses. Without them the checksum cannot be recomputed.", link: "tcp.html#notes" },
    { topic: "UDP", q: "What does a UDP checksum of zero mean in IPv4?", options: ["The checksum is invalid", "The sender did not compute it", "The payload is empty", "The port is closed"], a: 1, explain: "IPv4 allows a zero checksum to mean 'not computed'. IPv6 does not; zero is invalid there.", link: "udp.html#checksum" },
    { topic: "UDP", q: "Which port does QUIC conventionally use?", options: ["TCP 443", "UDP 443", "UDP 80", "TCP 8080"], a: 1, explain: "QUIC runs over UDP, conventionally port 443. HTTP/3 uses it.", link: "quic.html" },
    { topic: "DNS", q: "Which value starts a DNS compression pointer?", options: ["0x80", "0xC0", "0xF0", "0xFF"], a: 1, explain: "The top two bits 11 (0xC0) mark a 14-bit pointer to an earlier name offset.", link: "dns.html#names" },
    { topic: "DNS", q: "Which DNS record type is AAAA?", options: ["1", "5", "16", "28"], a: 3, explain: "A is 1, CNAME 5, TXT 16, AAAA 28. AAAA carries an IPv6 address.", link: "dns.html#records" },
    { topic: "DNS", q: "DNS over TLS conventionally uses which port?", options: ["53", "443", "853", "5353"], a: 2, explain: "DoT uses TCP 853. DoH uses HTTPS 443; DoQ uses QUIC.", link: "dns.html#transport" },
    { topic: "DHCP", q: "Which pair is DHCPv4 client/server?", options: ["67/68", "68/67", "546/547", "547/546"], a: 1, explain: "Client 68, server 67. DHCPv6 uses 546 (client) and 547 (server).", link: "dhcp.html" },
    { topic: "DHCPv6", q: "Which DHCPv6 option carries an IA_NA address?", options: ["3", "5", "6", "23"], a: 1, explain: "Option 3 is the IA_NA container; option 5 is IA Address inside it. Option 6 is ORO and 23 is DNS servers.", link: "dhcpv6.html#options" },
    { topic: "DHCPv6", q: "A DHCPv6 DUID-LL has which type value?", options: ["1", "2", "3", "4"], a: 2, explain: "1 DUID-LLT, 2 DUID-EN, 3 DUID-LL, 4 DUID-UUID.", link: "dhcpv6.html#options" },
    { topic: "HTTP", q: "Which HTTP/2 preface starts a connection?", options: ["GET / HTTP/2.0", "PRI * HTTP/2.0 CRLF CRLF SM CRLF CRLF", "HTTP/2 200", "CONNECT HTTP/2"], a: 1, explain: "The 24-byte connection preface is PRI * HTTP/2.0, CRLF CRLF, SM, CRLF CRLF.", link: "http.html#h2" },
    { topic: "HTTP/3", q: "How are HTTP/3 frame types and lengths encoded?", options: ["Fixed 4-byte integers", "QUIC varints", "HPACK integers", "Little-endian 16-bit"], a: 1, explain: "HTTP/3 uses QUIC variable-length integers for the type and payload length.", link: "http3.html" },
    { topic: "HTTP/3", q: "Which HTTP/3 frame type is SETTINGS?", options: ["0x00", "0x01", "0x04", "0x07"], a: 2, explain: "0x00 DATA, 0x01 HEADERS, 0x04 SETTINGS, 0x07 GOAWAY.", link: "http3.html#frames" },
    { topic: "TLS", q: "Which TLS content type marks a handshake record?", options: ["20", "21", "22", "23"], a: 2, explain: "20 change_cipher_spec, 21 alert, 22 handshake, 23 application_data.", link: "tls.html#record" },
    { topic: "TLS", q: "In TLS 1.3, which message is the last plaintext handshake message?", options: ["ClientHello", "ServerHello", "EncryptedExtensions", "Finished"], a: 1, explain: "ClientHello and ServerHello are plaintext. Everything after ServerHello is encrypted, including EncryptedExtensions and certificates.", link: "tls.html#sequence" },
    { topic: "QUIC", q: "A QUIC varint with first-byte prefix 11 is how long?", options: ["1 byte", "2 bytes", "4 bytes", "8 bytes"], a: 3, explain: "00 = 1, 01 = 2, 10 = 4, 11 = 8 bytes. The low 6 bits of the first byte are the high value bits.", link: "quic.html#varint" },
    { topic: "WebSocket", q: "Which direction must mask WebSocket data frames?", options: ["Server → client", "Client → server", "Both", "Neither"], a: 1, explain: "Client-to-server frames must be masked. Server-to-client frames must not be.", link: "websocket.html#frame" },
    { topic: "WebSocket", q: "Sec-WebSocket-Accept is…", options: ["SHA-1 of the key", "base64(SHA-1(key + GUID))", "MD5 of the path", "The key reversed"], a: 1, explain: "The server returns base64(SHA-1(Sec-WebSocket-Key + the RFC 6455 GUID)).", link: "websocket.html#handshake" },
    { topic: "BGP", q: "Which TCP port does BGP use?", options: ["89", "179", "520", "646"], a: 1, explain: "BGP uses TCP 179. OSPF is IP protocol 89 and LDP uses 646.", link: "bgp.html" },
    { topic: "BGP", q: "How large is the BGP message header?", options: ["16 bytes", "19 bytes", "24 bytes", "32 bytes"], a: 1, explain: "16-byte marker, 2-byte length and 1-byte type make 19 bytes.", link: "bgp.html#message" },
    { topic: "OSPF", q: "OSPFv2 is carried directly over which IP protocol?", options: ["6", "17", "89", "132"], a: 2, explain: "OSPF is IP protocol 89, not TCP or UDP. OSPFv3 uses the same protocol number over IPv6.", link: "ospf.html" },
    { topic: "OSPF", q: "How large is the OSPFv2 packet header?", options: ["16 bytes", "20 bytes", "24 bytes", "32 bytes"], a: 2, explain: "Version, type, length, router ID, area, checksum, auth type and 8-byte auth make 24 bytes.", link: "ospf.html#layout" },
    { topic: "GRE", q: "GRE uses which IP protocol number?", options: ["47", "50", "51", "132"], a: 0, explain: "47 GRE, 50 ESP, 51 AH, 132 SCTP.", link: "gre.html" },
    { topic: "VXLAN", q: "Which UDP port does VXLAN use by IANA assignment?", options: ["4789", "6081", "8472", "51820"], a: 0, explain: "VXLAN is UDP 4789. 6081 is Geneve, 8472 is a legacy VXLAN port and 51820 is WireGuard.", link: "vxlan.html" },
    { topic: "VXLAN", q: "How many bits are in a VXLAN VNI?", options: ["12", "16", "24", "32"], a: 2, explain: "The VNI is 24 bits, not the 12-bit VLAN ID. They are different namespaces.", link: "vxlan.html" },
    { topic: "WireGuard", q: "Which WireGuard message type carries encrypted inner packets?", options: ["1", "2", "3", "4"], a: 3, explain: "Type 4 is Transport Data. 1 initiation, 2 response, 3 cookie reply.", link: "wireguard.html#messages" },
    { topic: "SCTP", q: "Which checksum does SCTP use?", options: ["Internet checksum", "CRC-32", "CRC-32c", "MD5"], a: 2, explain: "SCTP uses CRC-32c (Castagnoli), not Ethernet's CRC-32 or the Internet checksum.", link: "sctp.html#layout" },
    { topic: "SCTP", q: "Which IP protocol number is SCTP?", options: ["47", "50", "132", "136"], a: 2, explain: "132 is SCTP. 136 is UDP-Lite.", link: "sctp.html" },
    { topic: "NTP", q: "What is the NTP timestamp epoch?", options: ["1970-01-01", "1900-01-01", "2000-01-01", "1980-01-01"], a: 1, explain: "NTP counts seconds from 1900-01-01, which is 2,208,988,800 seconds before the Unix epoch.", link: "ntp.html#time" },
    { topic: "IPsec", q: "Which IP protocol is ESP?", options: ["47", "50", "51", "58"], a: 1, explain: "50 ESP, 51 AH. 47 GRE and 58 ICMPv6.", link: "ipsec.html" },
    { topic: "IPsec", q: "Why does AH break under NAT?", options: ["It encrypts the addresses", "It authenticates the outer IP header", "It uses UDP", "It has no checksum"], a: 1, explain: "AH's ICV covers immutable outer IP fields. NAT rewrites the addresses, so the ICV no longer verifies.", link: "ipsec.html#ah" },
    { topic: "LLDP", q: "Which EtherType identifies LLDP?", options: ["0x0806", "0x88CC", "0x8847", "0x8100"], a: 1, explain: "LLDP uses EtherType 0x88CC. 0x88CC is also used by some discovery/control protocols.", link: "lldp.html" },
    { topic: "LLDP", q: "How is an LLDP TLV length encoded?", options: ["8 bits, in bytes", "9 bits, in bytes", "16 bits, in bytes", "7 bits, in words"], a: 1, explain: "The TLV header is a 7-bit type and a 9-bit length in bytes. The length excludes the two-byte header.", link: "lldp.html#layout" },
    { topic: "Checksums", q: "The Internet checksum is…", options: ["A CRC-32", "A one's-complement sum", "A cryptographic hash", "A Hamming code"], a: 1, explain: "RFC 1071 defines a 16-bit one's-complement sum, not a CRC or a cryptographic hash.", link: "checksum.html" },
    { topic: "Checksums", q: "Which polynomial family does CRC-32c use?", options: ["IEEE 802.3", "Castagnoli", "Adler", "FNV"], a: 1, explain: "CRC-32c uses the Castagnoli polynomial. Ethernet/zlib CRC-32 uses the IEEE polynomial.", link: "checksum.html#notes" },
    { topic: "Subnets", q: "How many usable addresses does an IPv4 /31 have under RFC 3021?", options: ["0", "1", "2", "254"], a: 2, explain: "RFC 3021 allows both addresses on a point-to-point /31 to be usable; there is no network/broadcast reservation.", link: "subnet.html#notes" },
    { topic: "Ports", q: "Which range is the IANA 'registered' range?", options: ["0–1023", "1024–49151", "49152–65535", "32768–60999"], a: 1, explain: "0–1023 well-known, 1024–49151 registered, 49152–65535 dynamic/private.", link: "ports.html#ranges" }
  ];

  const STATE = {
    order: QUESTIONS.map((_, index) => index),
    index: 0,
    answered: 0,
    correct: 0,
    streak: 0,
    best: 0,
    selected: null
  };

  function current() { return QUESTIONS[STATE.order[STATE.index % STATE.order.length]]; }

  function renderStats() {
    document.getElementById("quiz-stat-score").textContent = String(STATE.correct);
    document.getElementById("quiz-stat-answered").textContent = String(STATE.answered);
    document.getElementById("quiz-stat-streak").textContent = String(STATE.best);
    document.getElementById("quiz-stat-accuracy").textContent = STATE.answered ? Math.round((STATE.correct / STATE.answered) * 100) + "%" : "—";
    document.getElementById("quiz-score").textContent = String(STATE.correct);
    document.getElementById("quiz-streak").textContent = String(STATE.streak);
  }

  function renderQuestion() {
    const q = current();
    STATE.selected = null;
    document.getElementById("quiz-topic").textContent = q.topic;
    document.getElementById("quiz-number").textContent = "question " + (STATE.index + 1) + " / " + STATE.order.length;
    document.getElementById("quiz-progress-label").textContent = STATE.answered + " answered";
    document.getElementById("quiz-question").innerHTML = q.q;
    document.getElementById("quiz-options").innerHTML = q.options.map((option, i) =>
      `<button class="quiz-option" type="button" data-option="${i}"><span class="q-key">${String.fromCharCode(65 + i)}</span><span>${PH.esc(option)}</span></button>`
    ).join("");
    document.getElementById("quiz-explain").hidden = true;
    document.getElementById("quiz-explain").innerHTML = "";
    document.getElementById("quiz-next").disabled = true;
    document.getElementById("quiz-next").textContent = "Next question";
    document.getElementById("quiz-progress-bar").style.width = (STATE.index / STATE.order.length) * 100 + "%";
    renderStats();
    document.querySelectorAll("[data-option]").forEach((btn) => btn.addEventListener("click", () => answer(Number(btn.getAttribute("data-option")))));
  }

  function answer(choice) {
    if (STATE.selected != null) return;
    const q = current();
    STATE.selected = choice;
    STATE.answered += 1;
    const right = choice === q.a;
    if (right) {
      STATE.correct += 1;
      STATE.streak += 1;
      STATE.best = Math.max(STATE.best, STATE.streak);
    } else {
      STATE.streak = 0;
    }
    document.querySelectorAll("[data-option]").forEach((btn) => {
      const index = Number(btn.getAttribute("data-option"));
      btn.disabled = true;
      if (index === q.a) btn.classList.add("is-right");
      if (index === choice && !right) btn.classList.add("is-wrong");
    });
    const explain = document.getElementById("quiz-explain");
    explain.hidden = false;
    explain.innerHTML = `<b>${right ? "Correct." : "Incorrect."}</b> ${PH.esc(q.explain)} <a href="${PH.esc(q.link)}">open the reference page →</a>`;
    document.getElementById("quiz-next").disabled = false;
    document.getElementById("quiz-next").textContent = STATE.index + 1 >= STATE.order.length ? "Restart quiz" : "Next question";
    document.getElementById("quiz-progress-bar").style.width = ((STATE.index + 1) / STATE.order.length) * 100 + "%";
    renderStats();
  }

  function next() {
    if (STATE.selected == null) return;
    STATE.index += 1;
    if (STATE.index >= STATE.order.length) STATE.index = 0;
    renderQuestion();
  }

  function reset() {
    STATE.order = QUESTIONS.map((_, index) => index);
    STATE.index = 0; STATE.answered = 0; STATE.correct = 0;
    STATE.streak = 0; STATE.best = 0; STATE.selected = null;
    renderQuestion();
  }

  function shuffle(list) {
    for (let i = list.length - 1; i > 0; i--) {
      const j = Math.floor(Math.random() * (i + 1));
      [list[i], list[j]] = [list[j], list[i]];
    }
    return list;
  }

  function init() {
    if (!document.getElementById("quiz-question")) return;
    document.getElementById("quiz-next").addEventListener("click", next);
    document.getElementById("quiz-reset").addEventListener("click", () => { reset(); PH.toast("quiz reset"); });
    document.getElementById("quiz-shuffle").addEventListener("click", () => {
      STATE.order = shuffle(STATE.order);
      STATE.index = 0; STATE.answered = 0; STATE.correct = 0; STATE.streak = 0; STATE.best = 0;
      renderQuestion();
      PH.toast("question order shuffled");
    });
    document.addEventListener("keydown", (event) => {
      const tag = (event.target.tagName || "").toLowerCase();
      if (tag === "input" || tag === "textarea" || tag === "select") return;
      if (event.key >= "1" && event.key <= "4") {
        const index = Number(event.key) - 1;
        if (index < current().options.length) answer(index);
      } else if (event.key === "Enter" || event.key.toLowerCase() === "n") {
        if (!document.getElementById("quiz-next").disabled) next();
      }
    });
    renderQuestion();
  }

  if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", init);
  else init();
})();
