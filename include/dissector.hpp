// Phase 4 - Layered dissector:  Ethernet II -> ARP   |   Ethernet II -> IPv4 -> TCP -> Telnet
// Every tree node carries (offset, length) into the frame so the UI can highlight the exact bytes.
// Also contains the Wireshark-like display-filter engine.
#pragma once
#include <ctime>
#include <functional>
#include <set>

#include "l2l4_headers.hpp"

namespace netlab {

enum class Color { Default, Arp, Telnet, TcpCtl, Error };

struct Node {
  std::string text;
  int off = -1, len = 0;  // -1: derived field (no bytes)
  std::vector<Node> kids;
  Node() = default;
  Node(std::string t, int o = -1, int l = 0) : text(std::move(t)), off(o), len(l) {}
  Node& add(Node n) { kids.push_back(std::move(n)); return kids.back(); }
};

struct Dissected {
  uint32_t no = 0;
  double ts = 0;
  size_t caplen = 0;
  std::string proto = "Ethernet", src, dst, info;
  Color color = Color::Default;
  std::vector<Node> tree;
  // fields consumed by the display filter
  std::set<std::string> protos;
  Mac eth_src, eth_dst;
  bool has_ip = false, has_tcp = false;
  Ip4 ip_src = 0, ip_dst = 0;
  uint16_t sport = 0, dport = 0;
  uint8_t tcp_flags = 0;
  int arp_op = 0;
  Ip4 arp_spa = 0, arp_tpa = 0;
  bool arp_gratuitous = false, arp_probe = false;
};

namespace detail {
inline std::string hex(uint64_t v, int w = 0) { char b[24]; std::snprintf(b, sizeof b, "0x%0*llx", w, (unsigned long long)v); return b; }
inline std::string esc(const Bytes& d, size_t max = 64) {
  std::string o;
  for (uint8_t c : d) {
    if (o.size() >= max) { o += "..."; break; }
    if (c == '\r') o += "\\r"; else if (c == '\n') o += "\\n"; else if (c == 0) o += "\\0";
    else if (c == 8) o += "\\b"; else if (c == 27) o += "\\e";
    else if (c >= 32 && c < 127) o += char(c);
    else { char b[8]; std::snprintf(b, sizeof b, "\\x%02x", c); o += b; }
  }
  return o;
}
inline std::string flags_str(uint8_t f, bool brackets = true) {
  std::string s;
  auto add = [&](const char* n) { if (!s.empty()) s += ", "; s += n; };
  if (f & TCP_SYN) add("SYN");
  if (f & TCP_FIN) add("FIN");
  if (f & TCP_RST) add("RST");
  if (f & TCP_PSH) add("PSH");
  if (f & TCP_ACK) add("ACK");
  if (f & TCP_URG) add("URG");
  return brackets ? "[" + s + "]" : s;
}
inline std::string mac_label(const Mac& m) { return m.is_broadcast() ? "Broadcast" : m.str(); }
}  // namespace detail

// ----------------------------------------------------------------------------------------------- Telnet layer
inline std::string telnet_item_text(const TelnetItem& it, bool for_info) {
  using namespace detail;
  if (it.kind == TelnetItem::Data) return std::string(for_info ? "Data: " : "Data: ") + esc(it.data, for_info ? 40 : 200);
  if (it.kind == TelnetItem::Command) {
    if (it.cmd == tn::WILL || it.cmd == tn::WONT || it.cmd == tn::DO || it.cmd == tn::DONT)
      return std::string(tn::verb_name(it.cmd)) + " " + tn::opt_name(it.opt);
    return std::string("Command: ") + tn::verb_name(it.cmd);
  }
  std::string s = std::string("Suboption: ") + tn::opt_name(it.opt);
  if (it.opt == tn::OPT_NAWS && it.data.size() >= 4) s += " " + std::to_string(get16(&it.data[0])) + "x" + std::to_string(get16(&it.data[2]));
  else if (it.opt == tn::OPT_TTYPE && !it.data.empty()) {
    if (it.data[0] == tn::TTYPE_SEND) s += " SEND";
    else s += " IS \"" + std::string(it.data.begin() + 1, it.data.end()) + "\"";
  }
  return s;
}

inline void dissect_telnet(const uint8_t* p, size_t n, int base, Dissected& d) {
  TelnetParser tp;
  auto items = tp.feed(p, n);
  d.tree.push_back(Node("Telnet", base, int(n)));
  Node& t = d.tree.back();
  std::string info;
  for (auto& it : items) {
    Node& c = t.add(Node(telnet_item_text(it, false), base + int(it.off), int(it.len)));
    if (it.kind == TelnetItem::Command) {
      if (it.cmd >= tn::WILL) {
        c.add(Node("Command: " + std::string(tn::verb_name(it.cmd)) + " (" + std::to_string(it.cmd) + ")", base + int(it.off) + 1, 1));
        c.add(Node(std::string("Subcommand: ") + tn::opt_name(it.opt) + " (" + std::to_string(it.opt) + ")", base + int(it.off) + 2, 1));
      }
    } else if (it.kind == TelnetItem::Subneg) {
      if (it.opt == tn::OPT_NAWS && it.data.size() >= 4) {
        c.add(Node("Width: " + std::to_string(get16(&it.data[0])), base + int(it.off) + 3, 2));
        c.add(Node("Height: " + std::to_string(get16(&it.data[2])), base + int(it.off) + 5, 2));
      } else if (it.opt == tn::OPT_TTYPE && !it.data.empty()) {
        c.add(Node(it.data[0] == tn::TTYPE_SEND ? "Command: SEND (1)" : "Command: IS (0)", base + int(it.off) + 3, 1));
        if (it.data[0] == tn::TTYPE_IS) c.add(Node("Terminal type: " + std::string(it.data.begin() + 1, it.data.end()), base + int(it.off) + 4, int(it.data.size()) - 1));
      }
    }
    if (it.kind == TelnetItem::Data) {
      std::string txt = detail::esc(it.data, 200);
      c.text = "Data: " + txt;
      if (it.data.size() > 0 && it.data.back() == '\n') c.add(Node("(line terminated with CRLF)", -1, 0));
    }
    if (!info.empty()) info += ", ";
    info += telnet_item_text(it, true);
  }
  if (tp.pending()) { t.add(Node("[Incomplete IAC sequence at end of segment]", base + int(n) - 1, 1)); info += " [partial IAC]"; }
  d.proto = "Telnet";
  d.info = info.empty() ? "Telnet" : info;
  d.color = Color::Telnet;
  d.protos.insert("telnet");
}

// ----------------------------------------------------------------------------------------------- ARP layer
inline void dissect_arp(const Bytes& f, Dissected& d) {
  using namespace detail;
  ArpPacket a;
  const uint8_t* p = f.data() + ETH_HLEN;
  size_t n = f.size() - ETH_HLEN;
  d.proto = "ARP"; d.color = Color::Arp; d.protos.insert("arp");
  if (!ArpPacket::parse(p, n, a)) {
    d.color = Color::Error; d.info = "Malformed ARP packet (" + std::to_string(n) + " bytes)";
    d.tree.push_back(Node("Address Resolution Protocol [Malformed Packet]", ETH_HLEN, int(n)));
    return;
  }
  d.arp_op = a.oper; d.arp_spa = a.spa; d.arp_tpa = a.tpa; d.arp_gratuitous = a.is_gratuitous(); d.arp_probe = a.is_probe();
  d.src = a.sha.str();
  const char* opn = a.oper == ARP_REQUEST ? "request" : a.oper == ARP_REPLY ? "reply" : "unknown";
  if (a.oper == ARP_REQUEST) {
    if (a.is_probe()) d.info = "ARP Probe: Who has " + ip_str(a.tpa) + "? (sender 0.0.0.0)";
    else if (a.is_gratuitous()) d.info = "Gratuitous ARP for " + ip_str(a.spa) + " (Request)";
    else d.info = "Who has " + ip_str(a.tpa) + "? Tell " + ip_str(a.spa);
  } else if (a.oper == ARP_REPLY) {
    d.info = a.is_gratuitous() ? "Gratuitous ARP for " + ip_str(a.spa) + " (Reply)" : ip_str(a.spa) + " is at " + a.sha.str();
  } else d.info = "ARP opcode " + std::to_string(a.oper);

  Node t("Address Resolution Protocol (" + std::string(opn) + ")", ETH_HLEN, ARP_LEN);
  t.add(Node("Hardware type: " + std::string(a.htype == 1 ? "Ethernet" : "Unknown") + " (" + std::to_string(a.htype) + ")", 14, 2));
  t.add(Node("Protocol type: " + std::string(a.ptype == ETH_IPV4 ? "IPv4" : "Unknown") + " (" + hex(a.ptype, 4) + ")", 16, 2));
  t.add(Node("Hardware size: " + std::to_string(a.hlen), 18, 1));
  t.add(Node("Protocol size: " + std::to_string(a.plen), 19, 1));
  t.add(Node("Opcode: " + std::string(opn) + " (" + std::to_string(a.oper) + ")", 20, 2));
  if (a.is_gratuitous()) t.add(Node("[Is gratuitous: True]", -1, 0));
  if (a.is_probe()) t.add(Node("[Is probe: True]", -1, 0));
  t.add(Node("Sender MAC address: " + a.sha.str(), 22, 6));
  t.add(Node("Sender IP address: " + ip_str(a.spa), 28, 4));
  t.add(Node("Target MAC address: " + mac_label(a.tha) + (a.tha.is_zero() ? " (all zeros)" : ""), 32, 6));
  t.add(Node("Target IP address: " + ip_str(a.tpa), 38, 4));
  d.tree.push_back(std::move(t));
  if (f.size() > ETH_HLEN + ARP_LEN)
    d.tree.push_back(Node("Trailer: " + std::to_string(f.size() - ETH_HLEN - ARP_LEN) + " bytes (Ethernet padding to 60 bytes)", ETH_HLEN + ARP_LEN, int(f.size() - ETH_HLEN - ARP_LEN)));
}

// ----------------------------------------------------------------------------------------------- IPv4 / TCP layers
inline void dissect_ipv4(const Bytes& f, Dissected& d) {
  using namespace detail;
  const uint8_t* p = f.data() + ETH_HLEN;
  size_t n = f.size() - ETH_HLEN;
  Ipv4Header ih;
  d.proto = "IPv4";
  if (!Ipv4Header::parse(p, n, ih)) {
    d.color = Color::Error; d.info = "Malformed IPv4 header";
    d.tree.push_back(Node("Internet Protocol Version 4 [Malformed Packet]", ETH_HLEN, int(n)));
    return;
  }
  d.protos.insert("ip"); d.has_ip = true; d.ip_src = ih.src; d.ip_dst = ih.dst; d.src = ip_str(ih.src); d.dst = ip_str(ih.dst);
  int hl = ih.ihl * 4;
  bool csum_ok = inet_checksum(p, hl) == 0;
  const char* pn = ih.proto == IPPROTO_TCP_ ? "TCP" : ih.proto == IPPROTO_UDP_ ? "UDP" : ih.proto == IPPROTO_ICMP_ ? "ICMP" : "Unknown";
  Node ip("Internet Protocol Version 4, Src: " + ip_str(ih.src) + ", Dst: " + ip_str(ih.dst), ETH_HLEN, hl);
  ip.add(Node("0100 .... = Version: 4", 14, 1));
  ip.add(Node(".... 0101 = Header Length: " + std::to_string(hl) + " bytes (" + std::to_string(ih.ihl) + ")", 14, 1));
  ip.add(Node("Differentiated Services Field: " + hex(ih.tos, 2), 15, 1));
  ip.add(Node("Total Length: " + std::to_string(ih.total_len), 16, 2));
  ip.add(Node("Identification: " + hex(ih.id, 4) + " (" + std::to_string(ih.id) + ")", 18, 2));
  ip.add(Node("Flags: " + hex(ih.flags_frag >> 13, 1) + std::string((ih.flags_frag & 0x4000) ? ", Don't fragment" : ""), 20, 2));
  ip.add(Node("Time to Live: " + std::to_string(ih.ttl), 22, 1));
  ip.add(Node("Protocol: " + std::string(pn) + " (" + std::to_string(ih.proto) + ")", 23, 1));
  ip.add(Node("Header Checksum: " + hex(ih.checksum, 4) + (csum_ok ? " [correct]" : " [INCORRECT]"), 24, 2));
  ip.add(Node("Source Address: " + ip_str(ih.src), 26, 4));
  ip.add(Node("Destination Address: " + ip_str(ih.dst), 30, 4));
  d.tree.push_back(std::move(ip));
  if (!csum_ok) { d.color = Color::Error; d.info = "Bad IPv4 header checksum"; return; }

  size_t l4 = ETH_HLEN + hl;
  size_t end = std::min(f.size(), ETH_HLEN + size_t(ih.total_len));  // ignore Ethernet padding
  if (ih.proto != IPPROTO_TCP_ || end < l4 + 20) { d.proto = pn; d.info = std::string(pn) + " (" + std::to_string(end - l4) + " bytes)"; return; }

  const uint8_t* t = f.data() + l4;
  size_t tl = end - l4;
  uint8_t dof = (t[12] >> 4) * 4, fl = t[13];
  if (dof < 20 || dof > tl) { d.color = Color::Error; d.proto = "TCP"; d.info = "Malformed TCP header"; return; }
  uint16_t sp = get16(t), dp = get16(t + 2), win = get16(t + 14), cs = get16(t + 16);
  uint32_t seq = get32(t + 4), ack = get32(t + 8);
  size_t plen = tl - dof;
  bool tcs_ok = inet_checksum(t, tl, pseudo_sum(ih.src, ih.dst, IPPROTO_TCP_, tl)) == 0;
  d.has_tcp = true; d.sport = sp; d.dport = dp; d.tcp_flags = fl; d.protos.insert("tcp");
  d.proto = "TCP";
  d.info = std::to_string(sp) + " > " + std::to_string(dp) + " " + flags_str(fl) + " Seq=" + std::to_string(seq) +
           ((fl & TCP_ACK) ? " Ack=" + std::to_string(ack) : "") + " Win=" + std::to_string(win) + " Len=" + std::to_string(plen);
  d.color = (plen == 0 || (fl & (TCP_SYN | TCP_FIN | TCP_RST))) ? Color::TcpCtl : Color::Default;

  Node tcp("Transmission Control Protocol, Src Port: " + std::to_string(sp) + ", Dst Port: " + std::to_string(dp) +
               ", Seq: " + std::to_string(seq) + ", Len: " + std::to_string(plen), int(l4), int(dof));
  int b = int(l4);
  tcp.add(Node("Source Port: " + std::to_string(sp), b, 2));
  tcp.add(Node("Destination Port: " + std::to_string(dp) + (dp == 23 || sp == 23 ? " (telnet)" : ""), b + 2, 2));
  tcp.add(Node("Sequence Number: " + std::to_string(seq), b + 4, 4));
  tcp.add(Node("Acknowledgment Number: " + std::to_string(ack), b + 8, 4));
  tcp.add(Node("Header Length: " + std::to_string(dof) + " bytes (" + std::to_string(dof / 4) + ")", b + 12, 1));
  Node& fn = tcp.add(Node("Flags: " + hex(fl, 3) + " " + flags_str(fl), b + 13, 1));
  const std::pair<uint8_t, const char*> bits[] = {{TCP_URG, "Urgent"}, {TCP_ACK, "Acknowledgment"}, {TCP_PSH, "Push"}, {TCP_RST, "Reset"}, {TCP_SYN, "Syn"}, {TCP_FIN, "Fin"}};
  for (auto& [m, nm] : bits) fn.add(Node(std::string(nm) + ": " + ((fl & m) ? "Set" : "Not set"), b + 13, 1));
  tcp.add(Node("Window: " + std::to_string(win), b + 14, 2));
  tcp.add(Node("Checksum: " + hex(cs, 4) + (tcs_ok ? " [correct]" : " [INCORRECT]"), b + 16, 2));
  tcp.add(Node("Urgent Pointer: " + std::to_string(get16(t + 18)), b + 18, 2));
  if (plen) tcp.add(Node("TCP payload (" + std::to_string(plen) + " bytes)", b + dof, int(plen)));
  d.tree.push_back(std::move(tcp));
  if (!tcs_ok) { d.color = Color::Error; d.info += " [bad TCP checksum]"; return; }
  if (plen && (sp == 23 || dp == 23)) dissect_telnet(t + dof, plen, int(l4) + dof, d);
}

// ----------------------------------------------------------------------------------------------- Entry point
inline Dissected dissect(const Bytes& f, uint32_t no, double ts) {
  using namespace detail;
  Dissected d; d.no = no; d.ts = ts; d.caplen = f.size();
  std::time_t secs = std::time_t(ts); char tb[64]; std::strftime(tb, sizeof tb, "%b %d, %Y %H:%M:%S", std::localtime(&secs));
  d.tree.push_back(Node("Frame " + std::to_string(no) + ": " + std::to_string(f.size()) + " bytes on wire (" + std::to_string(f.size() * 8) + " bits)", 0, int(f.size())));
  d.tree.back().add(Node(std::string("Arrival Time: ") + tb, -1, 0));
  d.tree.back().add(Node("Frame Length: " + std::to_string(f.size()) + " bytes", -1, 0));

  EthernetHeader eh;
  if (!EthernetHeader::parse(f.data(), f.size(), eh)) { d.color = Color::Error; d.info = "Runt frame (" + std::to_string(f.size()) + " bytes)"; return d; }
  d.eth_src = eh.src; d.eth_dst = eh.dst; d.protos.insert("eth");
  d.src = eh.src.str(); d.dst = mac_label(eh.dst);
  Node e("Ethernet II, Src: " + eh.src.str() + ", Dst: " + eh.dst.str(), 0, ETH_HLEN);
  e.add(Node("Destination: " + mac_label(eh.dst) + (eh.dst.is_broadcast() ? " (ff:ff:ff:ff:ff:ff)" : ""), 0, 6));
  e.add(Node("Source: " + eh.src.str(), 6, 6));
  std::string tname = eh.type == ETH_ARP ? "ARP" : eh.type == ETH_IPV4 ? "IPv4" : "Unknown";
  e.add(Node("Type: " + tname + " (" + hex(eh.type, 4) + ")", 12, 2));
  d.tree.push_back(std::move(e));

  if (eh.type == ETH_ARP) { dissect_arp(f, d); d.dst = mac_label(eh.dst); }
  else if (eh.type == ETH_IPV4) dissect_ipv4(f, d);
  else d.info = "Ethernet type " + hex(eh.type, 4);
  return d;
}

// ----------------------------------------------------------------------------------------------- Display filter
// Grammar:  expr := term (('||'|'or') term)* ;  term := not (('&&'|'and') not)* ;  not := ('!'|'not') not | atom
//           atom := '(' expr ')' | field [('=='|'!=') value]
// Fields:   arp telnet tcp ip eth udp | ip == A | ip.addr ip.src ip.dst | port tcp.port tcp.srcport tcp.dstport
//           eth.addr eth.src eth.dst | arp.opcode arp.src.proto_ipv4 arp.dst.proto_ipv4 arp.isgratuitous arp.isprobe
//           tcp.flags.syn tcp.flags.fin tcp.flags.rst
class DisplayFilter {
 public:
  using Pred = std::function<bool(const Dissected&)>;
  bool compile(const std::string& text, std::string* err = nullptr) {
    pred_ = nullptr; toks_.clear(); pos_ = 0; err_.clear();
    tokenize(text);
    if (toks_.empty()) return true;  // empty filter shows everything
    Pred p = parse_or();
    if (err_.empty() && pos_ != toks_.size()) err_ = "unexpected '" + toks_[pos_] + "'";
    if (!err_.empty()) { if (err) *err = err_; return false; }
    pred_ = p;
    return true;
  }
  bool empty() const { return !pred_; }
  bool match(const Dissected& d) const { return !pred_ || pred_(d); }

 private:
  Pred pred_;
  std::vector<std::string> toks_;
  size_t pos_ = 0;
  std::string err_;

  void tokenize(const std::string& s) {
    for (size_t i = 0; i < s.size();) {
      char c = s[i];
      if (isspace((unsigned char)c)) { i++; continue; }
      if (c == '(' || c == ')') { toks_.push_back(std::string(1, c)); i++; continue; }
      if (s.compare(i, 2, "&&") == 0 || s.compare(i, 2, "||") == 0 || s.compare(i, 2, "==") == 0 || s.compare(i, 2, "!=") == 0) { toks_.push_back(s.substr(i, 2)); i += 2; continue; }
      if (c == '!') { toks_.push_back("!"); i++; continue; }
      size_t j = i;
      while (j < s.size() && !isspace((unsigned char)s[j]) && s[j] != '(' && s[j] != ')' && s[j] != '!' && s[j] != '=' && s[j] != '&' && s[j] != '|') j++;
      if (j == i) { err_ = std::string("bad character '") + c + "'"; toks_.clear(); toks_.push_back("?"); return; }
      toks_.push_back(s.substr(i, j - i)); i = j;
    }
  }
  bool peek(const char* t) const { return pos_ < toks_.size() && toks_[pos_] == t; }
  Pred parse_or() {
    Pred l = parse_and();
    while (err_.empty() && (peek("||") || peek("or"))) { pos_++; Pred r = parse_and(); l = [l, r](const Dissected& d) { return l(d) || r(d); }; }
    return l;
  }
  Pred parse_and() {
    Pred l = parse_not();
    while (err_.empty() && (peek("&&") || peek("and"))) { pos_++; Pred r = parse_not(); l = [l, r](const Dissected& d) { return l(d) && r(d); }; }
    return l;
  }
  Pred parse_not() {
    if (peek("!") || peek("not")) { pos_++; Pred p = parse_not(); return [p](const Dissected& d) { return !p(d); }; }
    if (peek("(")) {
      pos_++; Pred p = parse_or();
      if (!peek(")")) { err_ = "missing ')'"; return nullptr; }
      pos_++; return p;
    }
    return parse_atom();
  }
  Pred fail(const std::string& m) { if (err_.empty()) err_ = m; return [](const Dissected&) { return false; }; }
  Pred parse_atom() {
    if (pos_ >= toks_.size()) return fail("unexpected end of filter");
    std::string f = toks_[pos_++];
    if (f == "?" || f == ")" || f == "&&" || f == "||" || f == "==" || f == "!=") return fail("unexpected '" + f + "'");
    bool has_op = peek("==") || peek("!=");
    if (!has_op) {  // bare protocol / boolean field
      if (f == "arp" || f == "telnet" || f == "tcp" || f == "ip" || f == "eth" || f == "udp") return [f](const Dissected& d) { return d.protos.count(f) > 0; };
      if (f == "arp.isgratuitous") return [](const Dissected& d) { return d.arp_gratuitous; };
      if (f == "arp.isprobe") return [](const Dissected& d) { return d.arp_probe; };
      if (f == "tcp.flags.syn") return [](const Dissected& d) { return d.has_tcp && (d.tcp_flags & TCP_SYN); };
      if (f == "tcp.flags.fin") return [](const Dissected& d) { return d.has_tcp && (d.tcp_flags & TCP_FIN); };
      if (f == "tcp.flags.rst") return [](const Dissected& d) { return d.has_tcp && (d.tcp_flags & TCP_RST); };
      return fail("unknown field '" + f + "'");
    }
    bool neg = toks_[pos_++] == "!=";
    if (pos_ >= toks_.size()) return fail("missing value after '" + f + "'");
    std::string v = toks_[pos_++];
    Pred p;
    Ip4 ip = 0; unsigned long num = 0;
    auto is_ip = ip_parse(v, ip);
    char* endp = nullptr; num = std::strtoul(v.c_str(), &endp, 10);
    bool is_num = !v.empty() && endp && *endp == 0;
    auto mac = Mac::parse(v);
    if ((f == "ip" || f == "ip.addr") && is_ip) p = [ip](const Dissected& d) { return d.has_ip && (d.ip_src == ip || d.ip_dst == ip); };
    else if (f == "ip.src" && is_ip) p = [ip](const Dissected& d) { return d.has_ip && d.ip_src == ip; };
    else if (f == "ip.dst" && is_ip) p = [ip](const Dissected& d) { return d.has_ip && d.ip_dst == ip; };
    else if ((f == "port" || f == "tcp.port") && is_num) p = [num](const Dissected& d) { return d.has_tcp && (d.sport == num || d.dport == num); };
    else if (f == "tcp.srcport" && is_num) p = [num](const Dissected& d) { return d.has_tcp && d.sport == num; };
    else if (f == "tcp.dstport" && is_num) p = [num](const Dissected& d) { return d.has_tcp && d.dport == num; };
    else if (f == "eth.addr" && mac) p = [mac](const Dissected& d) { return d.eth_src == *mac || d.eth_dst == *mac; };
    else if (f == "eth.src" && mac) p = [mac](const Dissected& d) { return d.eth_src == *mac; };
    else if (f == "eth.dst" && mac) p = [mac](const Dissected& d) { return d.eth_dst == *mac; };
    else if (f == "arp.opcode" && is_num) p = [num](const Dissected& d) { return d.protos.count("arp") && d.arp_op == int(num); };
    else if (f == "arp.src.proto_ipv4" && is_ip) p = [ip](const Dissected& d) { return d.protos.count("arp") && d.arp_spa == ip; };
    else if (f == "arp.dst.proto_ipv4" && is_ip) p = [ip](const Dissected& d) { return d.protos.count("arp") && d.arp_tpa == ip; };
    else return fail("bad field/value: " + f + " " + v);
    return neg ? Pred([p](const Dissected& d) { return !p(d); }) : p;
  }
};

}  // namespace netlab
