// Phase 1 - Wire formats: Ethernet II, ARP (RFC 826), IPv4, TCP, Telnet (RFC 854/855).
// All multi-byte fields are big-endian on the wire.
#pragma once
#include <array>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <optional>
#include <string>
#include <vector>

namespace netlab {

using Bytes = std::vector<uint8_t>;
using Ip4 = uint32_t;  // host byte order, a.b.c.d == (a<<24)|(b<<16)|(c<<8)|d

// ---------------------------------------------------------------- BE helpers
inline void put16(Bytes& b, uint16_t v) { b.push_back(uint8_t(v >> 8)); b.push_back(uint8_t(v)); }
inline void put32(Bytes& b, uint32_t v) { for (int s = 24; s >= 0; s -= 8) b.push_back(uint8_t(v >> s)); }
inline uint16_t get16(const uint8_t* p) { return uint16_t((p[0] << 8) | p[1]); }
inline uint32_t get32(const uint8_t* p) {
  return (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3];
}

// ---------------------------------------------------------------- addresses
struct Mac {
  std::array<uint8_t, 6> b{};
  static Mac broadcast() { Mac m; m.b.fill(0xFF); return m; }
  static Mac make(uint8_t a, uint8_t b_, uint8_t c, uint8_t d, uint8_t e, uint8_t f) {
    Mac m; m.b = {a, b_, c, d, e, f}; return m;
  }
  static std::optional<Mac> parse(const std::string& s) {
    unsigned v[6]; char tail;
    if (std::sscanf(s.c_str(), "%x:%x:%x:%x:%x:%x%c", &v[0], &v[1], &v[2], &v[3], &v[4], &v[5], &tail) != 6)
      return std::nullopt;
    Mac m;
    for (int i = 0; i < 6; i++) { if (v[i] > 255) return std::nullopt; m.b[i] = uint8_t(v[i]); }
    return m;
  }
  bool is_broadcast() const { for (auto x : b) if (x != 0xFF) return false; return true; }
  bool is_multicast() const { return b[0] & 1; }
  bool is_zero() const { for (auto x : b) if (x) return false; return true; }
  std::string str() const {
    char buf[18];
    std::snprintf(buf, sizeof buf, "%02x:%02x:%02x:%02x:%02x:%02x", b[0], b[1], b[2], b[3], b[4], b[5]);
    return buf;
  }
  bool operator==(const Mac& o) const { return b == o.b; }
  bool operator!=(const Mac& o) const { return b != o.b; }
  bool operator<(const Mac& o) const { return b < o.b; }
};

constexpr Ip4 make_ip(unsigned a, unsigned b, unsigned c, unsigned d) {
  return (Ip4(a) << 24) | (Ip4(b) << 16) | (Ip4(c) << 8) | Ip4(d);
}
inline std::string ip_str(Ip4 ip) {
  char buf[16];
  std::snprintf(buf, sizeof buf, "%u.%u.%u.%u", ip >> 24, (ip >> 16) & 255, (ip >> 8) & 255, ip & 255);
  return buf;
}
inline bool ip_parse(const std::string& s, Ip4& out) {
  unsigned a, b, c, d; char tail;
  if (std::sscanf(s.c_str(), "%u.%u.%u.%u%c", &a, &b, &c, &d, &tail) != 4) return false;
  if (a > 255 || b > 255 || c > 255 || d > 255) return false;
  out = make_ip(a, b, c, d);
  return true;
}

// RFC 1071 internet checksum. `init` lets callers chain a pseudo-header sum.
inline uint16_t inet_checksum(const uint8_t* p, size_t n, uint32_t init = 0) {
  uint32_t sum = init;
  for (; n > 1; p += 2, n -= 2) sum += get16(p);
  if (n) sum += uint32_t(*p) << 8;
  while (sum >> 16) sum = (sum & 0xFFFF) + (sum >> 16);
  return uint16_t(~sum);
}

// ---------------------------------------------------------------- Ethernet II
constexpr uint16_t ETH_IPV4 = 0x0800, ETH_ARP = 0x0806;
constexpr size_t ETH_HLEN = 14, ETH_MIN_FRAME = 60;  // 60 bytes + 4 FCS on the wire

struct EthernetHeader {
  Mac dst, src;
  uint16_t type = 0;
  void write(Bytes& o) const {
    o.insert(o.end(), dst.b.begin(), dst.b.end());
    o.insert(o.end(), src.b.begin(), src.b.end());
    put16(o, type);
  }
  static bool parse(const uint8_t* p, size_t n, EthernetHeader& h) {
    if (n < ETH_HLEN) return false;
    std::memcpy(h.dst.b.data(), p, 6);
    std::memcpy(h.src.b.data(), p + 6, 6);
    h.type = get16(p + 12);
    return true;
  }
};

inline Bytes make_eth_frame(const Mac& dst, const Mac& src, uint16_t type, const Bytes& payload, bool pad = true) {
  Bytes f;
  EthernetHeader{dst, src, type}.write(f);
  f.insert(f.end(), payload.begin(), payload.end());
  if (pad && f.size() < ETH_MIN_FRAME) f.resize(ETH_MIN_FRAME, 0);
  return f;
}

// ---------------------------------------------------------------- ARP (RFC 826)
constexpr uint16_t ARP_REQUEST = 1, ARP_REPLY = 2;
constexpr size_t ARP_LEN = 28;

struct ArpPacket {
  uint16_t htype = 1, ptype = ETH_IPV4;
  uint8_t hlen = 6, plen = 4;
  uint16_t oper = ARP_REQUEST;
  Mac sha; Ip4 spa = 0;
  Mac tha; Ip4 tpa = 0;

  bool is_probe() const { return oper == ARP_REQUEST && spa == 0; }  // RFC 5227 address probe
  bool is_gratuitous() const { return spa != 0 && spa == tpa; }      // announcement / gratuitous ARP
  Bytes serialize() const {
    Bytes o;
    put16(o, htype); put16(o, ptype); o.push_back(hlen); o.push_back(plen); put16(o, oper);
    o.insert(o.end(), sha.b.begin(), sha.b.end()); put32(o, spa);
    o.insert(o.end(), tha.b.begin(), tha.b.end()); put32(o, tpa);
    return o;
  }
  static bool parse(const uint8_t* p, size_t n, ArpPacket& a) {
    if (n < ARP_LEN) return false;
    a.htype = get16(p); a.ptype = get16(p + 2); a.hlen = p[4]; a.plen = p[5]; a.oper = get16(p + 6);
    if (a.hlen != 6 || a.plen != 4) return false;
    std::memcpy(a.sha.b.data(), p + 8, 6);  a.spa = get32(p + 14);
    std::memcpy(a.tha.b.data(), p + 18, 6); a.tpa = get32(p + 24);
    return true;
  }
};

// ---------------------------------------------------------------- IPv4 / TCP
constexpr uint8_t IPPROTO_TCP_ = 6, IPPROTO_UDP_ = 17, IPPROTO_ICMP_ = 1;

struct Ipv4Header {
  uint8_t ihl = 5;  // 32-bit words
  uint8_t tos = 0;
  uint16_t total_len = 0, id = 0, flags_frag = 0x4000;  // DF
  uint8_t ttl = 64, proto = 0;
  uint16_t checksum = 0;
  Ip4 src = 0, dst = 0;

  void write(Bytes& o, size_t payload_len) const {  // computes the header checksum itself
    size_t start = o.size();
    o.push_back(uint8_t(0x40 | 5)); o.push_back(tos);
    put16(o, uint16_t(20 + payload_len)); put16(o, id); put16(o, flags_frag);
    o.push_back(ttl); o.push_back(proto); put16(o, 0); put32(o, src); put32(o, dst);
    uint16_t cs = inet_checksum(o.data() + start, 20);
    o[start + 10] = uint8_t(cs >> 8); o[start + 11] = uint8_t(cs);
  }
  static bool parse(const uint8_t* p, size_t n, Ipv4Header& h) {
    if (n < 20 || (p[0] >> 4) != 4) return false;
    h.ihl = p[0] & 0x0F;
    if (h.ihl < 5 || n < size_t(h.ihl) * 4) return false;
    h.tos = p[1]; h.total_len = get16(p + 2); h.id = get16(p + 4); h.flags_frag = get16(p + 6);
    h.ttl = p[8]; h.proto = p[9]; h.checksum = get16(p + 10); h.src = get32(p + 12); h.dst = get32(p + 16);
    return true;
  }
};

constexpr uint8_t TCP_FIN = 0x01, TCP_SYN = 0x02, TCP_RST = 0x04, TCP_PSH = 0x08, TCP_ACK = 0x10, TCP_URG = 0x20;

struct TcpHeader {
  uint16_t sport = 0, dport = 0;
  uint32_t seq = 0, ack = 0;
  uint8_t flags = 0;
  uint16_t window = 64240, urg = 0;
};

inline uint32_t pseudo_sum(Ip4 src, Ip4 dst, uint8_t proto, size_t len) {
  return (src >> 16) + (src & 0xFFFF) + (dst >> 16) + (dst & 0xFFFF) + proto + uint32_t(len);
}

// Build a TCP segment (20-byte header + payload) with a correct pseudo-header checksum.
inline Bytes make_tcp_segment(const TcpHeader& h, Ip4 src, Ip4 dst, const Bytes& payload) {
  Bytes s;
  put16(s, h.sport); put16(s, h.dport); put32(s, h.seq); put32(s, h.ack);
  s.push_back(uint8_t(5 << 4)); s.push_back(h.flags); put16(s, h.window); put16(s, 0); put16(s, h.urg);
  s.insert(s.end(), payload.begin(), payload.end());
  uint16_t cs = inet_checksum(s.data(), s.size(), pseudo_sum(src, dst, IPPROTO_TCP_, s.size()));
  s[16] = uint8_t(cs >> 8); s[17] = uint8_t(cs);
  return s;
}

inline Bytes make_tcp_frame(const Mac& smac, const Mac& dmac, Ip4 sip, Ip4 dip, const TcpHeader& th,
                            const Bytes& payload, uint16_t ip_id) {
  Bytes seg = make_tcp_segment(th, sip, dip, payload), ip;
  Ipv4Header ih; ih.id = ip_id; ih.proto = IPPROTO_TCP_; ih.src = sip; ih.dst = dip;
  ih.write(ip, seg.size());
  ip.insert(ip.end(), seg.begin(), seg.end());
  return make_eth_frame(dmac, smac, ETH_IPV4, ip);
}

// ---------------------------------------------------------------- Telnet (RFC 854)
namespace tn {
constexpr uint8_t SE = 240, NOP = 241, DM = 242, BRK = 243, IP = 244, AO = 245, AYT = 246, EC = 247, EL = 248,
                  GA = 249, SB = 250, WILL = 251, WONT = 252, DO = 253, DONT = 254, IAC = 255;
constexpr uint8_t OPT_BINARY = 0, OPT_ECHO = 1, OPT_SGA = 3, OPT_STATUS = 5, OPT_TTYPE = 24, OPT_NAWS = 31,
                  OPT_TSPEED = 32, OPT_LINEMODE = 34, OPT_XDISPLOC = 35, OPT_NEWENV = 39;
constexpr uint8_t TTYPE_IS = 0, TTYPE_SEND = 1;

inline const char* verb_name(uint8_t c) {
  switch (c) {
    case WILL: return "WILL"; case WONT: return "WON'T"; case DO: return "DO"; case DONT: return "DON'T";
    case SB: return "SB"; case SE: return "SE"; case NOP: return "NOP"; case GA: return "Go Ahead";
    case AYT: return "Are You There"; case IP: return "Interrupt Process"; case EC: return "Erase Character";
    case EL: return "Erase Line"; case BRK: return "Break"; case AO: return "Abort Output"; case DM: return "Data Mark";
    default: return "Unknown";
  }
}
inline const char* opt_name(uint8_t o) {
  switch (o) {
    case OPT_BINARY: return "Binary Transmission"; case OPT_ECHO: return "Echo";
    case OPT_SGA: return "Suppress Go Ahead"; case OPT_STATUS: return "Status";
    case OPT_TTYPE: return "Terminal Type"; case OPT_NAWS: return "Negotiate About Window Size";
    case OPT_TSPEED: return "Terminal Speed"; case OPT_LINEMODE: return "Linemode";
    case OPT_XDISPLOC: return "X Display Location"; case OPT_NEWENV: return "New Environment Option";
    default: return "Unknown Option";
  }
}
inline Bytes cmd(uint8_t verb, uint8_t opt) { return {IAC, verb, opt}; }
inline Bytes sb(uint8_t opt, const Bytes& data) {
  Bytes o{IAC, SB, opt};
  for (uint8_t c : data) { o.push_back(c); if (c == IAC) o.push_back(IAC); }
  o.push_back(IAC); o.push_back(SE);
  return o;
}
inline Bytes text(const std::string& s) {  // plain data with 0xFF escaped as IAC IAC
  Bytes o;
  for (unsigned char c : s) { o.push_back(c); if (c == IAC) o.push_back(IAC); }
  return o;
}
}  // namespace tn

struct TelnetItem {
  enum Kind { Data, Command, Subneg } kind = Data;
  uint8_t cmd = 0;          // WILL/WONT/DO/DONT (or a 1-byte command) for Command; SB for Subneg
  uint8_t opt = 0;
  Bytes data;               // payload for Data / Subneg
  size_t off = 0, len = 0;  // byte range relative to the buffer start given to feed()
};

// Streaming NVT parser. State survives across feed() calls, so an IAC sequence split over TCP segments works.
class TelnetParser {
 public:
  std::vector<TelnetItem> feed(const uint8_t* p, size_t n, size_t base = 0) {
    std::vector<TelnetItem> out;
    for (size_t i = 0; i < n; i++) {
      uint8_t c = p[i]; size_t pos = base + i;
      switch (st_) {
        case DATA:
          if (c == tn::IAC) { st_ = GOT_IAC; start_ = pos; }  // may still turn out to be an escaped 0xFF data byte
          else push_data(c, pos);
          break;
        case GOT_IAC:
          if (c == tn::IAC) { push_data(0xFF, start_); dend_ = pos + 1; st_ = DATA; }  // escaped 0xFF
          else if (c == tn::WILL || c == tn::WONT || c == tn::DO || c == tn::DONT) { flush(out); verb_ = c; st_ = NEG; }
          else if (c == tn::SB) { flush(out); st_ = SB_OPT; }
          else {
            flush(out);
            TelnetItem it; it.kind = TelnetItem::Command; it.cmd = c; it.off = start_; it.len = pos - start_ + 1;
            out.push_back(it); st_ = DATA;
          }
          break;
        case NEG: {
          TelnetItem it; it.kind = TelnetItem::Command; it.cmd = verb_; it.opt = c;
          it.off = start_; it.len = pos - start_ + 1;
          out.push_back(it); st_ = DATA; break;
        }
        case SB_OPT: sbopt_ = c; sub_.clear(); st_ = SB_DATA; break;
        case SB_DATA: if (c == tn::IAC) st_ = SB_IAC; else sub_.push_back(c); break;
        case SB_IAC:
          if (c == tn::SE) {
            TelnetItem it; it.kind = TelnetItem::Subneg; it.cmd = tn::SB; it.opt = sbopt_; it.data = sub_;
            it.off = start_; it.len = pos - start_ + 1; out.push_back(it); st_ = DATA;
          } else { sub_.push_back(c); st_ = SB_DATA; }  // IAC IAC inside SB => literal 0xFF
          break;
      }
    }
    flush(out);
    return out;
  }
  bool pending() const { return st_ != DATA; }  // ended mid-sequence

 private:
  enum St { DATA, GOT_IAC, NEG, SB_OPT, SB_DATA, SB_IAC } st_ = DATA;
  uint8_t verb_ = 0, sbopt_ = 0;
  size_t start_ = 0, dstart_ = 0, dend_ = 0;
  Bytes data_, sub_;
  void push_data(uint8_t c, size_t pos) { if (data_.empty()) dstart_ = pos; data_.push_back(c); dend_ = pos + 1; }
  void flush(std::vector<TelnetItem>& out) {
    if (data_.empty()) return;
    TelnetItem it; it.kind = TelnetItem::Data; it.data = data_; it.off = dstart_; it.len = dend_ - dstart_;
    out.push_back(it); data_.clear();
  }
};

}  // namespace netlab
