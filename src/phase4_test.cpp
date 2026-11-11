// Phase 4: dissector, display filter, pcap round trip, capture session.
#include <cstdlib>
#include <random>

#include "capture_session.hpp"
#include "dissector.hpp"
#include "telnet_engine.hpp"
#include "test_util.hpp"

using namespace netlab;

static const Mac MA = Mac::make(2, 0, 0, 0, 0, 0xA1), MB = Mac::make(2, 0, 0, 0, 0, 0xB1);
static const Ip4 IA = make_ip(192, 168, 1, 10), IB = make_ip(192, 168, 1, 1);

static Bytes arp_frame(uint16_t op, Ip4 spa, Ip4 tpa, bool bcast) {
  ArpPacket a; a.oper = op; a.sha = MA; a.spa = spa; a.tpa = tpa; if (op == ARP_REPLY) a.tha = MB;
  return make_eth_frame(bcast ? Mac::broadcast() : MB, MA, ETH_ARP, a.serialize());
}
static Bytes tcp_frame(uint8_t flags, const Bytes& payload, bool c2s = true, uint16_t cp = 40000) {
  TcpHeader h; h.sport = c2s ? cp : 23; h.dport = c2s ? 23 : cp; h.seq = 1000; h.ack = 2000; h.flags = flags;
  return c2s ? make_tcp_frame(MA, MB, IA, IB, h, payload, 1) : make_tcp_frame(MB, MA, IB, IA, h, payload, 1);
}
static bool has(const Dissected& d, const std::string& needle) {
  std::function<bool(const std::vector<Node>&)> f = [&](const std::vector<Node>& v) {
    for (auto& n : v) if (n.text.find(needle) != std::string::npos || f(n.kids)) return true;
    return false;
  };
  return f(d.tree);
}
static void ranges_ok(const Dissected& d, bool& ok) {  // every node's byte range must lie inside the frame
  std::function<void(const std::vector<Node>&)> f = [&](const std::vector<Node>& v) {
    for (auto& n : v) { if (n.off >= 0 && (n.len < 0 || size_t(n.off + n.len) > d.caplen)) ok = false; f(n.kids); }
  };
  f(d.tree);
}

int main() {
  { // ARP variants
    Dissected d = dissect(arp_frame(ARP_REQUEST, IA, IB, true), 1, 1000);
    CHECK(d.proto == "ARP" && d.color == Color::Arp && d.info == "Who has 192.168.1.1? Tell 192.168.1.10" && d.dst == "Broadcast");
    CHECK(has(d, "Opcode: request (1)") && has(d, "Trailer: 18 bytes"));
    d = dissect(arp_frame(ARP_REPLY, IB, IA, false), 2, 1000); CHECK(d.info == "192.168.1.1 is at 02:00:00:00:00:a1");
    d = dissect(arp_frame(ARP_REQUEST, IA, IA, true), 3, 1000); CHECK(d.arp_gratuitous && d.info == "Gratuitous ARP for 192.168.1.10 (Request)" && has(d, "Is gratuitous"));
    d = dissect(arp_frame(ARP_REQUEST, 0, IA, true), 4, 1000); CHECK(d.arp_probe && d.info.find("ARP Probe") == 0 && has(d, "Is probe"));
  }
  { // TCP + Telnet
    Dissected d = dissect(tcp_frame(TCP_SYN, {}), 1, 1000);
    CHECK(d.proto == "TCP" && d.color == Color::TcpCtl && d.info.find("[SYN]") != std::string::npos && d.has_tcp && d.sport == 40000 && d.dport == 23);
    d = dissect(tcp_frame(TCP_PSH | TCP_ACK, Bytes{'a', 'd', 'm', 'i', 'n', '\r', '\n'}), 2, 1000);
    CHECK(d.proto == "Telnet" && d.color == Color::Telnet && d.info == "Data: admin\\r\\n");
    Bytes neg = tn::cmd(tn::WILL, tn::OPT_ECHO), n2 = tn::sb(tn::OPT_NAWS, {0, 80, 0, 24}), n3 = tn::sb(tn::OPT_TTYPE, {0, 'V', 'T'});
    neg.insert(neg.end(), n2.begin(), n2.end()); neg.insert(neg.end(), n3.begin(), n3.end());
    d = dissect(tcp_frame(TCP_PSH | TCP_ACK, neg, false), 3, 1000);
    CHECK(d.info == "WILL Echo, Suboption: Negotiate About Window Size 80x24, Suboption: Terminal Type IS \"VT\"");
    CHECK(has(d, "Width: 80") && has(d, "Height: 24") && has(d, "Terminal type: VT"));
    bool ok = true; ranges_ok(d, ok); CHECK(ok);
    // Telnet node ranges point at the real payload bytes
    Bytes f = tcp_frame(TCP_PSH | TCP_ACK, Bytes{tn::IAC, tn::DO, tn::OPT_SGA}, false);
    d = dissect(f, 4, 1000); const Node* tel = nullptr; for (auto& n : d.tree) if (n.text == "Telnet") tel = &n;
    CHECK(tel && tel->off == 54 && tel->len == 3 && tel->kids.size() == 1 && f[size_t(tel->kids[0].off)] == tn::IAC && tel->kids[0].len == 3);
    // IAC split across segments => flagged, not crashed
    d = dissect(tcp_frame(TCP_PSH | TCP_ACK, Bytes{'x', tn::IAC, tn::DO}), 5, 1000); CHECK(d.info.find("[partial IAC]") != std::string::npos);
  }
  { // corruption is reported, never crashes
    Bytes f = tcp_frame(TCP_ACK, Bytes{'h', 'i'}); f[14 + 8] ^= 0x01;  // TTL changed -> IP checksum wrong
    Dissected d = dissect(f, 1, 0); CHECK(d.color == Color::Error && d.info.find("checksum") != std::string::npos);
    f = tcp_frame(TCP_ACK, Bytes{'h', 'i'}); f[34 + 21] ^= 0x40;  // payload byte flipped -> TCP checksum wrong
    d = dissect(f, 1, 0); CHECK(d.color == Color::Error && d.info.find("bad TCP checksum") != std::string::npos);
    Bytes arp = arp_frame(ARP_REQUEST, IA, IB, true); arp.resize(30); d = dissect(arp, 1, 0); CHECK(d.color == Color::Error);
    CHECK(dissect(Bytes(5, 0), 1, 0).color == Color::Error);
    CHECK(dissect({}, 1, 0).color == Color::Error);
    Bytes unk = make_eth_frame(MB, MA, 0x88B5, Bytes(10, 1)); CHECK(dissect(unk, 1, 0).info == "Ethernet type 0x88b5");
  }
  { // fuzz: 20000 random / mutated frames must not crash, and all byte ranges must stay in bounds
    std::mt19937 rng(7); bool ok = true;
    std::vector<Bytes> seeds = {arp_frame(ARP_REQUEST, IA, IB, true), tcp_frame(TCP_ACK | TCP_PSH, tn::sb(tn::OPT_NAWS, {0, 80, 0, 24})), tcp_frame(TCP_SYN, {})};
    for (int i = 0; i < 20000; i++) {
      Bytes f;
      if (i % 2) { f.resize(rng() % 120); for (auto& b : f) b = uint8_t(rng()); }
      else { f = seeds[rng() % seeds.size()]; for (int k = 0, n = 1 + rng() % 4; k < n; k++) f[rng() % f.size()] = uint8_t(rng()); if (rng() % 4 == 0) f.resize(rng() % f.size()); }
      Dissected d = dissect(f, 1, 0); ranges_ok(d, ok);
    }
    CHECK(ok);
  }
  { // display filters
    std::vector<Dissected> v = {dissect(arp_frame(ARP_REQUEST, IA, IB, true), 1, 0), dissect(tcp_frame(TCP_SYN, {}), 2, 0),
                                dissect(tcp_frame(TCP_PSH | TCP_ACK, Bytes{'x'}, false), 3, 0), dissect(arp_frame(ARP_REPLY, IB, IA, false), 4, 0)};
    auto run = [&](const std::string& expr) { DisplayFilter f; std::string err; std::string out;
      if (!f.compile(expr, &err)) return std::string("ERR"); for (auto& d : v) if (f.match(d)) out += char('0' + d.no); return out; };
    CHECK(run("") == "1234"); CHECK(run("arp") == "14"); CHECK(run("telnet") == "3"); CHECK(run("tcp") == "23");
    CHECK(run("ip == 192.168.1.1") == "23"); CHECK(run("ip.src == 192.168.1.10") == "2"); CHECK(run("ip.dst == 192.168.1.10") == "3");
    CHECK(run("port == 23") == "23"); CHECK(run("tcp.srcport == 23") == "3"); CHECK(run("port == 40000 && !telnet") == "2");
    CHECK(run("arp.opcode == 2") == "4"); CHECK(run("arp.opcode != 2 && arp") == "1");
    CHECK(run("arp.src.proto_ipv4 == 192.168.1.1") == "4"); CHECK(run("eth.src == 02:00:00:00:00:b1") == "3");
    CHECK(run("arp || telnet") == "134"); CHECK(run("(arp or tcp) and not telnet") == "124"); CHECK(run("!arp") == "23");
    CHECK(run("tcp.flags.syn") == "2"); CHECK(run("!(arp || tcp)") == "");
    for (const char* bad : {"foo", "arp &&", "(arp", "arp)", "ip == notanip", "port ==", "== 3", "arp @ tcp", "&& arp"}) CHECK(run(bad) == "ERR");
  }
  { // pcap: write -> read -> identical; hand-checked header; bad files rejected
    std::vector<CapturedPacket> v;
    for (int i = 0; i < 5; i++) { CapturedPacket p; p.no = i + 1; p.ts = 1700000000.25 + i; p.frame = i % 2 ? tcp_frame(TCP_SYN, {}) : arp_frame(ARP_REQUEST, IA, IB, true); v.push_back(p); }
    std::string path = "netlab_t4.pcap"; CHECK(write_pcap(path, v));
    FILE* f = std::fopen(path.c_str(), "rb"); uint8_t h[24]; CHECK(f && std::fread(h, 1, 24, f) == 24); if (f) std::fclose(f);
    CHECK(h[0] == 0xD4 && h[1] == 0xC3 && h[2] == 0xB2 && h[3] == 0xA1 && h[4] == 2 && h[6] == 4 && h[20] == 1);  // magic, v2.4, LINKTYPE_ETHERNET
    std::vector<CapturedPacket> r; std::string err; CHECK(read_pcap(path, r, &err) && r.size() == 5);
    bool same = r.size() == 5; for (size_t i = 0; same && i < 5; i++) same = r[i].frame == v[i].frame && std::abs(r[i].ts - v[i].ts) < 1e-5 && r[i].no == i + 1; CHECK(same);
    FILE* g = std::fopen("netlab_bad.pcap", "wb"); std::fputs("this is not a pcap file at all.....", g); std::fclose(g);
    CHECK(!read_pcap("netlab_bad.pcap", r, &err)); CHECK(!read_pcap("does_not_exist.pcap", r, &err));
    // truncated record
    FILE* a = std::fopen(path.c_str(), "rb"); Bytes all(4096); size_t n = std::fread(all.data(), 1, all.size(), a); std::fclose(a);
    FILE* b = std::fopen("netlab_trunc.pcap", "wb"); std::fwrite(all.data(), 1, n - 7, b); std::fclose(b);
    CHECK(!read_pcap("netlab_trunc.pcap", r, &err));
  }
  { // live capture session end-to-end through the tap
    CaptureSession cap(24298); std::string err; CHECK(cap.start(&err));
    CaptureSession dup(24298); CHECK(!dup.start());  // port already taken -> reported, not crashed
    TapSender tap(24298); int cb = 0; cap.set_on_packet([&] { cb++; });
    for (int i = 0; i < 50; i++) tap.emit(arp_frame(ARP_REQUEST, IA, IB, true));
    for (int i = 0; i < 40 && cap.size() < 50; i++) std::this_thread::sleep_for(std::chrono::milliseconds(25));
    CHECK(cap.size() == 50 && cb == 50);
    auto tail = cap.snapshot(40); CHECK(tail.size() == 10 && tail[0].no == 41);
    uint8_t junk[] = {1, 2, 3}; Socket s = Socket::udp(); s.sendto_loopback(24298, junk, 3);  // garbage datagrams are ignored
    std::this_thread::sleep_for(std::chrono::milliseconds(150)); CHECK(cap.size() == 50);
    cap.clear(); CHECK(cap.size() == 0); cap.stop(); CHECK(!cap.running());
  }
  TEST_MAIN_END("phase4");
}
