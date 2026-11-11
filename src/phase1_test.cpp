// Phase 1: wire formats, checksums, Telnet parser, sockets and tap datagrams.
#include <thread>

#include "net_io.hpp"
#include "test_util.hpp"

using namespace netlab;

int main() {
  // addresses
  CHECK(ip_str(make_ip(192, 168, 1, 10)) == "192.168.1.10");
  Ip4 ip; CHECK(ip_parse("10.0.0.50", ip) && ip == make_ip(10, 0, 0, 50));
  CHECK(!ip_parse("10.0.0.256", ip)); CHECK(!ip_parse("10.0.0", ip)); CHECK(!ip_parse("1.2.3.4x", ip));
  auto m = Mac::parse("02:00:00:00:00:a1"); CHECK(m && m->str() == "02:00:00:00:00:a1");
  CHECK(!Mac::parse("02:00:00:00:00")); CHECK(!Mac::parse("zz:00:00:00:00:00")); CHECK(Mac::broadcast().is_broadcast());

  // ARP round trip (exact wire bytes per RFC 826)
  ArpPacket a; a.oper = ARP_REQUEST; a.sha = *m; a.spa = make_ip(192, 168, 1, 10); a.tpa = make_ip(192, 168, 1, 1);
  Bytes w = a.serialize();
  CHECK(w.size() == ARP_LEN);
  const uint8_t expect[] = {0, 1, 8, 0, 6, 4, 0, 1, 2, 0, 0, 0, 0, 0xa1, 192, 168, 1, 10, 0, 0, 0, 0, 0, 0, 192, 168, 1, 1};
  CHECK(w == Bytes(expect, expect + sizeof expect));
  ArpPacket b; CHECK(ArpPacket::parse(w.data(), w.size(), b) && b.oper == ARP_REQUEST && b.spa == a.spa && b.tpa == a.tpa && b.sha == a.sha);
  CHECK(!ArpPacket::parse(w.data(), 27, b));  // truncated
  Bytes bad = w; bad[4] = 8; CHECK(!ArpPacket::parse(bad.data(), bad.size(), b));  // hlen != 6
  ArpPacket g = a; g.tpa = g.spa; CHECK(g.is_gratuitous() && !a.is_gratuitous());
  ArpPacket pr = a; pr.spa = 0; CHECK(pr.is_probe());

  // Ethernet padding
  Bytes fr = make_eth_frame(Mac::broadcast(), *m, ETH_ARP, w);
  CHECK(fr.size() == 60); EthernetHeader eh; CHECK(EthernetHeader::parse(fr.data(), fr.size(), eh) && eh.type == ETH_ARP && eh.dst.is_broadcast());
  CHECK(!EthernetHeader::parse(fr.data(), 13, eh));

  // IPv4 header checksum: summing a valid header gives 0
  Bytes ipb; Ipv4Header ih; ih.src = make_ip(1, 2, 3, 4); ih.dst = make_ip(5, 6, 7, 8); ih.proto = IPPROTO_TCP_; ih.write(ipb, 0);
  CHECK(ipb.size() == 20 && inet_checksum(ipb.data(), 20) == 0);
  Ipv4Header ip2; CHECK(Ipv4Header::parse(ipb.data(), ipb.size(), ip2) && ip2.src == ih.src && ip2.proto == IPPROTO_TCP_);
  // known vector from RFC 1071-style header: 4500 0073 0000 4000 4011 b861 c0a8 0001 c0a8 00c7
  const uint8_t kv[] = {0x45,0,0,0x73,0,0,0x40,0,0x40,0x11,0xb8,0x61,0xc0,0xa8,0,1,0xc0,0xa8,0,0xc7};
  CHECK(inet_checksum(kv, 20) == 0);

  // TCP frame: checksum valid, flags/seq/ack preserved
  TcpHeader th; th.sport = 40000; th.dport = 23; th.seq = 100; th.ack = 200; th.flags = TCP_PSH | TCP_ACK;
  Bytes tf = make_tcp_frame(*m, Mac::broadcast(), ih.src, ih.dst, th, Bytes{'h', 'i', '!'}, 7);
  CHECK(tf.size() == 60);  // 14+20+20+3 = 57 -> padded
  const uint8_t* seg = tf.data() + 34;
  CHECK(get16(seg) == 40000 && get16(seg + 2) == 23 && get32(seg + 4) == 100 && get32(seg + 8) == 200 && seg[13] == 0x18);
  CHECK(inet_checksum(seg, 23, pseudo_sum(ih.src, ih.dst, IPPROTO_TCP_, 23)) == 0);
  Bytes odd = make_tcp_frame(*m, Mac::broadcast(), ih.src, ih.dst, th, Bytes(101, 'x'), 8);  // odd payload length
  CHECK(inet_checksum(odd.data() + 34, 20 + 101, pseudo_sum(ih.src, ih.dst, IPPROTO_TCP_, 121)) == 0);

  // Telnet parser
  TelnetParser p;
  Bytes s1 = {'h', 'i', tn::IAC, tn::WILL, tn::OPT_ECHO, 'x', tn::IAC, tn::IAC, 'y'};
  auto it = p.feed(s1.data(), s1.size());
  CHECK(it.size() == 3 && it[0].kind == TelnetItem::Data && it[0].data.size() == 2);
  CHECK(it[1].kind == TelnetItem::Command && it[1].cmd == tn::WILL && it[1].opt == tn::OPT_ECHO && it[1].off == 2 && it[1].len == 3);
  CHECK(it[2].data.size() == 3 && it[2].data[1] == 0xFF);  // x, 0xFF, y
  Bytes sb = tn::sb(tn::OPT_NAWS, {0, 80, 0, 24});
  it = p.feed(sb.data(), sb.size());
  CHECK(it.size() == 1 && it[0].kind == TelnetItem::Subneg && it[0].opt == tn::OPT_NAWS && it[0].data.size() == 4 && get16(&it[0].data[0]) == 80);
  // an IAC sequence split across two TCP segments
  Bytes full = {tn::IAC, tn::DO, tn::OPT_TTYPE}; TelnetParser q;
  auto r1 = q.feed(full.data(), 2); CHECK(r1.empty() && q.pending());
  auto r2 = q.feed(full.data() + 2, 1); CHECK(r2.size() == 1 && r2[0].cmd == tn::DO && r2[0].opt == tn::OPT_TTYPE && !q.pending());
  // 0xFF inside a subnegotiation is doubled
  Bytes sb2 = tn::sb(tn::OPT_TTYPE, {0, 0xFF, 'A'}); TelnetParser q2; auto r3 = q2.feed(sb2.data(), sb2.size());
  CHECK(r3.size() == 1 && r3[0].data.size() == 3 && r3[0].data[1] == 0xFF);
  CHECK(tn::text(std::string("a\xFF")) == (Bytes{'a', 0xFF, 0xFF}));

  // tap datagram
  Bytes d = make_tap_datagram(fr, 1234.5); double ts; Bytes back;
  CHECK(parse_tap_datagram(d.data(), d.size(), ts, back) && back == fr && ts > 1234.49 && ts < 1234.51);
  d[0] = 'X'; CHECK(!parse_tap_datagram(d.data(), d.size(), ts, back));

  // UDP loopback
  Socket rx = Socket::udp(); CHECK(rx.bind_loopback(0)); uint16_t port = rx.local_port(); CHECK(port != 0);
  Socket tx = Socket::udp(); uint8_t msg[] = {1, 2, 3}; CHECK(tx.sendto_loopback(port, msg, 3));
  uint8_t buf[16]; CHECK(rx.recvfrom_some(buf, sizeof buf, 500) == 3 && buf[2] == 3);
  CHECK(rx.recvfrom_some(buf, sizeof buf, 30) == RECV_TIMEOUT);
  // TCP loopback
  Socket ls = Socket::tcp(); CHECK(ls.bind_loopback(0) && ls.listen()); uint16_t lp = ls.local_port();
  std::thread t([&] { Socket c = Socket::tcp(); c.connect_loopback(lp); const uint8_t z[] = {9, 8, 7}; c.send_all(z, 3); });
  Socket acc = ls.accept(1000); CHECK(acc.valid());
  CHECK(acc.recv_some(buf, sizeof buf, 1000) == 3 && buf[0] == 9);
  t.join(); CHECK(acc.recv_some(buf, sizeof buf, 1000) == 0);  // peer closed

  TEST_MAIN_END("phase1");
}
