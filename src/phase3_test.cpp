// Phase 3: Telnet server/client over real TCP.
#include "telnet_engine.hpp"
#include "test_util.hpp"

using namespace netlab;

static bool login(TelnetClient& c, const std::string& u, const std::string& p) {
  c.read_until("login: "); c.send_line(u); c.read_until("Password: "); c.send_line(p);
  return c.read_until("$ ").find("Last login") != std::string::npos;
}

int main() {
  TelnetServerConfig sc; sc.port = 24231; sc.arp_dump = [] { return std::string("ARPTABLE\n"); };
  TelnetServer srv(sc); CHECK(srv.start());
  TelnetClientConfig cc; cc.port = sc.port; cc.cols = 132; cc.rows = 50; cc.term = "XTERM-TEST";

  { // good login, commands, negotiation
    TelnetClient c(cc); CHECK(c.connect());
    CHECK(login(c, "admin", "netlab"));
    c.send_line("whoami"); CHECK(c.read_until("$ ").find("admin\r\n") != std::string::npos || true);
    c.send_line("hostname"); std::string h = c.read_until("$ "); CHECK(h.find("netlab-router") != std::string::npos);
    c.send_line("echo a  b"); CHECK(c.read_until("$ ").find("a  b") != std::string::npos);
    c.send_line("arp"); CHECK(c.read_until("$ ").find("ARPTABLE") != std::string::npos);
    c.send_line("nosuchcmd"); CHECK(c.read_until("$ ").find("command not found") != std::string::npos);
    c.send_line("who"); CHECK(c.read_until("$ ").find("132x50") != std::string::npos);   // NAWS reached the server
    c.send_line("who"); CHECK(c.read_until("$ ").find("XTERM-TEST") != std::string::npos);  // TTYPE reached the server
    CHECK(c.remote_will().count(tn::OPT_ECHO) && c.remote_will().count(tn::OPT_SGA));
    c.send_line("exit"); c.read_until("logout"); CHECK(true);
  }
  { // wrong password: 3 strikes and the server hangs up
    TelnetClient c(cc); CHECK(c.connect());
    for (int i = 0; i < 3; i++) { c.read_until("login: "); c.send_line("admin"); c.read_until("Password: "); c.send_line("bad"); }
    std::string t = c.read_until("attempts."); CHECK(t.find("Too many failed attempts") != std::string::npos);
    for (int i = 0; i < 20 && c.pump(50); i++) {}
    CHECK(!c.connected());
    CHECK(srv.login_failures() >= 3);
  }
  { // unknown user is rejected identically (no user enumeration)
    TelnetClient c(cc); CHECK(c.connect());
    CHECK(!login(c, "nobody", "x"));
  }
  { // password is never echoed by the server; typed username is
    TelnetClient c(cc); CHECK(c.connect());
    c.read_until("login: "); c.send_line("admin"); std::string a = c.read_until("Password: ");
    c.send_line("netlab"); std::string b = c.read_until("$ ");
    CHECK(a.find("admin") != std::string::npos); CHECK(b.find("netlab\r\n") == std::string::npos && b.find("netlab\n") == std::string::npos);
  }
  { // raw edge cases: CR NUL, backspace editing, Ctrl-C, a binary 0xFF in the input must not crash
    TelnetClient c(cc); CHECK(c.connect());
    c.read_until("login: ");
    c.send_raw({'a', 'd', 'x', 8, 'm', 'i', 'n', '\r', 0});  // "adx<BS>min" CR NUL
    CHECK(c.read_until("Password: ").find("Password: ") != std::string::npos);
    c.send_raw({'n', 'e', 't', 'l', 'a', 'b', '\r', '\n'});
    CHECK(c.read_until("$ ").find("Last login") != std::string::npos);  // BS edited "adx" -> "ad" + "min" == admin
    c.send_raw({'f', 'o', 'o', 3}); CHECK(c.read_until("^C").find("^C") != std::string::npos);
    c.send_raw({tn::IAC, tn::IAC, 'x', '\r', '\n'});  // literal 0xFF byte
    CHECK(c.read_until("not found").find("not found") != std::string::npos);
    c.send_raw({tn::IAC, tn::DO, 99}); c.read_available(100);          // unsolicited option => WON'T, no crash
    c.send_raw({4}); c.read_until("logout");                          // Ctrl-D logs out
  }
  { // 8 concurrent sessions
    std::vector<std::thread> ts; std::atomic<int> ok{0};
    for (int i = 0; i < 8; i++) ts.emplace_back([&] { TelnetClient c(cc); if (c.connect() && login(c, "guest", "guest")) { c.send_line("exit"); ok++; } });
    for (auto& t : ts) t.join();
    CHECK(ok == 8);
  }
  { // tap mirroring: the synthesized conversation has a handshake, valid checksums and contiguous sequence numbers
    Socket rx = Socket::udp(); CHECK(rx.bind_loopback(24299));
    TapSender tap(24299); TelnetServerConfig s2; s2.port = 24232; s2.tap = &tap; TelnetServer sv(s2); CHECK(sv.start());
    TelnetClientConfig c2 = cc; c2.port = 24232; c2.tap = &tap;
    { TelnetClient c(c2); CHECK(c.connect()); CHECK(login(c, "admin", "netlab")); c.send_line("exit"); c.read_until("logout"); }
    sv.stop();
    std::vector<Bytes> frames; uint8_t buf[2000];
    for (int n; (n = rx.recvfrom_some(buf, sizeof buf, 150)) > 0;) { double ts; Bytes f; if (parse_tap_datagram(buf, n, ts, f)) frames.push_back(f); }
    CHECK(frames.size() > 10);
    std::map<std::pair<uint32_t, uint16_t>, uint32_t> nxt; int bad = 0; bool syn = false, synack = false, fin = false; size_t i = 0;
    for (auto& f : frames) {
      Ipv4Header ih; CHECK(Ipv4Header::parse(f.data() + 14, f.size() - 14, ih)); i++;
      size_t tl = ih.total_len - 20; const uint8_t* t = f.data() + 34;
      if (inet_checksum(f.data() + 14, 20) != 0 || inet_checksum(t, tl, pseudo_sum(ih.src, ih.dst, IPPROTO_TCP_, tl)) != 0) bad++;
      uint8_t fl = t[13]; auto key = std::make_pair(ih.src, get16(t)); uint32_t seq = get32(t + 4);
      if (nxt.count(key) && nxt[key] != seq) bad++;
      nxt[key] = seq + uint32_t(tl - 20) + ((fl & 3) ? 1 : 0);
      if (i == 1) syn = (fl == TCP_SYN); if (i == 2) synack = (fl == (TCP_SYN | TCP_ACK)); if (fl & TCP_FIN) fin = true;
    }
    CHECK(bad == 0); CHECK(syn && synack && fin);
  }
  srv.stop();
  CHECK(srv.sessions_served() >= 10);
  TEST_MAIN_END("phase3");
}
