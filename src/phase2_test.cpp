// Phase 2: ARP engine (cache, switch, host state machine).
#include <thread>

#include "arp_engine.hpp"
#include "test_util.hpp"

using namespace netlab;

struct Spy : LanPort {  // counts frames delivered to it
  Mac m; std::atomic<int> n{0};
  explicit Spy(Mac mac) : m(mac) {}
  Mac port_mac() const override { return m; }
  void on_frame(const Bytes&) override { n++; }
};

int main() {
  const Ip4 A = make_ip(10, 0, 0, 1), B = make_ip(10, 0, 0, 2), C = make_ip(10, 0, 0, 3);
  const Mac MA = Mac::make(2, 0, 0, 0, 0, 1), MB = Mac::make(2, 0, 0, 0, 0, 2), MC = Mac::make(2, 0, 0, 0, 0, 3);

  { // cache TTL + static
    ArpCache c(40);
    c.insert(A, MA); c.insert(B, MB, true);
    CHECK(c.lookup(A) == MA);
    std::this_thread::sleep_for(std::chrono::milliseconds(80));
    CHECK(!c.lookup(A).has_value()); CHECK(c.lookup(B) == MB);  // dynamic expired, static stays
    c.insert(B, MC);  CHECK(c.lookup(B) == MB);                  // dynamic cannot overwrite static
    c.insert(B, MC, true); CHECK(c.lookup(B) == MC);
    CHECK(c.dump().find("static") != std::string::npos);
  }
  { // resolve + cache hit + exactly one request/one reply
    VirtualLan lan; ArpHost a(lan, "a", MA, A), b(lan, "b", MB, B), c(lan, "c", MC, C);
    auto r = a.resolve(B); CHECK(r && *r == MB);
    CHECK(a.requests_sent() == 1 && b.replies_sent() == 1 && c.replies_sent() == 0);
    CHECK(b.cache().lookup(A) == MA);               // target learned the requester (RFC 826)
    CHECK(!c.cache().lookup(A).has_value());        // bystander did not
    size_t f = lan.frames(); a.resolve(B); CHECK(lan.frames() == f);  // cache hit: silent
  }
  { // unanswered -> exactly max_tries requests, then gives up
    VirtualLan lan; ArpHost a(lan, "a", MA, A);
    auto t0 = Clock::now();
    CHECK(!a.resolve(B, 30, 3).has_value());
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(Clock::now() - t0).count();
    CHECK(a.requests_sent() == 3); CHECK(ms >= 30 + 60 + 120 - 5);  // exponential backoff 30/60/120
  }
  { // switch learns MACs: after b talks, unicast to b is not flooded to c
    VirtualLan lan; ArpHost a(lan, "a", MA, A), b(lan, "b", MB, B); Spy spy(MC); lan.attach(&spy);
    a.resolve(B);                                   // broadcast request floods (spy sees it); unicast reply learned
    CHECK(spy.n == 1);
    a.send_unsolicited_reply(make_ip(9, 9, 9, 9), B, MB);  // unicast a->b, b's MAC is known => no flood
    CHECK(spy.n == 1 && lan.mac_table_size() >= 2);
    lan.detach(&spy);
  }
  { // gratuitous ARP refreshes an existing entry but never creates one
    VirtualLan lan; ArpHost a(lan, "a", MA, A), b(lan, "b", MB, B), c(lan, "c", MC, C);
    a.resolve(C);  // a knows C
    c.set_ip(C); ArpHost c2(lan, "c2", Mac::make(2, 0, 0, 0, 0, 0x33), C);  // C's address now also claimed by c2
    c2.announce();
    CHECK(!b.cache().lookup(C).has_value());                       // b had no entry -> not created
    CHECK(a.cache().lookup(C) == Mac::make(2, 0, 0, 0, 0, 0x33));  // a's entry refreshed
    bool conflict = false; for (auto& e : c.events()) if (e.find("CONFLICT") != std::string::npos) conflict = true;
    CHECK(conflict);                                               // the real owner noticed the duplicate IP
  }
  { // RFC 5227 probe: free address vs address in use
    VirtualLan lan; ArpHost a(lan, "a", MA, A), b(lan, "b", MB, B);
    CHECK(a.probe(make_ip(10, 0, 0, 77), 60));     // nobody owns it
    CHECK(!a.probe(B, 200));                       // b answers -> conflict
    CHECK(!a.cache().lookup(0).has_value());       // probe replies never poison the cache with 0.0.0.0
  }
  { // proxy ARP
    VirtualLan lan; ArpHost a(lan, "a", MA, A), gw(lan, "gw", MB, B);
    gw.add_proxy(make_ip(172, 16, 0, 9));
    CHECK(a.resolve(make_ip(172, 16, 0, 9)) == MB);
  }
  { // poisoning: dynamic entry is hijacked, static entry survives, hardened host refuses to create new entries
    VirtualLan lan; ArpHost a(lan, "a", MA, A), gw(lan, "gw", MB, B), evil(lan, "evil", MC, C), s(lan, "s", Mac::make(2, 0, 0, 0, 0, 4), make_ip(10, 0, 0, 4));
    a.resolve(B); s.cache().insert(B, MB, true);
    evil.send_unsolicited_reply(B, A, MA); evil.send_unsolicited_reply(B, s.ip(), s.mac());
    CHECK(a.cache().lookup(B) == MC);              // poisoned
    CHECK(s.cache().lookup(B) == MB && !s.events().empty());  // protected
    evil.send_unsolicited_reply(make_ip(10, 9, 9, 9), s.ip(), s.mac());
    CHECK(!s.cache().lookup(make_ip(10, 9, 9, 9)).has_value());
    s.set_learn_unsolicited(true);
    evil.send_unsolicited_reply(make_ip(10, 9, 9, 9), s.ip(), s.mac());
    CHECK(s.cache().lookup(make_ip(10, 9, 9, 9)).has_value());  // permissive mode learns it
  }
  { // 100% loss -> resolution fails; 0% -> works again
    VirtualLan lan; ArpHost a(lan, "a", MA, A), b(lan, "b", MB, B);
    lan.set_loss_percent(100); CHECK(!a.resolve(B, 20, 2).has_value()); CHECK(lan.dropped() >= 2);
    lan.set_loss_percent(0); CHECK(a.resolve(B, 50, 2).has_value());
  }
  { // malformed input must never crash a host
    VirtualLan lan; ArpHost a(lan, "a", MA, A);
    a.on_frame({}); a.on_frame(Bytes(13, 0)); a.on_frame(make_eth_frame(Mac::broadcast(), MB, ETH_ARP, Bytes(10, 1), false));
    Bytes junk = make_eth_frame(Mac::broadcast(), MB, ETH_ARP, ArpPacket{}.serialize()); junk[14 + 4] = 99; a.on_frame(junk);
    CHECK(a.cache().size() == 0);
  }
  TEST_MAIN_END("phase2");
}
