// Scripted scenarios shared by the CLI tools and the GUI's one-click "Run ARP+Telnet Demo" button.
#pragma once
#include <thread>

#include "arp_engine.hpp"
#include "telnet_engine.hpp"

namespace netlab {

using Say = std::function<void(const std::string&)>;
inline void sleep_ms(int ms) { std::this_thread::sleep_for(std::chrono::milliseconds(ms)); }

// Everything ARP can do on one simulated segment. Returns alice's final ARP cache (for the Telnet `arp` command).
inline std::string run_arp_demo(TapSender* tap, const Say& say, std::shared_ptr<std::string>* final_cache = nullptr) {
  VirtualLan lan;
  lan.set_tap(tap);
  const Ip4 A = make_ip(192, 168, 1, 10), B = make_ip(192, 168, 1, 20), GW = make_ip(192, 168, 1, 1), ATK = make_ip(192, 168, 1, 66);
  ArpHost alice(lan, "alice", Mac::make(2, 0, 0, 0, 0, 0xA1), A);

  say("[1] alice probes " + ip_str(A) + " (RFC 5227, sender IP 0.0.0.0) before using it");
  say(alice.probe(A, 150) ? "    no reply -> address is free" : "    CONFLICT");
  alice.announce();
  say("[2] alice announces herself with a gratuitous ARP");

  ArpHost gw(lan, "gateway", Mac::make(2, 0, 0, 0, 0, 0x01), GW);
  ArpHost bob(lan, "bob", Mac::make(2, 0, 0, 0, 0, 0xB2), B);
  bob.cache().insert(GW, gw.mac(), /*static=*/true);  // bob's hardening against spoofing

  say("[3] alice resolves the gateway and bob (broadcast request, unicast reply)");
  auto m1 = alice.resolve(GW), m2 = alice.resolve(B);
  say("    " + ip_str(GW) + " is at " + (m1 ? m1->str() : "?") + ",  " + ip_str(B) + " is at " + (m2 ? m2->str() : "?"));
  size_t f0 = lan.frames();
  alice.resolve(GW);
  say(std::string("    second lookup of the gateway used the cache: ") + (lan.frames() == f0 ? "0 new frames" : "unexpected traffic"));

  say("[4] alice asks for 192.168.1.99 - nobody answers, so she retries with exponential backoff (80/160/320 ms)");
  auto none = alice.resolve(make_ip(192, 168, 1, 99), 80, 3);
  say(none ? "    unexpected answer" : "    resolution failed after 3 requests");

  say("[5] proxy ARP: the gateway answers for 10.0.0.50 on behalf of a remote host");
  gw.add_proxy(make_ip(10, 0, 0, 50));
  auto pm = alice.resolve(make_ip(10, 0, 0, 50));
  say("    10.0.0.50 is at " + (pm ? pm->str() : std::string("?")) + " (the gateway's MAC)");

  ArpHost mallory(lan, "mallory", Mac::make(2, 0, 0, 0, 0, 0x66), ATK);
  say("[6] duplicate-IP detection: mallory claims " + ip_str(A));
  mallory.set_ip(A);
  mallory.announce();
  mallory.set_ip(ATK);
  for (auto& e : alice.events()) say("    alice: " + e);

  say("[7] ARP cache poisoning: mallory tells alice and bob that the gateway is at HER MAC");
  mallory.send_unsolicited_reply(GW, A, alice.mac());
  mallory.send_unsolicited_reply(GW, B, bob.mac());
  auto am = alice.cache().lookup(GW);
  say("    alice now thinks the gateway is at " + (am ? am->str() : "?") + (am && *am == mallory.mac() ? "  <-- POISONED" : ""));
  auto bm = bob.cache().lookup(GW);
  say("    bob still has " + (bm ? bm->str() : "?") + (bm && *bm == gw.mac() ? "  (static entry held)" : ""));
  for (auto& e : bob.events()) say("    bob: " + e);

  std::string dump = alice.cache().dump();
  say("[8] alice's final ARP cache:\n" + dump);
  say("    frames on the segment: " + std::to_string(lan.frames()) + ", switch MAC table: " + std::to_string(lan.mac_table_size()) + " entries");
  if (final_cache) *final_cache = std::make_shared<std::string>(dump);
  return dump;
}

// A full Telnet session: negotiation, one failed login, a successful one, a few commands, logout.
inline bool run_telnet_demo(TapSender* tap, const std::string& arp_text, const Say& say, uint16_t port = 2323) {
  TelnetServerConfig sc; sc.port = port; sc.tap = tap;
  sc.arp_dump = [arp_text] { return arp_text; };
  TelnetServer srv(sc);
  if (!srv.start()) { say("telnet: cannot listen on 127.0.0.1:" + std::to_string(port) + " (port busy?)"); return false; }
  TelnetClientConfig cc; cc.port = port; cc.tap = tap;
  TelnetClient cl(cc);
  if (!cl.connect()) { say("telnet: connect failed"); return false; }
  auto show = [&](const std::string& t) { std::string s = t; while (!s.empty() && (s.back() == '\n' || s.back() == ' ')) s.pop_back(); if (!s.empty()) say("    " + s); };
  say("[9] telnet: client connects to the server (SYN, SYN/ACK, ACK) and negotiates options");
  show(cl.read_until("login: "));
  say("[10] first login attempt with a WRONG password (everything is sent in clear text!)");
  cl.send_line("guest"); show(cl.read_until("Password: "));
  cl.send_line("hunter2"); show(cl.read_until("login: "));
  say("[11] second attempt succeeds");
  cl.send_line("admin"); show(cl.read_until("Password: "));
  cl.send_line("netlab"); show(cl.read_until("$ "));
  for (const char* c : {"hostname", "whoami", "arp", "echo hello from telnet", "who"}) {
    cl.send_line(c); show(cl.read_until("$ "));
  }
  cl.send_line("exit"); show(cl.read_until("logout"));
  sleep_ms(150);
  cl.close();
  for (auto& l : cl.negotiation_log()) say("    option " + l);
  say("    server sessions served: " + std::to_string(srv.sessions_served()) + ", failed logins: " + std::to_string(srv.login_failures()));
  srv.stop();
  return true;
}

}  // namespace netlab
