// arp_lab - scripted ARP demo or an interactive ARP shell on a simulated Ethernet segment.
//   arp_lab [--tap-port 9998]               run the full scripted scenario
//   arp_lab --interactive [--tap-port N]    shell: resolve/cache/announce/probe/spoof/proxy/loss/flush
#include <iostream>
#include <memory>

#include "demos.hpp"

using namespace netlab;

int main(int argc, char** argv) {
  uint16_t tap_port = DEFAULT_TAP_PORT;
  bool interactive = false;
  for (int i = 1; i < argc; i++) {
    std::string a = argv[i];
    if (a == "--tap-port" && i + 1 < argc) tap_port = uint16_t(std::stoi(argv[++i]));
    else if (a == "--interactive") interactive = true;
    else { std::cerr << "usage: arp_lab [--interactive] [--tap-port N]\n"; return 2; }
  }
  TapSender tap(tap_port);
  Say say = [](const std::string& s) { std::cout << s << std::endl; };
  if (!interactive) { run_arp_demo(&tap, say); return 0; }

  VirtualLan lan; lan.set_tap(&tap);
  std::map<std::string, std::unique_ptr<ArpHost>> hosts;
  auto add = [&](const char* n, uint8_t last, Ip4 ip) { hosts[n] = std::make_unique<ArpHost>(lan, n, Mac::make(2, 0, 0, 0, 0, last), ip); };
  add("alice", 0xA1, make_ip(192, 168, 1, 10)); add("bob", 0xB2, make_ip(192, 168, 1, 20));
  add("gateway", 0x01, make_ip(192, 168, 1, 1)); add("mallory", 0x66, make_ip(192, 168, 1, 66));
  std::cout << "hosts: alice .10  bob .20  gateway .1  mallory .66   (type 'help')\n";
  std::string line;
  while (std::cout << "arp> " && std::getline(std::cin, line)) {
    std::istringstream in(line); std::string c, h, x; in >> c >> h >> x;
    if (c == "quit" || c == "exit") break;
    if (c == "help") { std::cout << "resolve <host> <ip> | cache <host> | announce <host> | probe <host> <ip> | spoof <victim> <claimed-ip> [by mallory]\n"
                                    "proxy <host> <ip> | static <host> <ip> <mac> | loss <pct> | flush <host> | quit\n"; continue; }
    if (c == "loss") { lan.set_loss_percent(std::atoi(h.c_str())); continue; }
    if (!hosts.count(h)) { std::cout << "unknown host '" << h << "'\n"; continue; }
    ArpHost& H = *hosts[h]; Ip4 ip = 0;
    if (c == "cache") std::cout << H.cache().dump();
    else if (c == "flush") H.cache().flush();
    else if (c == "announce") H.announce();
    else if (c == "resolve" && ip_parse(x, ip)) { auto m = H.resolve(ip); std::cout << (m ? ip_str(ip) + " is at " + m->str() : "no answer") << "\n"; }
    else if (c == "probe" && ip_parse(x, ip)) std::cout << (H.probe(ip) ? "address is free\n" : "ADDRESS IN USE\n");
    else if (c == "proxy" && ip_parse(x, ip)) H.add_proxy(ip);
    else if (c == "spoof" && ip_parse(x, ip)) { hosts["mallory"]->send_unsolicited_reply(ip, H.ip(), H.mac()); std::cout << "sent forged reply to " << h << "\n"; }
    else if (c == "static" && ip_parse(x, ip)) { std::string ms; in >> ms; auto m = Mac::parse(ms); if (m) H.cache().insert(ip, *m, true); else std::cout << "bad mac\n"; }
    else std::cout << "?\n";
    for (auto& e : H.events()) std::cout << "  [" << h << "] " << e << "\n";
  }
}
