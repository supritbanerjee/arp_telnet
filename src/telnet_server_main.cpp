// telnet_server --port 2323 --tap-port 9998 [--hostname NAME]    (users: admin/netlab, guest/guest)
#include <iostream>

#include "arp_engine.hpp"
#include "telnet_engine.hpp"

using namespace netlab;

int main(int argc, char** argv) {
  TelnetServerConfig sc; uint16_t tap_port = DEFAULT_TAP_PORT;
  for (int i = 1; i < argc; i++) {
    std::string a = argv[i];
    if (a == "--port" && i + 1 < argc) sc.port = uint16_t(std::stoi(argv[++i]));
    else if (a == "--tap-port" && i + 1 < argc) tap_port = uint16_t(std::stoi(argv[++i]));
    else if (a == "--hostname" && i + 1 < argc) sc.hostname = argv[++i];
    else { std::cerr << "usage: telnet_server [--port N] [--tap-port N] [--hostname NAME]\n"; return 2; }
  }
  TapSender tap(tap_port); sc.tap = &tap;
  ArpCache cache; cache.insert(make_ip(192, 168, 1, 10), Mac::make(2, 0, 0, 0, 0, 0xA1)); cache.insert(make_ip(192, 168, 1, 20), Mac::make(2, 0, 0, 0, 0, 0xB2), true);
  sc.arp_dump = [&] { return cache.dump(); };
  TelnetServer srv(sc);
  if (!srv.start()) { std::cerr << "cannot listen on 127.0.0.1:" << sc.port << "\n"; return 1; }
  std::cout << "telnet server on 127.0.0.1:" << sc.port << " (mirroring to tap port " << tap_port << "). Press Enter to stop.\n";
  std::string l; std::getline(std::cin, l);
  srv.stop();
  std::cout << "sessions served: " << srv.sessions_served() << ", failed logins: " << srv.login_failures() << "\n";
}
