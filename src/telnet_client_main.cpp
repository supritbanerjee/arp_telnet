// telnet_client --port 2323 --tap-port 9998 [--user U --pass P --cmd "arp" --cmd "whoami" ...]   (scripted)
// telnet_client --interactive                                                                      (default)
#include <iostream>
#include <thread>

#include "telnet_engine.hpp"

using namespace netlab;

int main(int argc, char** argv) {
  TelnetClientConfig cc; uint16_t tap_port = DEFAULT_TAP_PORT;
  std::string user, pass; std::vector<std::string> cmds;
  for (int i = 1; i < argc; i++) {
    std::string a = argv[i];
    if (a == "--port" && i + 1 < argc) cc.port = uint16_t(std::stoi(argv[++i]));
    else if (a == "--tap-port" && i + 1 < argc) tap_port = uint16_t(std::stoi(argv[++i]));
    else if (a == "--user" && i + 1 < argc) user = argv[++i];
    else if (a == "--pass" && i + 1 < argc) pass = argv[++i];
    else if (a == "--cmd" && i + 1 < argc) cmds.push_back(argv[++i]);
    else if (a == "--interactive") {}
    else { std::cerr << "usage: telnet_client [--port N] [--tap-port N] [--user U --pass P --cmd C ...]\n"; return 2; }
  }
  TapSender tap(tap_port); cc.tap = &tap;
  TelnetClient cl(cc);
  if (!cl.connect()) { std::cerr << "cannot connect to 127.0.0.1:" << cc.port << "\n"; return 1; }

  if (!user.empty()) {  // scripted
    std::cout << cl.read_until("login: "); cl.send_line(user);
    std::cout << cl.read_until("Password: "); cl.send_line(pass);
    std::cout << cl.read_until("$ ");
    for (auto& c : cmds) { cl.send_line(c); std::cout << cl.read_until("$ "); }
    cl.send_line("exit"); std::cout << cl.read_until("logout") << std::endl;
    return 0;
  }
  std::atomic<bool> run{true};
  std::thread reader([&] { while (run && cl.connected()) { std::string t = cl.read_available(100); if (!t.empty()) { std::cout << t << std::flush; } } run = false; });
  std::string line;
  while (run && std::getline(std::cin, line)) cl.send_line(line);
  run = false; reader.join();
  cl.close();
  std::cout << "\nConnection closed.\n";
}
