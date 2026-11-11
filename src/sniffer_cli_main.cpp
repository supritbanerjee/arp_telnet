// sniffer_cli - terminal front-end for the dissector.
//   sniffer_cli [--port 9998] [--filter EXPR] [--out cap.pcap] [--duration SEC] [--tree] [--hex]    live capture
//   sniffer_cli --read cap.pcap [--filter EXPR] [--tree] [--hex]                                    offline
#include <iostream>

#include "capture_session.hpp"
#include "dissector.hpp"

using namespace netlab;

static void print_hex(const Bytes& f) {
  for (size_t i = 0; i < f.size(); i += 16) {
    std::printf("    %04zx  ", i);
    for (size_t j = 0; j < 16; j++) { if (i + j < f.size()) std::printf("%02x ", f[i + j]); else std::printf("   "); if (j == 7) std::printf(" "); }
    std::printf(" ");
    for (size_t j = 0; j < 16 && i + j < f.size(); j++) std::printf("%c", f[i + j] >= 32 && f[i + j] < 127 ? f[i + j] : '.');
    std::printf("\n");
  }
}
static void print_tree(const std::vector<Node>& v, int depth) {
  for (auto& n : v) {
    std::printf("    %*s%s", depth * 2, "", n.text.c_str());
    if (n.off >= 0) std::printf("   [%d..%d]", n.off, n.off + n.len - 1);
    std::printf("\n");
    print_tree(n.kids, depth + 1);
  }
}
static void show(const Dissected& d, double t0, bool tree, bool hex, const Bytes& f) {
  std::printf("%5u %10.6f %-19s %-19s %-8s %s\n", d.no, d.ts - t0, d.src.c_str(), d.dst.c_str(), d.proto.c_str(), d.info.c_str());
  if (tree) print_tree(d.tree, 0);
  if (hex) print_hex(f);
}

int main(int argc, char** argv) {
  uint16_t port = DEFAULT_TAP_PORT; std::string filter, out, in; int duration = 0; bool tree = false, hex = false;
  for (int i = 1; i < argc; i++) {
    std::string a = argv[i];
    if (a == "--port" && i + 1 < argc) port = uint16_t(std::stoi(argv[++i]));
    else if (a == "--filter" && i + 1 < argc) filter = argv[++i];
    else if (a == "--out" && i + 1 < argc) out = argv[++i];
    else if (a == "--read" && i + 1 < argc) in = argv[++i];
    else if (a == "--duration" && i + 1 < argc) duration = std::stoi(argv[++i]);
    else if (a == "--tree") tree = true;
    else if (a == "--hex") hex = true;
    else { std::cerr << "bad argument: " << a << "\n"; return 2; }
  }
  DisplayFilter df; std::string err;
  if (!df.compile(filter, &err)) { std::cerr << "filter error: " << err << "\n"; return 2; }
  std::vector<CapturedPacket> pkts;
  if (!in.empty()) {
    if (!read_pcap(in, pkts, &err)) { std::cerr << "read error: " << err << "\n"; return 1; }
  } else {
    CaptureSession cap(port);
    if (!cap.start(&err)) { std::cerr << err << "\n"; return 1; }
    std::cerr << "capturing on tap port " << port << (duration ? " for " + std::to_string(duration) + "s" : " - press Enter to stop") << "\n";
    if (duration) std::this_thread::sleep_for(std::chrono::seconds(duration)); else { std::string l; std::getline(std::cin, l); }
    cap.stop(); pkts = cap.snapshot();
  }
  double t0 = pkts.empty() ? 0 : pkts[0].ts; size_t shown = 0;
  for (auto& p : pkts) { Dissected d = dissect(p.frame, p.no, p.ts); if (df.match(d)) { show(d, t0, tree, hex, p.frame); shown++; } }
  std::printf("-- %zu packets, %zu displayed\n", pkts.size(), shown);
  if (!out.empty()) std::printf("-- %s %s\n", write_pcap(out, pkts) ? "saved" : "FAILED to save", out.c_str());
}
