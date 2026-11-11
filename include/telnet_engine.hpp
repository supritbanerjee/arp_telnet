// Phase 3 - Custom Telnet engine (RFC 854/855/857/858/1073/1091) over real TCP sockets (loopback).
//
//   TcpTap        synthesizes Ethernet II + IPv4 + TCP frames (with valid seq/ack/checksums) for every segment
//                 this side sends, so Mini-Wireshark sees a realistic conversation (SYN, SYN/ACK, ACK, PSH/ACK, FIN).
//   TelnetServer  option negotiation (WILL ECHO, WILL SGA, DO NAWS, DO TTYPE), login with 3 attempts,
//                 line editor, tiny shell (help/whoami/hostname/uname/date/arp/who/echo/clear/exit).
//   TelnetClient  answers negotiation (DO ECHO/SGA, WILL NAWS + SB NAWS, WILL TTYPE + SB TTYPE IS), scripted or interactive.
//
// Real sockets use 127.0.0.1:<port>; the *mirrored* frames use the lab addresses in TcpEndpoint.
#pragma once
#include <algorithm>
#include <atomic>
#include <ctime>
#include <functional>
#include <map>
#include <memory>
#include <set>
#include <sstream>
#include <thread>

#include "net_io.hpp"

namespace netlab {

struct TcpEndpoint {
  Mac mac;
  Ip4 ip = 0;
  uint16_t port = 0;
};

// Both ends derive each other's initial sequence number from (ip, port), so two independent processes agree on
// seq/ack numbers without ever seeing each other's SYN.
inline uint32_t tap_isn(const TcpEndpoint& e) { return 0x10000u + uint32_t(e.port) * 7919u + (e.ip & 0xFFFF); }

class TcpTap {
 public:
  TcpTap(TapSender* tap, TcpEndpoint local, TcpEndpoint remote)
      : tap_(tap), l_(local), r_(remote), snd_(tap_isn(local)), rcv_(tap_isn(remote)) {}
  void syn() { emit(TCP_SYN, {}); snd_++; }
  // The accepting side mirrors SYN/ACK and then the client's (fully deterministic) final ACK, exactly as a tap on the
  // wire would see them. This keeps the handshake ahead of the first data segment in the capture.
  void syn_ack() {
    rcv_++; emit(TCP_SYN | TCP_ACK, {}); snd_++;
    if (!tap_) return;
    TcpHeader h; h.sport = r_.port; h.dport = l_.port; h.seq = rcv_; h.ack = snd_; h.flags = TCP_ACK;
    tap_->emit(make_tcp_frame(r_.mac, l_.mac, r_.ip, l_.ip, h, {}, 1));
  }
  void handshake_done() { rcv_++; }  // client side: account for the server's SYN (its ACK was mirrored by the server)
  void data(const Bytes& b) {  // call BEFORE the real send so the capture order matches causality
    for (size_t i = 0; i < b.size(); i += 1460) {
      Bytes chunk(b.begin() + i, b.begin() + std::min(b.size(), i + 1460));
      emit(TCP_PSH | TCP_ACK, chunk);
      snd_ += uint32_t(chunk.size());
    }
  }
  void on_rx(size_t n) { rcv_ += uint32_t(n); }
  void fin() { emit(TCP_FIN | TCP_ACK, {}); snd_++; }

 private:
  TapSender* tap_;
  TcpEndpoint l_, r_;
  uint32_t snd_, rcv_;
  uint16_t ipid_ = 1;
  void emit(uint8_t flags, const Bytes& payload) {
    if (!tap_) return;
    TcpHeader h; h.sport = l_.port; h.dport = r_.port; h.seq = snd_; h.ack = (flags & TCP_ACK) ? rcv_ : 0; h.flags = flags;
    tap_->emit(make_tcp_frame(l_.mac, r_.mac, l_.ip, r_.ip, h, payload, ipid_++));
  }
};

inline std::string crlf(const std::string& s) {  // bare \n -> \r\n (NVT line ending)
  std::string o;
  for (char c : s) { if (c == '\n') o += '\r'; o += c; }
  return o;
}

// ---------------------------------------------------------------------------------------------- Server
struct TelnetServerConfig {
  uint16_t port = 2323;  // real listening port on 127.0.0.1
  std::map<std::string, std::string> users{{"admin", "netlab"}, {"guest", "guest"}};
  std::string hostname = "netlab-router";
  TapSender* tap = nullptr;
  TcpEndpoint server_ep{Mac::make(2, 0, 0, 0, 0, 0xB1), make_ip(192, 168, 1, 1), 23};
  TcpEndpoint client_ep{Mac::make(2, 0, 0, 0, 0, 0xA1), make_ip(192, 168, 1, 10), 0};  // port filled per connection
  std::function<std::string()> arp_dump;  // wires the `arp` shell command to an ArpCache
};

class TelnetServer {
 public:
  explicit TelnetServer(TelnetServerConfig c) : cfg_(std::move(c)) {}
  ~TelnetServer() { stop(); }

  bool start() {
    listener_ = Socket::tcp();
    if (!listener_.valid() || !listener_.bind_loopback(cfg_.port) || !listener_.listen()) return false;
    running_ = true;
    accept_thread_ = std::thread([this] { accept_loop(); });
    return true;
  }
  void stop() {
    running_ = false;
    if (accept_thread_.joinable()) accept_thread_.join();
    for (auto& t : workers_) if (t.joinable()) t.join();
    workers_.clear();
    listener_.close();
  }
  size_t sessions_served() const { return served_; }
  size_t login_failures() const { return failures_; }

 private:
  TelnetServerConfig cfg_;
  Socket listener_;
  std::atomic<bool> running_{false};
  std::atomic<size_t> served_{0}, failures_{0};
  std::thread accept_thread_;
  std::vector<std::thread> workers_;
  std::mutex who_m_;
  std::map<int, std::string> who_;
  int next_id_ = 1;

  void accept_loop() {
    while (running_) {
      Socket c = listener_.accept(100);
      if (!c.valid()) continue;
      auto sp = std::make_shared<Socket>(std::move(c));
      workers_.emplace_back([this, sp] { handle(*sp); });
    }
  }

  std::string run_command(const std::string& line, const std::string& user, bool& quit, bool& cls) {
    std::istringstream in(line);
    std::string cmd, rest;
    in >> cmd;
    std::getline(in, rest);
    if (!rest.empty() && rest[0] == ' ') rest.erase(0, 1);
    if (cmd.empty()) return "";
    if (cmd == "help") return "Commands: help whoami hostname uname date arp who echo clear exit\n";
    if (cmd == "whoami") return user + "\n";
    if (cmd == "hostname") return cfg_.hostname + "\n";
    if (cmd == "uname") return "NetLab-OS 1.0 (custom Telnet suite) x86_64\n";
    if (cmd == "date") { std::time_t t = std::time(nullptr); char b[64]; std::strftime(b, sizeof b, "%a %b %d %H:%M:%S %Y", std::localtime(&t)); return std::string(b) + "\n"; }
    if (cmd == "arp") return cfg_.arp_dump ? cfg_.arp_dump() : "arp: no ARP cache attached\n";
    if (cmd == "echo") return rest + "\n";
    if (cmd == "who") { std::lock_guard<std::mutex> g(who_m_); std::string o; for (auto& [id, d] : who_) o += d + "\n"; return o; }
    if (cmd == "clear") { cls = true; return ""; }
    if (cmd == "exit" || cmd == "logout" || cmd == "quit") { quit = true; return "logout\n"; }
    return "sh: " + cmd + ": command not found\n";
  }

  void handle(Socket& sock) {
    TcpEndpoint cli = cfg_.client_ep; cli.port = sock.peer_port();
    TcpTap tap(cfg_.tap, cfg_.server_ep, cli);
    tap.syn_ack();
    auto send = [&](const Bytes& b) { if (b.empty()) return; tap.data(b); sock.send_all(b.data(), b.size()); };

    Bytes neg;  // initial negotiation: one segment, like real servers
    for (auto b : {tn::cmd(tn::WILL, tn::OPT_ECHO), tn::cmd(tn::WILL, tn::OPT_SGA), tn::cmd(tn::DO, tn::OPT_NAWS), tn::cmd(tn::DO, tn::OPT_TTYPE)})
      neg.insert(neg.end(), b.begin(), b.end());
    send(neg);
    send(tn::text("\r\n" + cfg_.hostname + " - NetLab Telnet Service\r\n\r\nlogin: "));

    enum { USER, PASS, SHELL } st = USER;
    std::string line, user, term = "unknown", out;
    int attempts = 0, id = 0;
    unsigned cols = 0, rows = 0;
    bool prev_cr = false, done = false;
    TelnetParser parser;
    auto prompt = [&] { return user + "@" + cfg_.hostname + ":~$ "; };

    auto eol = [&] {
      out += "\r\n";
      std::string l = line; line.clear();
      if (st == USER) { user = l; st = PASS; out += "Password: "; }
      else if (st == PASS) {
        auto it = cfg_.users.find(user);
        if (it != cfg_.users.end() && it->second == l) {
          st = SHELL; served_++;
          std::time_t t = std::time(nullptr); char b[64]; std::strftime(b, sizeof b, "%a %b %d %H:%M:%S %Y", std::localtime(&t));
          out += std::string("Last login: ") + b + "\r\nType 'help' for a list of commands.\r\n" + prompt();
          std::lock_guard<std::mutex> g(who_m_);
          id = next_id_++;
          who_[id] = user + "  pts/" + std::to_string(id) + "  127.0.0.1:" + std::to_string(cli.port) + "  (" + term + " " + std::to_string(cols) + "x" + std::to_string(rows) + ")";
        } else if (++attempts >= 3) { failures_++; out += "Too many failed attempts.\r\n"; done = true; }
        else { failures_++; out += "Login incorrect\r\nlogin: "; st = USER; }
      } else {
        bool quit = false, cls = false;
        std::string r = crlf(run_command(l, user, quit, cls));
        if (cls) r = "\x1b[2J\x1b[H";
        out += r;
        if (quit) done = true; else out += prompt();
      }
    };

    uint8_t buf[2048];
    while (running_ && !done) {
      int n = sock.recv_some(buf, sizeof buf, 100);
      if (n == RECV_TIMEOUT) continue;
      if (n <= 0) break;
      tap.on_rx(size_t(n));
      for (auto& it : parser.feed(buf, size_t(n))) {
        if (it.kind == TelnetItem::Command) {
          if (it.cmd == tn::WILL) {
            if (it.opt == tn::OPT_NAWS) {}                                                   // answer to our DO
            else if (it.opt == tn::OPT_TTYPE) send(tn::sb(tn::OPT_TTYPE, {tn::TTYPE_SEND}));  // ask for the terminal name
            else send(tn::cmd(tn::DONT, it.opt));                                            // unsolicited: refuse
          } else if (it.cmd == tn::DO && it.opt != tn::OPT_ECHO && it.opt != tn::OPT_SGA) send(tn::cmd(tn::WONT, it.opt));
        } else if (it.kind == TelnetItem::Subneg) {
          if (it.opt == tn::OPT_NAWS && it.data.size() >= 4) { cols = get16(&it.data[0]); rows = get16(&it.data[2]); }
          else if (it.opt == tn::OPT_TTYPE && it.data.size() >= 2 && it.data[0] == tn::TTYPE_IS) term.assign(it.data.begin() + 1, it.data.end());
        } else {
          for (uint8_t c : it.data) {
            if (prev_cr && (c == '\n' || c == 0)) { prev_cr = false; continue; }  // CR LF / CR NUL
            prev_cr = false;
            if (c == '\r') { prev_cr = true; eol(); }
            else if (c == '\n') eol();
            else if (c == 8 || c == 127) { if (!line.empty()) { line.pop_back(); if (st != PASS) out += "\b \b"; } }
            else if (c == 3) { line.clear(); out += "^C\r\n"; if (st == SHELL) out += prompt(); else { st = USER; out += "login: "; } }
            else if (c == 4 && line.empty() && st == SHELL) { out += "logout\r\n"; done = true; }
            else if (c >= 32 && c < 127) { line.push_back(char(c)); if (st != PASS) out += char(c); }  // server-side echo (WILL ECHO)
            if (done) break;
          }
        }
      }
      if (!out.empty()) { send(tn::text(out)); out.clear(); }
    }
    tap.fin();
    sock.shutdown_both();
    if (id) { std::lock_guard<std::mutex> g(who_m_); who_.erase(id); }
  }
};

// ---------------------------------------------------------------------------------------------- Client
struct TelnetClientConfig {
  uint16_t port = 2323;
  TapSender* tap = nullptr;
  TcpEndpoint client_ep{Mac::make(2, 0, 0, 0, 0, 0xA1), make_ip(192, 168, 1, 10), 0};
  TcpEndpoint server_ep{Mac::make(2, 0, 0, 0, 0, 0xB1), make_ip(192, 168, 1, 1), 23};
  std::string term = "NETLAB";
  uint16_t cols = 80, rows = 24;
};

class TelnetClient {
 public:
  explicit TelnetClient(TelnetClientConfig c) : cfg_(std::move(c)) {}
  ~TelnetClient() { close(); }

  bool connect() {
    sock_ = Socket::tcp();
    if (!sock_.valid() || !sock_.bind_loopback(0)) return false;
    TcpEndpoint cli = cfg_.client_ep; cli.port = sock_.local_port();
    tap_ = std::make_unique<TcpTap>(cfg_.tap, cli, cfg_.server_ep);
    tap_->syn();  // mirrored before the real connect so SYN precedes SYN/ACK in the capture
    if (!sock_.connect_loopback(cfg_.port)) { sock_.close(); return false; }
    connected_ = true; ever_connected_ = true;
    return true;
  }
  void close() {
    if (sock_.valid()) {
      if (ever_connected_ && tap_ && !fin_sent_) { tap_->fin(); fin_sent_ = true; }  // our FIN even if the peer closed first
      sock_.shutdown_both(); sock_.close();
    }
    connected_ = false;
  }
  bool connected() const { return connected_; }

  bool send_line(const std::string& s) { Bytes b = tn::text(s); b.push_back('\r'); b.push_back('\n'); return send_raw(b); }
  bool send_raw(const Bytes& b) {
    std::lock_guard<std::mutex> g(send_m_);
    if (!connected_ || b.empty()) return false;
    tap_->data(b);
    return sock_.send_all(b.data(), b.size());
  }

  // Read one chunk, run negotiation, append clean text to the pending buffer. False once the peer closed.
  bool pump(int timeout_ms) {
    uint8_t buf[2048];
    int n = sock_.recv_some(buf, sizeof buf, timeout_ms);
    if (n == RECV_TIMEOUT) return true;
    if (n <= 0) { connected_ = false; return false; }
    if (!hs_acked_) { tap_->handshake_done(); hs_acked_ = true; }
    tap_->on_rx(size_t(n));
    Bytes replies;
    for (auto& it : parser_.feed(buf, size_t(n))) handle(it, replies);
    send_raw(replies);
    return true;
  }
  // Returns everything up to and including `marker`, or whatever arrived before the timeout.
  std::string read_until(const std::string& marker, int timeout_ms = 2000) {
    auto deadline = Clock::now() + std::chrono::milliseconds(timeout_ms);
    for (;;) {
      size_t p = pending_.find(marker);
      if (p != std::string::npos) { std::string r = pending_.substr(0, p + marker.size()); pending_.erase(0, p + marker.size()); return r; }
      int left = (int)std::chrono::duration_cast<std::chrono::milliseconds>(deadline - Clock::now()).count();
      if (left <= 0 || !pump(std::min(left, 100))) break;
    }
    std::string r = pending_; pending_.clear(); return r;
  }
  std::string read_available(int timeout_ms = 100) { pump(timeout_ms); std::string r = pending_; pending_.clear(); return r; }
  const std::vector<std::string>& negotiation_log() const { return log_; }
  const std::set<uint8_t>& remote_will() const { return remote_will_; }

 private:
  using Clock = std::chrono::steady_clock;
  TelnetClientConfig cfg_;
  Socket sock_;
  std::unique_ptr<TcpTap> tap_;
  TelnetParser parser_;
  std::string pending_;
  std::vector<std::string> log_;
  std::set<uint8_t> remote_will_, did_do_, did_will_;
  std::mutex send_m_;
  std::atomic<bool> connected_{false};
  bool hs_acked_ = false, ever_connected_ = false, fin_sent_ = false;

  void handle(const TelnetItem& it, Bytes& rep) {
    auto add = [&](const Bytes& b, const std::string& what) { rep.insert(rep.end(), b.begin(), b.end()); log_.push_back(">> " + what); };
    if (it.kind == TelnetItem::Data) { for (uint8_t c : it.data) if (c != '\r' && c != 0) pending_.push_back(char(c)); return; }
    if (it.kind == TelnetItem::Command) {
      log_.push_back(std::string("<< ") + tn::verb_name(it.cmd) + " " + tn::opt_name(it.opt));
      if (it.cmd == tn::WILL) {
        remote_will_.insert(it.opt);
        if (it.opt == tn::OPT_ECHO || it.opt == tn::OPT_SGA) { if (did_do_.insert(it.opt).second) add(tn::cmd(tn::DO, it.opt), std::string("DO ") + tn::opt_name(it.opt)); }
        else add(tn::cmd(tn::DONT, it.opt), std::string("DON'T ") + tn::opt_name(it.opt));
      } else if (it.cmd == tn::DO) {
        if (it.opt == tn::OPT_NAWS || it.opt == tn::OPT_TTYPE) {
          if (did_will_.insert(it.opt).second) {
            add(tn::cmd(tn::WILL, it.opt), std::string("WILL ") + tn::opt_name(it.opt));
            if (it.opt == tn::OPT_NAWS) add(tn::sb(tn::OPT_NAWS, {uint8_t(cfg_.cols >> 8), uint8_t(cfg_.cols), uint8_t(cfg_.rows >> 8), uint8_t(cfg_.rows)}), "SB NAWS " + std::to_string(cfg_.cols) + "x" + std::to_string(cfg_.rows));
          }
        } else add(tn::cmd(tn::WONT, it.opt), std::string("WON'T ") + tn::opt_name(it.opt));
      }
    } else if (it.opt == tn::OPT_TTYPE && !it.data.empty() && it.data[0] == tn::TTYPE_SEND) {
      Bytes d{tn::TTYPE_IS}; d.insert(d.end(), cfg_.term.begin(), cfg_.term.end());
      log_.push_back("<< SB Terminal Type SEND");
      add(tn::sb(tn::OPT_TTYPE, d), "SB Terminal Type IS " + cfg_.term);
    }
  }
};

}  // namespace netlab
