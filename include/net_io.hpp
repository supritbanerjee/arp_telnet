// Phase 1 - Cross-platform RAII sockets (Winsock2 on Windows) + the Tap link used by Mini-Wireshark.
//
// Tap datagram (UDP -> 127.0.0.1:<tap port>):   'N' 'L' 'T' '2' | u32 sec | u32 usec | raw Ethernet frame
#pragma once
#include <chrono>
#include <mutex>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
using sock_t = SOCKET;
#define NL_INVALID INVALID_SOCKET
#define NL_CLOSE closesocket
#define NL_SENDFLAGS 0
using socklen_nl = int;
#else
#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <unistd.h>
using sock_t = int;
#define NL_INVALID (-1)
#define NL_CLOSE ::close
#ifdef MSG_NOSIGNAL
#define NL_SENDFLAGS MSG_NOSIGNAL
#else
#define NL_SENDFLAGS 0  // macOS/BSD: SIGPIPE is suppressed per-socket with SO_NOSIGPIPE instead (see Socket::nosigpipe)
#endif
using socklen_nl = socklen_t;
#endif

#include "l2l4_headers.hpp"

namespace netlab {

constexpr uint16_t DEFAULT_TAP_PORT = 9998;   // (BOOTP/DNS lab uses 9999; kept separate so both can run)
constexpr int RECV_TIMEOUT = -2, RECV_ERROR = -1;

inline void net_init() {
#ifdef _WIN32
  static bool done = [] { WSADATA w; WSAStartup(MAKEWORD(2, 2), &w); return true; }();
  (void)done;
#endif
}

inline double now_epoch() {
  using namespace std::chrono;
  return duration_cast<duration<double>>(system_clock::now().time_since_epoch()).count();
}

class Socket {
 public:
  Socket() { net_init(); }
  explicit Socket(sock_t s) : s_(s) { nosigpipe(); }
  Socket(const Socket&) = delete;
  Socket& operator=(const Socket&) = delete;
  Socket(Socket&& o) noexcept : s_(o.s_) { o.s_ = NL_INVALID; }
  Socket& operator=(Socket&& o) noexcept { if (this != &o) { close(); s_ = o.s_; o.s_ = NL_INVALID; } return *this; }
  ~Socket() { close(); }

  static Socket udp() { net_init(); return Socket(::socket(AF_INET, SOCK_DGRAM, 0)); }
  static Socket tcp() { net_init(); return Socket(::socket(AF_INET, SOCK_STREAM, 0)); }

  bool valid() const { return s_ != NL_INVALID; }
  void nosigpipe() {
#if defined(SO_NOSIGPIPE) && !defined(_WIN32)
    if (s_ != NL_INVALID) { int one = 1; ::setsockopt(s_, SOL_SOCKET, SO_NOSIGPIPE, (const char*)&one, sizeof one); }
#endif
  }
  void close() { if (s_ != NL_INVALID) { NL_CLOSE(s_); s_ = NL_INVALID; } }
  void shutdown_both() { if (valid()) ::shutdown(s_, 2); }

  bool bind_loopback(uint16_t port) {
#ifndef _WIN32
    int type = 0; socklen_nl tl = sizeof type;  // SO_REUSEADDR only for TCP listeners: on UDP it would let a second
    ::getsockopt(s_, SOL_SOCKET, SO_TYPE, (char*)&type, &tl);  // sniffer share (and steal) the tap port
    if (type == SOCK_STREAM) { int one = 1; ::setsockopt(s_, SOL_SOCKET, SO_REUSEADDR, (const char*)&one, sizeof one); }
#endif
    sockaddr_in a = addr(port);
    return ::bind(s_, (sockaddr*)&a, sizeof a) == 0;
  }
  bool listen(int backlog = 8) { return ::listen(s_, backlog) == 0; }
  Socket accept(int timeout_ms) {
    if (!wait_readable(timeout_ms)) return Socket(NL_INVALID);
    return Socket(::accept(s_, nullptr, nullptr));
  }
  bool connect_loopback(uint16_t port) {
    sockaddr_in a = addr(port);
    return ::connect(s_, (sockaddr*)&a, sizeof a) == 0;
  }
  bool send_all(const uint8_t* p, size_t n) {
    while (n) {
      int k = (int)::send(s_, (const char*)p, (int)n, NL_SENDFLAGS);
      if (k <= 0) return false;
      p += k; n -= size_t(k);
    }
    return true;
  }
  // >0 bytes read, 0 peer closed, RECV_TIMEOUT on timeout, RECV_ERROR on error
  int recv_some(uint8_t* p, size_t n, int timeout_ms) {
    if (!wait_readable(timeout_ms)) return RECV_TIMEOUT;
    int k = (int)::recv(s_, (char*)p, (int)n, 0);
    return k < 0 ? RECV_ERROR : k;
  }
  bool sendto_loopback(uint16_t port, const uint8_t* p, size_t n) {
    sockaddr_in a = addr(port);
    return ::sendto(s_, (const char*)p, (int)n, 0, (sockaddr*)&a, sizeof a) == (int)n;
  }
  int recvfrom_some(uint8_t* p, size_t n, int timeout_ms) {
    if (!wait_readable(timeout_ms)) return RECV_TIMEOUT;
    int k = (int)::recvfrom(s_, (char*)p, (int)n, 0, nullptr, nullptr);
    return k < 0 ? RECV_ERROR : k;
  }
  uint16_t local_port() const { return port_of(false); }
  uint16_t peer_port() const { return port_of(true); }

 private:
  sock_t s_ = NL_INVALID;
  static sockaddr_in addr(uint16_t port) {
    sockaddr_in a{}; a.sin_family = AF_INET; a.sin_port = htons(port); a.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return a;
  }
  uint16_t port_of(bool peer) const {
    sockaddr_in a{}; socklen_nl l = sizeof a;
    int r = peer ? ::getpeername(s_, (sockaddr*)&a, &l) : ::getsockname(s_, (sockaddr*)&a, &l);
    return r == 0 ? ntohs(a.sin_port) : 0;
  }
  bool wait_readable(int timeout_ms) {
    fd_set fds; FD_ZERO(&fds); FD_SET(s_, &fds);
    timeval tv{timeout_ms / 1000, (timeout_ms % 1000) * 1000};
    return ::select((int)s_ + 1, &fds, nullptr, nullptr, &tv) > 0;
  }
};

// ----------------------------------------------------------------------------- Tap
inline Bytes make_tap_datagram(const Bytes& frame, double ts) {
  Bytes d{'N', 'L', 'T', '2'};
  uint32_t sec = uint32_t(ts), usec = uint32_t((ts - sec) * 1e6);
  put32(d, sec); put32(d, usec);
  d.insert(d.end(), frame.begin(), frame.end());
  return d;
}
inline bool parse_tap_datagram(const uint8_t* p, size_t n, double& ts, Bytes& frame) {
  if (n < 12 || p[0] != 'N' || p[1] != 'L' || p[2] != 'T' || p[3] != '2') return false;
  ts = double(get32(p + 4)) + double(get32(p + 8)) / 1e6;
  frame.assign(p + 12, p + n);
  return true;
}

// Fire-and-forget emitter. Anything that "puts a frame on the wire" mirrors it here.
class TapSender {
 public:
  explicit TapSender(uint16_t port = DEFAULT_TAP_PORT) : s_(Socket::udp()), port_(port) {}
  void emit(const Bytes& frame) {
    Bytes d = make_tap_datagram(frame, now_epoch());
    std::lock_guard<std::mutex> g(m_);
    s_.sendto_loopback(port_, d.data(), d.size());
  }
 private:
  Socket s_;
  uint16_t port_;
  std::mutex m_;
};

}  // namespace netlab
