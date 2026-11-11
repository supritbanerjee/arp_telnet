// Phase 4 - Thread-safe live Tap sniffer + packet store.
#pragma once
#include <atomic>
#include <functional>
#include <thread>

#include "net_io.hpp"
#include "pcap_writer.hpp"

namespace netlab {

class CaptureSession {
 public:
  explicit CaptureSession(uint16_t port = DEFAULT_TAP_PORT) : port_(port) {}
  ~CaptureSession() { stop(); }

  bool start(std::string* err = nullptr) {
    if (running_) return true;
    sock_ = Socket::udp();
    if (!sock_.valid() || !sock_.bind_loopback(port_)) { if (err) *err = "cannot bind tap port " + std::to_string(port_); sock_.close(); return false; }
    running_ = true;
    th_ = std::thread([this] { loop(); });
    return true;
  }
  void stop() {
    running_ = false;
    if (th_.joinable()) th_.join();
    sock_.close();
  }
  bool running() const { return running_; }
  uint16_t port() const { return port_; }

  void clear() { std::lock_guard<std::mutex> g(m_); pkts_.clear(); }
  void load(std::vector<CapturedPacket> v) {
    std::lock_guard<std::mutex> g(m_);
    pkts_ = std::move(v);
    for (size_t i = 0; i < pkts_.size(); i++) pkts_[i].no = uint32_t(i + 1);
  }
  size_t size() { std::lock_guard<std::mutex> g(m_); return pkts_.size(); }
  std::vector<CapturedPacket> snapshot(size_t from = 0) {  // packets [from, end)
    std::lock_guard<std::mutex> g(m_);
    return from >= pkts_.size() ? std::vector<CapturedPacket>{} : std::vector<CapturedPacket>(pkts_.begin() + from, pkts_.end());
  }
  void set_on_packet(std::function<void()> cb) { std::lock_guard<std::mutex> g(m_); cb_ = std::move(cb); }

 private:
  uint16_t port_;
  Socket sock_;
  std::atomic<bool> running_{false};
  std::thread th_;
  std::mutex m_;
  std::vector<CapturedPacket> pkts_;
  std::function<void()> cb_;

  void loop() {
    Bytes buf(70000);
    while (running_) {
      int n = sock_.recvfrom_some(buf.data(), buf.size(), 100);
      if (n <= 0) continue;
      CapturedPacket p;
      if (!parse_tap_datagram(buf.data(), size_t(n), p.ts, p.frame)) continue;
      std::function<void()> cb;
      {
        std::lock_guard<std::mutex> g(m_);
        p.no = uint32_t(pkts_.size() + 1);
        pkts_.push_back(std::move(p));
        cb = cb_;
      }
      if (cb) cb();
    }
  }
};

}  // namespace netlab
