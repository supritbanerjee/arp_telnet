// Phase 2 - Custom ARP engine (RFC 826 + RFC 5227 probes/announcements) on a simulated Ethernet segment.
//
//   ArpCache    TTL-aware, supports static entries, "arp -a" style dump
//   VirtualLan  learning L2 switch (floods broadcast/unknown unicast), loss simulation, mirrors every frame to the Tap
//   ArpHost     request/reply state machine, retry with exponential backoff, gratuitous ARP, probes,
//               proxy ARP, duplicate-IP detection, cache-poisoning-able (unless static entries are used)
#pragma once
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <map>
#include <mutex>
#include <random>
#include <set>
#include <sstream>

#include "net_io.hpp"

namespace netlab {

using Clock = std::chrono::steady_clock;

// ---------------------------------------------------------------------------------------------- ArpCache
class ArpCache {
 public:
  explicit ArpCache(int ttl_ms = 60000) : ttl_ms_(ttl_ms) {}
  void set_ttl_ms(int ms) { std::lock_guard<std::mutex> g(m_); ttl_ms_ = ms; }

  void insert(Ip4 ip, const Mac& mac, bool is_static = false) {
    std::lock_guard<std::mutex> g(m_);
    auto it = map_.find(ip);
    if (it != map_.end() && it->second.is_static && !is_static) return;  // static entries are immutable
    map_[ip] = {mac, Clock::now() + std::chrono::milliseconds(ttl_ms_), is_static};
  }
  bool has(Ip4 ip) { return lookup(ip).has_value(); }
  bool is_static(Ip4 ip) {
    std::lock_guard<std::mutex> g(m_);
    auto it = map_.find(ip);
    return it != map_.end() && it->second.is_static;
  }
  std::optional<Mac> lookup(Ip4 ip) {
    std::lock_guard<std::mutex> g(m_);
    auto it = map_.find(ip);
    if (it == map_.end()) return std::nullopt;
    if (!it->second.is_static && Clock::now() >= it->second.expiry) { map_.erase(it); return std::nullopt; }
    return it->second.mac;
  }
  size_t size() { std::lock_guard<std::mutex> g(m_); purge(); return map_.size(); }
  void flush() { std::lock_guard<std::mutex> g(m_); map_.clear(); }

  // "arp -a" style listing with a live remaining-TTL countdown.
  std::string dump() {
    std::lock_guard<std::mutex> g(m_);
    purge();
    std::ostringstream o;
    o << "Address          HWaddress           Type     TTL\n";
    for (auto& [ip, e] : map_) {
      char line[128];
      long left = e.is_static ? 0 : (long)std::chrono::duration_cast<std::chrono::seconds>(e.expiry - Clock::now()).count();
      std::snprintf(line, sizeof line, "%-16s %-19s %-8s %s\n", ip_str(ip).c_str(), e.mac.str().c_str(),
                    e.is_static ? "static" : "dynamic", e.is_static ? "-" : (std::to_string(left) + "s").c_str());
      o << line;
    }
    return o.str();
  }

 private:
  struct Entry { Mac mac; Clock::time_point expiry; bool is_static; };
  std::mutex m_;
  std::map<Ip4, Entry> map_;
  int ttl_ms_;
  void purge() {
    auto now = Clock::now();
    for (auto it = map_.begin(); it != map_.end();) it = (!it->second.is_static && now >= it->second.expiry) ? map_.erase(it) : std::next(it);
  }
};

// ---------------------------------------------------------------------------------------------- VirtualLan
class LanPort {
 public:
  virtual ~LanPort() = default;
  virtual Mac port_mac() const = 0;
  virtual void on_frame(const Bytes& frame) = 0;
};

class VirtualLan {
 public:
  void attach(LanPort* p) { std::lock_guard<std::mutex> g(m_); ports_.push_back(p); }
  void detach(LanPort* p) {
    std::lock_guard<std::mutex> g(m_);
    ports_.erase(std::remove(ports_.begin(), ports_.end(), p), ports_.end());
    for (auto it = table_.begin(); it != table_.end();) it = (it->second == p) ? table_.erase(it) : std::next(it);
  }
  void set_tap(TapSender* t) { std::lock_guard<std::mutex> g(m_); tap_ = t; }
  void set_loss_percent(int pct) { std::lock_guard<std::mutex> g(m_); loss_ = pct; }
  size_t frames() const { return frames_; }
  size_t dropped() const { return dropped_; }
  size_t mac_table_size() { std::lock_guard<std::mutex> g(m_); return table_.size(); }

  void transmit(LanPort* from, const Bytes& frame) {
    EthernetHeader eh;
    if (!EthernetHeader::parse(frame.data(), frame.size(), eh)) return;
    std::vector<LanPort*> targets;
    {
      std::lock_guard<std::mutex> g(m_);
      frames_++;
      if (loss_ > 0 && int(rng_() % 100) < loss_) { dropped_++; return; }
      if (tap_) tap_->emit(frame);  // the tap sees each frame once, as it enters the switch
      if (!eh.src.is_multicast()) table_[eh.src] = from;  // learn
      auto it = eh.dst.is_multicast() ? table_.end() : table_.find(eh.dst);
      if (it != table_.end()) { if (it->second != from) targets.push_back(it->second); }
      else for (auto* p : ports_) if (p != from) targets.push_back(p);  // flood
    }
    for (auto* p : targets) p->on_frame(frame);  // delivered outside the lock: hosts may reply re-entrantly
  }

 private:
  std::mutex m_;
  std::vector<LanPort*> ports_;
  std::map<Mac, LanPort*> table_;
  TapSender* tap_ = nullptr;
  int loss_ = 0;
  std::mt19937 rng_{12345};
  std::atomic<size_t> frames_{0}, dropped_{0};
};

// ---------------------------------------------------------------------------------------------- ArpHost
class ArpHost : public LanPort {
 public:
  ArpHost(VirtualLan& lan, std::string name, Mac mac, Ip4 ip) : lan_(lan), name_(std::move(name)), mac_(mac), ip_(ip) {
    lan_.attach(this);
  }
  ~ArpHost() override { lan_.detach(this); }

  const std::string& name() const { return name_; }
  Mac mac() const { return mac_; }
  Ip4 ip() const { return ip_; }
  void set_ip(Ip4 ip) { std::lock_guard<std::mutex> g(m_); ip_ = ip; }
  ArpCache& cache() { return cache_; }
  void add_proxy(Ip4 ip) { std::lock_guard<std::mutex> g(m_); proxy_.insert(ip); }
  // false (default, like Linux): a reply may only refresh entries we hold or answer a request we sent. true: it may create any.
  void set_learn_unsolicited(bool v) { learn_unsolicited_ = v; }
  std::vector<std::string> events() { std::lock_guard<std::mutex> g(m_); return events_; }
  size_t requests_sent() const { return req_sent_; }
  size_t replies_sent() const { return rep_sent_; }

  // Resolve ip -> MAC. Sends up to `max_tries` broadcast requests; waits base, 2*base, 4*base ms (exponential backoff).
  std::optional<Mac> resolve(Ip4 target, int base_timeout_ms = 150, int max_tries = 3) {
    if (auto m = cache_.lookup(target)) return m;
    int wait = base_timeout_ms;
    { std::lock_guard<std::mutex> g(m_); pending_.insert(target); }  // replies are only accepted for IPs we asked about
    std::optional<Mac> result;
    for (int t = 0; t < max_tries && !result; t++) {
      send_request(target);
      std::unique_lock<std::mutex> lk(m_);
      if (cv_.wait_for(lk, std::chrono::milliseconds(wait), [&] { return cache_.has(target); })) result = cache_.lookup(target);
      wait *= 2;
    }
    { std::lock_guard<std::mutex> g(m_); pending_.erase(target); }
    return result;
  }

  // Gratuitous ARP announcement (request with SPA == TPA). Refreshes neighbours' caches.
  void announce() {
    ArpPacket a; a.oper = ARP_REQUEST; a.sha = mac_; a.spa = ip_; a.tpa = ip_;
    send(Mac::broadcast(), a);
  }

  // RFC 5227 probe: ARP request with sender IP 0.0.0.0. Returns true if nobody claimed `candidate`.
  bool probe(Ip4 candidate, int timeout_ms = 200) {
    {
      std::lock_guard<std::mutex> g(m_);
      probing_ = true; probe_ip_ = candidate; conflict_ = false;
    }
    ArpPacket a; a.oper = ARP_REQUEST; a.sha = mac_; a.spa = 0; a.tpa = candidate;
    send(Mac::broadcast(), a);
    std::unique_lock<std::mutex> lk(m_);
    cv_.wait_for(lk, std::chrono::milliseconds(timeout_ms), [&] { return conflict_; });
    probing_ = false;
    return !conflict_;
  }

  // ARP spoofing primitive: tell `to_ip` that `claimed_ip` lives at OUR MAC (an unsolicited reply).
  void send_unsolicited_reply(Ip4 claimed_ip, Ip4 to_ip, const Mac& to_mac) {
    ArpPacket a; a.oper = ARP_REPLY; a.sha = mac_; a.spa = claimed_ip; a.tha = to_mac; a.tpa = to_ip;
    send(to_mac, a);
  }

  // LanPort
  Mac port_mac() const override { return mac_; }
  void on_frame(const Bytes& f) override {
    EthernetHeader eh;
    if (!EthernetHeader::parse(f.data(), f.size(), eh) || eh.type != ETH_ARP) return;
    if (eh.dst != mac_ && !eh.dst.is_broadcast()) return;  // NIC filter
    ArpPacket a;
    if (!ArpPacket::parse(f.data() + ETH_HLEN, f.size() - ETH_HLEN, a) || a.ptype != ETH_IPV4) return;

    std::optional<std::pair<Mac, ArpPacket>> reply;
    {
      std::lock_guard<std::mutex> g(m_);
      // RFC 5227 conflict detection: somebody else claims our address (or the one we are probing).
      Ip4 watched = probing_ ? probe_ip_ : ip_;
      if (a.spa != 0 && a.spa == watched && a.sha != mac_) {
        events_.push_back("CONFLICT: " + a.sha.str() + " claims " + ip_str(a.spa));
        if (probing_) conflict_ = true;
      }
      if (probing_ && a.spa == 0 && a.tpa == probe_ip_ && a.sha != mac_) conflict_ = true;  // simultaneous probe

      bool for_me = (a.tpa == ip_);
      bool target_us = for_me || proxy_.count(a.tpa) > 0;
      bool merged = false;
      if (a.spa != 0 && cache_.has(a.spa)) {  // RFC 826: refresh an entry we already hold
        if (cache_.is_static(a.spa)) events_.push_back("IGNORED update for static entry " + ip_str(a.spa));
        else { cache_.insert(a.spa, a.sha); merged = true; }
      }
      if (a.spa != 0 && a.spa != ip_ && !merged && !cache_.has(a.spa) &&
          ((a.oper == ARP_REQUEST && target_us) ||
           (a.oper == ARP_REPLY && (pending_.count(a.spa) || learn_unsolicited_))))
        cache_.insert(a.spa, a.sha);  // new entry: only if the packet is for us (or we are permissive)

      if (a.oper == ARP_REQUEST && target_us && a.sha != mac_ && !a.is_gratuitous()) {
        ArpPacket r; r.oper = ARP_REPLY; r.sha = mac_; r.spa = a.tpa; r.tha = a.sha; r.tpa = a.spa;
        reply = {a.sha, r};
      }
    }
    cv_.notify_all();
    if (reply) send(reply->first, reply->second);
  }

 private:
  VirtualLan& lan_;
  std::string name_;
  Mac mac_;
  Ip4 ip_;
  ArpCache cache_;
  std::set<Ip4> proxy_, pending_;
  std::mutex m_;
  std::condition_variable cv_;
  std::vector<std::string> events_;
  std::atomic<size_t> req_sent_{0}, rep_sent_{0};
  std::atomic<bool> learn_unsolicited_{false};
  bool probing_ = false, conflict_ = false;
  Ip4 probe_ip_ = 0;

  void send_request(Ip4 target) {
    ArpPacket a; a.oper = ARP_REQUEST; a.sha = mac_; a.spa = ip_; a.tpa = target;
    send(Mac::broadcast(), a);
  }
  void send(const Mac& dst, const ArpPacket& a) {
    (a.oper == ARP_REQUEST ? req_sent_ : rep_sent_)++;
    lan_.transmit(this, make_eth_frame(dst, mac_, ETH_ARP, a.serialize()));
  }
};

}  // namespace netlab
