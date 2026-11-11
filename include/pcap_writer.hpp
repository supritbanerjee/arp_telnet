// Phase 4 - Standard libpcap file export/import (LINKTYPE_ETHERNET = 1, microsecond timestamps).
// Files written here open directly in real Wireshark / tcpdump.
#pragma once
#include <cstdio>
#include <string>
#include <vector>

#include "l2l4_headers.hpp"

namespace netlab {

struct CapturedPacket {
  uint32_t no = 0;
  double ts = 0;  // seconds since the epoch
  Bytes frame;
};

namespace pcap_detail {
inline void le16(Bytes& b, uint16_t v) { b.push_back(uint8_t(v)); b.push_back(uint8_t(v >> 8)); }
inline void le32(Bytes& b, uint32_t v) { for (int s = 0; s < 32; s += 8) b.push_back(uint8_t(v >> s)); }
inline uint32_t rd32(const uint8_t* p, bool swap) {
  return swap ? (uint32_t(p[0]) << 24) | (uint32_t(p[1]) << 16) | (uint32_t(p[2]) << 8) | p[3]
              : (uint32_t(p[3]) << 24) | (uint32_t(p[2]) << 16) | (uint32_t(p[1]) << 8) | p[0];
}
}  // namespace pcap_detail

inline bool write_pcap(const std::string& path, const std::vector<CapturedPacket>& pkts) {
  using namespace pcap_detail;
  Bytes out;
  le32(out, 0xA1B2C3D4); le16(out, 2); le16(out, 4); le32(out, 0); le32(out, 0); le32(out, 65535); le32(out, 1);
  for (auto& p : pkts) {
    uint32_t sec = uint32_t(p.ts), usec = uint32_t((p.ts - sec) * 1e6);
    le32(out, sec); le32(out, usec); le32(out, uint32_t(p.frame.size())); le32(out, uint32_t(p.frame.size()));
    out.insert(out.end(), p.frame.begin(), p.frame.end());
  }
  FILE* f = std::fopen(path.c_str(), "wb");
  if (!f) return false;
  bool ok = std::fwrite(out.data(), 1, out.size(), f) == out.size();
  std::fclose(f);
  return ok;
}

inline bool read_pcap(const std::string& path, std::vector<CapturedPacket>& out, std::string* err = nullptr) {
  using namespace pcap_detail;
  auto fail = [&](const char* m) { if (err) *err = m; return false; };
  FILE* f = std::fopen(path.c_str(), "rb");
  if (!f) return fail("cannot open file");
  Bytes d; uint8_t buf[65536]; size_t k;
  while ((k = std::fread(buf, 1, sizeof buf, f)) > 0) d.insert(d.end(), buf, buf + k);
  std::fclose(f);
  if (d.size() < 24) return fail("file too short");
  uint32_t magic = rd32(d.data(), false);
  bool swap = false, nano = false;
  if (magic == 0xA1B2C3D4) {} else if (magic == 0xD4C3B2A1) swap = true;
  else if (magic == 0xA1B23C4D) nano = true; else if (magic == 0x4D3CB2A1) { swap = true; nano = true; }
  else return fail("not a pcap file");
  if (rd32(d.data() + 20, swap) != 1) return fail("unsupported link type (need Ethernet)");
  out.clear();
  size_t pos = 24; uint32_t no = 1;
  while (pos + 16 <= d.size()) {
    uint32_t sec = rd32(&d[pos], swap), frac = rd32(&d[pos + 4], swap), incl = rd32(&d[pos + 8], swap);
    pos += 16;
    if (pos + incl > d.size()) return fail("truncated packet record");
    CapturedPacket p; p.no = no++; p.ts = sec + frac / (nano ? 1e9 : 1e6);
    p.frame.assign(d.begin() + pos, d.begin() + pos + incl);
    out.push_back(std::move(p)); pos += incl;
  }
  return true;
}

}  // namespace netlab
