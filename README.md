# Custom ARP + Telnet Protocol Suite & Mini-Wireshark

A modular C++17 networking lab project implementing **ARP** (RFC 826 / RFC 5227) over a simulated Ethernet segment and
**Telnet** (RFC 854-858, 1073, 1091) over real TCP sockets, paired with a Mini-Wireshark packet dissector and `.pcap` exporter.
Same architecture as the BOOTP + DNS suite: protocol headers -> sockets/tap -> engines -> dissector -> 3-pane Win32 UI.

## Project Phases

1. **Phase 1 - Wire Formats & Socket/Tap Foundation**
   * `include/l2l4_headers.hpp`: big-endian Ethernet II, ARP, IPv4, TCP (pseudo-header checksums), and a streaming Telnet NVT parser
     (`IAC` commands, `WILL/WONT/DO/DONT`, `SB..SE`, escaped `0xFF`, sequences split across TCP segments).
   * `include/net_io.hpp`: cross-platform RAII UDP/TCP `Socket` (Winsock2 on Windows) and `TapSender`
     (tap datagram = `NLT2` + timestamp + raw Ethernet frame, UDP -> `127.0.0.1:9998`).
   * `src/phase1_test.cpp`
2. **Phase 2 - Custom ARP Engine**
   * `include/arp_engine.hpp`: `ArpCache` (TTL, static entries, `arp -a` dump), `VirtualLan` (learning L2 switch, flooding, loss simulation,
     mirrors every frame to the tap), `ArpHost` (request/reply, retry with exponential backoff, gratuitous ARP, RFC 5227 probes,
     proxy ARP, duplicate-IP detection, Linux-style acceptance rules so spoofing demos are realistic).
   * `src/arp_lab_main.cpp` (scripted demo or `--interactive` shell), `src/phase2_test.cpp`
3. **Phase 3 - Custom Telnet Engine**
   * `include/telnet_engine.hpp`: `TelnetServer` (option negotiation, login with 3 attempts, line editor with backspace/Ctrl-C/Ctrl-D,
     tiny shell: `help whoami hostname uname date arp who echo clear exit`), `TelnetClient` (answers negotiation, NAWS + TTYPE, scripted or interactive),
     `TcpTap` (synthesizes Ethernet+IPv4+TCP frames with valid seq/ack/checksums: SYN, SYN/ACK, ACK, PSH/ACK, FIN).
   * `include/demos.hpp`, `src/telnet_server_main.cpp`, `src/telnet_client_main.cpp`, `src/phase3_test.cpp`
4. **Phase 4 - Dissector Engine & `.pcap` Exporter**
   * `include/dissector.hpp`: `Ethernet II -> ARP` and `Ethernet II -> IPv4 -> TCP -> Telnet` with byte-offset tracking, checksum verification
     (bad checksums are flagged red), ARP expert info (gratuitous / probe), and Wireshark-like display filters:
     `arp`, `telnet`, `tcp`, `ip == 1.2.3.4`, `port == 23`, `eth.addr == ..`, `arp.opcode == 2`, `arp.src.proto_ipv4 == ..`,
     `tcp.flags.syn`, combined with `&&` `||` `!` `( )` (or `and` `or` `not`).
   * `include/pcap_writer.hpp`: standard libpcap export & import (`LINKTYPE_ETHERNET`) - files open in real Wireshark.
   * `include/capture_session.hpp`: thread-safe live tap sniffer & packet store.
   * `src/sniffer_cli_main.cpp` (`--filter --tree --hex --out --read`), `src/phase4_test.cpp`
5. **Phase 5 - Mini-Wireshark 3-Pane Visual UI**
   * `src/mini_wireshark_main.cpp`: native Win32 GUI (`mini_wireshark.exe`):
     * Pane 1 (Packet List): colour-coded rows (`ARP` pale yellow, `Telnet` lavender, TCP control grey, errors light red), live auto-scroll.
     * Pane 2 (Dissector Tree): collapsible layers (`Frame`, `Ethernet II`, `ARP` | `IPv4`, `TCP`, `Telnet` with per-option sub-fields).
     * Pane 3 (Hex + ASCII): custom GDI view highlighting the exact bytes of whichever tree field is selected.
     * Toolbar: Start/Stop Capture, Clear, Open/Save `.pcap`, Display Filter (Enter or Apply), one-click **Run ARP+Telnet Demo**.

## Building (Windows MSYS2 / MinGW g++)

    ./build_all.ps1            # builds all targets and runs the four test suites  (-SkipTests to skip)

Linux / WSL (core + tests, sanitizers on): `make test`.

## Live Demo Quick-Start

1. **All-in-one:** launch `build/mini_wireshark.exe` and click **Run ARP+Telnet Demo**. Try filters: `arp.isgratuitous`, `arp.opcode == 2`,
   `telnet && ip.src == 192.168.1.10` (the client's password is visible in clear text), `tcp.flags.syn`.
2. **Multi-terminal:**
   * Terminal 1: `build/mini_wireshark.exe`   (or `build/sniffer_cli.exe --tree`)
   * Terminal 2: `build/arp_lab.exe`          (or `--interactive`: `resolve alice 192.168.1.1`, `spoof alice 192.168.1.1`, `static bob 192.168.1.1 02:00:00:00:00:01`)
   * Terminal 3: `build/telnet_server.exe`    (users `admin/netlab`, `guest/guest`)
   * Terminal 4: `build/telnet_client.exe`    (interactive) or `--user admin --pass netlab --cmd arp --cmd whoami`

## Adding this to the BOOTP + DNS project

The suites are independent (separate tap port 9998 vs 9999, own headers) so both can run side by side. To get ONE Wireshark showing all four
protocols: add `case 0x0806` (ARP) and the TCP/23 branch from `dissector.hpp` into your `dissect()`, and have your `TapMirror` emit the same
`NLT2` datagram (or keep two `CaptureSession`s). Colours/filters follow the same pattern.
