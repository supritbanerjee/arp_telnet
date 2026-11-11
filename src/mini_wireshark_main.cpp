// Phase 5 - Mini-Wireshark: native Win32 3-pane UI for ARP + Telnet.
//   Pane 1  packet list (virtual ListView, colour-coded, live auto-scroll)
//   Pane 2  protocol dissector tree (Frame > Ethernet II > ARP | IPv4 > TCP > Telnet)
//   Pane 3  hex + ASCII inspector (custom GDI control; selecting a tree field highlights its exact bytes)
// Toolbar: Start/Stop capture, Clear, Open/Save .pcap, display filter, one-click ARP+Telnet demo.
#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include "net_io.hpp"  // pulls in winsock2 before windows.h

#include <commctrl.h>
#include <commdlg.h>
#include <windows.h>

#include <atomic>
#include <memory>
#include <thread>

#include "capture_session.hpp"
#include "demos.hpp"
#include "dissector.hpp"

using namespace netlab;

enum {
  IDC_START = 101, IDC_STOP, IDC_CLEAR, IDC_OPEN, IDC_SAVE, IDC_FILTER_LABEL, IDC_FILTER, IDC_APPLY, IDC_DEMO,
  IDC_LIST = 120, IDC_TREE, IDC_HEX, IDC_STATUS
};
constexpr UINT WM_APP_PKT = WM_APP + 1, WM_APP_LOG = WM_APP + 2, WM_APP_DEMO_DONE = WM_APP + 3;
constexpr int TOOLBAR_H = 38;

// ------------------------------------------------------------------------------------------------ hex control
struct HexState {
  Bytes data;
  int selOff = -1, selLen = 0, top = 0, cw = 8, ch = 16;
  HFONT font = nullptr;
} hx;

static int hex_rows() { return std::max<int>(1, int((hx.data.size() + 15) / 16)); }
static void hex_scrollbar(HWND h) {
  RECT rc; GetClientRect(h, &rc);
  int page = std::max(1, int(rc.bottom) / hx.ch);
  hx.top = std::max(0, std::min(hx.top, hex_rows() - page));
  SCROLLINFO si{sizeof si, SIF_RANGE | SIF_PAGE | SIF_POS, 0, hex_rows() - 1, UINT(page), hx.top, 0};
  SetScrollInfo(h, SB_VERT, &si, TRUE);
}
static void hex_set(HWND h, const Bytes& d) { hx.data = d; hx.selOff = -1; hx.selLen = 0; hx.top = 0; hex_scrollbar(h); InvalidateRect(h, nullptr, TRUE); }
static void hex_select(HWND h, int off, int len) {
  hx.selOff = off; hx.selLen = len;
  if (off >= 0) {
    RECT rc; GetClientRect(h, &rc);
    int page = std::max(1, int(rc.bottom) / hx.ch), row = off / 16;
    if (row < hx.top || row >= hx.top + page) hx.top = row;
    hex_scrollbar(h);
  }
  InvalidateRect(h, nullptr, FALSE);
}

static LRESULT CALLBACK HexProc(HWND h, UINT m, WPARAM w, LPARAM l) {
  switch (m) {
    case WM_CREATE: {
      hx.font = CreateFontA(-15, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas");
      HDC dc = GetDC(h); HGDIOBJ old = SelectObject(dc, hx.font); TEXTMETRICA tm; GetTextMetricsA(dc, &tm);
      hx.cw = tm.tmAveCharWidth; hx.ch = tm.tmHeight + 1; SelectObject(dc, old); ReleaseDC(h, dc);
      return 0;
    }
    case WM_SIZE: hex_scrollbar(h); return 0;
    case WM_ERASEBKGND: return 1;
    case WM_VSCROLL: {
      SCROLLINFO si{sizeof si, SIF_ALL}; GetScrollInfo(h, SB_VERT, &si);
      int t = si.nPos;
      switch (LOWORD(w)) {
        case SB_LINEUP: t--; break; case SB_LINEDOWN: t++; break;
        case SB_PAGEUP: t -= si.nPage; break; case SB_PAGEDOWN: t += si.nPage; break;
        case SB_THUMBTRACK: case SB_THUMBPOSITION: t = si.nTrackPos; break;
      }
      hx.top = t; hex_scrollbar(h); InvalidateRect(h, nullptr, FALSE);
      return 0;
    }
    case WM_MOUSEWHEEL: hx.top -= GET_WHEEL_DELTA_WPARAM(w) / WHEEL_DELTA * 3; hex_scrollbar(h); InvalidateRect(h, nullptr, FALSE); return 0;
    case WM_PAINT: {
      PAINTSTRUCT ps; HDC dc = BeginPaint(h, &ps); RECT rc; GetClientRect(h, &rc);
      HDC mdc = CreateCompatibleDC(dc); HBITMAP bmp = CreateCompatibleBitmap(dc, rc.right, rc.bottom);
      HGDIOBJ ob = SelectObject(mdc, bmp), of = SelectObject(mdc, hx.font);
      FillRect(mdc, &rc, (HBRUSH)GetStockObject(WHITE_BRUSH));
      SetBkMode(mdc, TRANSPARENT);
      HBRUSH sel = CreateSolidBrush(RGB(150, 200, 255)), asel = CreateSolidBrush(RGB(255, 220, 140));
      int rows = rc.bottom / hx.ch + 1;
      for (int r = 0; r < rows; r++) {
        size_t base = size_t(hx.top + r) * 16;
        if (base >= hx.data.size()) break;
        int y = r * hx.ch; char buf[8];
        SetTextColor(mdc, RGB(110, 110, 110));
        std::snprintf(buf, sizeof buf, "%04zx", base); TextOutA(mdc, 4, y, buf, 4);
        for (int i = 0; i < 16 && base + i < hx.data.size(); i++) {
          int idx = int(base + i);
          bool s = hx.selOff >= 0 && idx >= hx.selOff && idx < hx.selOff + hx.selLen;
          int hxcol = 6 + i * 3 + (i >= 8 ? 1 : 0), ascol = 6 + 16 * 3 + 1 + 2 + i;
          RECT a{4 + hxcol * hx.cw, y, 4 + (hxcol + 2) * hx.cw, y + hx.ch}, b{4 + ascol * hx.cw, y, 4 + (ascol + 1) * hx.cw, y + hx.ch};
          if (s) { FillRect(mdc, &a, sel); FillRect(mdc, &b, asel); }
          SetTextColor(mdc, RGB(0, 0, 0));
          std::snprintf(buf, sizeof buf, "%02x", hx.data[idx]); TextOutA(mdc, a.left, y, buf, 2);
          uint8_t c = hx.data[idx]; char ch = (c >= 32 && c < 127) ? char(c) : '.'; TextOutA(mdc, b.left, y, &ch, 1);
        }
      }
      DeleteObject(sel); DeleteObject(asel);
      BitBlt(dc, 0, 0, rc.right, rc.bottom, mdc, 0, 0, SRCCOPY);
      SelectObject(mdc, of); SelectObject(mdc, ob); DeleteObject(bmp); DeleteDC(mdc);
      EndPaint(h, &ps);
      return 0;
    }
    case WM_DESTROY: if (hx.font) DeleteObject(hx.font); return 0;
  }
  return DefWindowProcA(h, m, w, l);
}

// ------------------------------------------------------------------------------------------------ application state
struct App {
  HWND hwnd = nullptr, list = nullptr, tree = nullptr, hex = nullptr, status = nullptr, filterEdit = nullptr;
  CaptureSession cap{DEFAULT_TAP_PORT};
  std::vector<CapturedPacket> pkts;
  std::vector<Dissected> dis;
  std::vector<int> view;                      // indices into pkts/dis that pass the filter
  std::vector<std::pair<int, int>> ranges;    // tree item lParam -> (offset, length)
  DisplayFilter filter;
  std::atomic<bool> pending{false}, demoBusy{false};
  std::thread demo;
  std::string lastLog;
} g;

static COLORREF row_color(Color c) {
  switch (c) {
    case Color::Arp: return RGB(255, 243, 200);
    case Color::Telnet: return RGB(222, 214, 255);
    case Color::TcpCtl: return RGB(228, 228, 228);
    case Color::Error: return RGB(255, 190, 190);
    default: return RGB(255, 255, 255);
  }
}

static void set_status() {
  std::string s = (g.cap.running() ? "Capturing on tap 127.0.0.1:" + std::to_string(g.cap.port()) : std::string("Capture stopped")) +
                  "   |   Packets: " + std::to_string(g.pkts.size()) + "   Displayed: " + std::to_string(g.view.size());
  if (!g.filter.empty()) s += "   (filtered)";
  if (!g.lastLog.empty()) s += "   |   " + g.lastLog;
  SendMessageA(g.status, SB_SETTEXTA, 0, (LPARAM)s.c_str());
}

static void fill_tree(HTREEITEM parent, const std::vector<Node>& v) {
  for (auto& n : v) {
    TVINSERTSTRUCTA is{};
    is.hParent = parent; is.hInsertAfter = TVI_LAST; is.item.mask = TVIF_TEXT | TVIF_PARAM;
    is.item.pszText = const_cast<char*>(n.text.c_str());
    is.item.lParam = LPARAM(g.ranges.size());
    g.ranges.push_back({n.off, n.len});
    HTREEITEM h = (HTREEITEM)SendMessageA(g.tree, TVM_INSERTITEMA, 0, (LPARAM)&is);
    fill_tree(h, n.kids);
  }
}

static void show_packet(int viewIdx) {
  TreeView_DeleteAllItems(g.tree);
  g.ranges.clear();
  if (viewIdx < 0 || viewIdx >= int(g.view.size())) { hex_set(g.hex, {}); return; }
  int i = g.view[viewIdx];
  SendMessage(g.tree, WM_SETREDRAW, FALSE, 0);
  fill_tree(TVI_ROOT, g.dis[i].tree);
  bool first = true;  // expand every protocol layer except the (boring) Frame node
  for (HTREEITEM h = TreeView_GetRoot(g.tree); h; h = TreeView_GetNextSibling(g.tree, h)) {
    if (!first) TreeView_Expand(g.tree, h, TVE_EXPAND);
    first = false;
  }
  SendMessage(g.tree, WM_SETREDRAW, TRUE, 0);
  hex_set(g.hex, g.pkts[i].frame);
}

static void refresh_list(bool keepBottom) {
  ListView_SetItemCountEx(g.list, int(g.view.size()), LVSICF_NOINVALIDATEALL | LVSICF_NOSCROLL);
  InvalidateRect(g.list, nullptr, FALSE);
  if (keepBottom && !g.view.empty()) ListView_EnsureVisible(g.list, int(g.view.size()) - 1, FALSE);
  set_status();
}

static void rebuild_view() {
  g.view.clear();
  for (int i = 0; i < int(g.dis.size()); i++) if (g.filter.match(g.dis[i])) g.view.push_back(i);
  ListView_SetItemState(g.list, -1, 0, LVIS_SELECTED);
  show_packet(-1);
  refresh_list(true);
}

static void pump() {  // pull new packets from the capture session into the UI model
  auto v = g.cap.snapshot(g.pkts.size());
  if (v.empty()) return;
  for (auto& p : v) {
    g.dis.push_back(dissect(p.frame, p.no, p.ts));
    g.pkts.push_back(std::move(p));
    if (g.filter.match(g.dis.back())) g.view.push_back(int(g.dis.size()) - 1);
  }
  refresh_list(true);
}

static void clear_all() {
  g.cap.clear(); g.pkts.clear(); g.dis.clear(); g.view.clear();
  show_packet(-1); refresh_list(false);
}

static void apply_filter() {
  char buf[512]; GetWindowTextA(g.filterEdit, buf, sizeof buf);
  DisplayFilter f; std::string err;
  if (!f.compile(buf, &err)) { g.lastLog = "Filter error: " + err; set_status(); MessageBeep(MB_ICONEXCLAMATION); return; }
  g.filter = f; g.lastLog.clear();
  rebuild_view();
}

static bool start_capture() {
  std::string err;
  if (g.cap.running()) return true;
  if (!g.cap.start(&err)) { MessageBoxA(g.hwnd, (err + "\n(Is another sniffer already using this port?)").c_str(), "Mini-Wireshark", MB_ICONERROR); return false; }
  g.cap.set_on_packet([] { if (!g.pending.exchange(true)) PostMessageA(g.hwnd, WM_APP_PKT, 0, 0); });
  set_status();
  return true;
}

static void open_pcap() {
  char path[MAX_PATH] = "";
  OPENFILENAMEA o{sizeof o}; o.hwndOwner = g.hwnd; o.lpstrFile = path; o.nMaxFile = MAX_PATH;
  o.lpstrFilter = "Capture files (*.pcap)\0*.pcap;*.cap\0All files\0*.*\0"; o.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
  if (!GetOpenFileNameA(&o)) return;
  std::vector<CapturedPacket> v; std::string err;
  if (!read_pcap(path, v, &err)) { MessageBoxA(g.hwnd, err.c_str(), "Open failed", MB_ICONERROR); return; }
  g.cap.stop();
  g.pkts.clear(); g.dis.clear(); g.view.clear();
  g.cap.load(std::move(v));
  pump(); rebuild_view();
  g.lastLog = std::string("Opened ") + path; set_status();
}

static void save_pcap() {
  char path[MAX_PATH] = "capture.pcap";
  OPENFILENAMEA o{sizeof o}; o.hwndOwner = g.hwnd; o.lpstrFile = path; o.nMaxFile = MAX_PATH; o.lpstrDefExt = "pcap";
  o.lpstrFilter = "Capture files (*.pcap)\0*.pcap\0"; o.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;
  if (!GetSaveFileNameA(&o)) return;
  g.lastLog = write_pcap(path, g.pkts) ? std::string("Saved ") + std::to_string(g.pkts.size()) + " packets to " + path : "Save FAILED";
  set_status();
}

static void run_demo() {
  if (g.demoBusy.exchange(true)) return;
  if (g.demo.joinable()) g.demo.join();
  if (!start_capture()) { g.demoBusy = false; return; }
  uint16_t port = g.cap.port();
  g.demo = std::thread([port] {
    TapSender tap(port);
    Say say = [](const std::string& s) { PostMessageA(g.hwnd, WM_APP_LOG, 0, (LPARAM) new std::string(s)); };
    std::string arp = run_arp_demo(&tap, say);
    run_telnet_demo(&tap, arp, say);
    g.demoBusy = false;
    PostMessageA(g.hwnd, WM_APP_DEMO_DONE, 0, 0);
  });
}

// ------------------------------------------------------------------------------------------------ main window
static WNDPROC oldEdit;
static LRESULT CALLBACK EditProc(HWND h, UINT m, WPARAM w, LPARAM l) {
  if (m == WM_CHAR && w == VK_RETURN) { SendMessageA(GetParent(h), WM_COMMAND, MAKEWPARAM(IDC_APPLY, BN_CLICKED), 0); return 0; }
  return CallWindowProcA(oldEdit, h, m, w, l);
}

static void layout() {
  RECT rc; GetClientRect(g.hwnd, &rc);
  SendMessage(g.status, WM_SIZE, 0, 0);
  RECT sr; GetWindowRect(g.status, &sr);
  int sbH = sr.bottom - sr.top, avail = std::max(120, int(rc.bottom) - TOOLBAR_H - sbH);
  int h1 = avail * 40 / 100, h2 = avail * 30 / 100, h3 = avail - h1 - h2, W = rc.right;
  MoveWindow(g.list, 0, TOOLBAR_H, W, h1, TRUE);
  MoveWindow(g.tree, 0, TOOLBAR_H + h1, W, h2, TRUE);
  MoveWindow(g.hex, 0, TOOLBAR_H + h1 + h2, W, h3, TRUE);
}

static LRESULT CALLBACK MainProc(HWND h, UINT m, WPARAM w, LPARAM l) {
  switch (m) {
    case WM_CREATE: {
      g.hwnd = h;
      HFONT gui = (HFONT)GetStockObject(DEFAULT_GUI_FONT);
      struct B { int id; const char* t; int w; } bs[] = {{IDC_START, "Start Capture", 100}, {IDC_STOP, "Stop", 60}, {IDC_CLEAR, "Clear", 60},
                                                          {IDC_OPEN, "Open .pcap", 84}, {IDC_SAVE, "Save .pcap", 84}};
      int x = 6;
      for (auto& b : bs) { HWND c = CreateWindowA("BUTTON", b.t, WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, x, 6, b.w, 26, h, (HMENU)(INT_PTR)b.id, nullptr, nullptr); SendMessage(c, WM_SETFONT, (WPARAM)gui, TRUE); x += b.w + 4; }
      x += 10;
      HWND lbl = CreateWindowA("STATIC", "Display filter:", WS_CHILD | WS_VISIBLE | SS_CENTERIMAGE, x, 6, 88, 26, h, (HMENU)IDC_FILTER_LABEL, nullptr, nullptr);
      SendMessage(lbl, WM_SETFONT, (WPARAM)gui, TRUE); x += 90;
      g.filterEdit = CreateWindowExA(WS_EX_CLIENTEDGE, "EDIT", "", WS_CHILD | WS_VISIBLE | ES_AUTOHSCROLL, x, 6, 300, 26, h, (HMENU)IDC_FILTER, nullptr, nullptr);
      SendMessage(g.filterEdit, WM_SETFONT, (WPARAM)gui, TRUE);
      SendMessageA(g.filterEdit, EM_SETCUEBANNER, TRUE, (LPARAM)L"arp | telnet | tcp | ip == 192.168.1.1 | port == 23 | arp.opcode == 2 && !telnet");
      oldEdit = (WNDPROC)SetWindowLongPtrA(g.filterEdit, GWLP_WNDPROC, (LONG_PTR)EditProc);
      x += 304;
      HWND ap = CreateWindowA("BUTTON", "Apply", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, x, 6, 60, 26, h, (HMENU)IDC_APPLY, nullptr, nullptr);
      SendMessage(ap, WM_SETFONT, (WPARAM)gui, TRUE); x += 74;
      HWND dm = CreateWindowA("BUTTON", "Run ARP+Telnet Demo", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON, x, 6, 160, 26, h, (HMENU)IDC_DEMO, nullptr, nullptr);
      SendMessage(dm, WM_SETFONT, (WPARAM)gui, TRUE);

      g.list = CreateWindowExA(WS_EX_CLIENTEDGE, WC_LISTVIEWA, "", WS_CHILD | WS_VISIBLE | LVS_REPORT | LVS_OWNERDATA | LVS_SINGLESEL | LVS_SHOWSELALWAYS,
                               0, 0, 10, 10, h, (HMENU)IDC_LIST, nullptr, nullptr);
      ListView_SetExtendedListViewStyle(g.list, LVS_EX_FULLROWSELECT | LVS_EX_GRIDLINES | LVS_EX_DOUBLEBUFFER);
      const char* cols[] = {"No.", "Time", "Source", "Destination", "Protocol", "Length", "Info"}; int cw[] = {60, 90, 150, 150, 75, 65, 700};
      for (int i = 0; i < 7; i++) { LVCOLUMNA c{}; c.mask = LVCF_TEXT | LVCF_WIDTH; c.pszText = const_cast<char*>(cols[i]); c.cx = cw[i]; SendMessageA(g.list, LVM_INSERTCOLUMNA, i, (LPARAM)&c); }
      g.tree = CreateWindowExA(WS_EX_CLIENTEDGE, WC_TREEVIEWA, "", WS_CHILD | WS_VISIBLE | TVS_HASLINES | TVS_HASBUTTONS | TVS_LINESATROOT | TVS_SHOWSELALWAYS,
                               0, 0, 10, 10, h, (HMENU)IDC_TREE, nullptr, nullptr);
      g.hex = CreateWindowExA(WS_EX_CLIENTEDGE, "MiniWSHex", "", WS_CHILD | WS_VISIBLE | WS_VSCROLL, 0, 0, 10, 10, h, (HMENU)IDC_HEX, nullptr, nullptr);
      g.status = CreateWindowA(STATUSCLASSNAMEA, "", WS_CHILD | WS_VISIBLE, 0, 0, 0, 0, h, (HMENU)IDC_STATUS, nullptr, nullptr);
      HFONT mono = CreateFontA(-14, 0, 0, 0, FW_NORMAL, 0, 0, 0, DEFAULT_CHARSET, 0, 0, DEFAULT_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas");
      SendMessage(g.tree, WM_SETFONT, (WPARAM)mono, TRUE); SendMessage(g.list, WM_SETFONT, (WPARAM)mono, TRUE);
      set_status();
      return 0;
    }
    case WM_SIZE: if (g.list) layout(); return 0;
    case WM_GETMINMAXINFO: ((MINMAXINFO*)l)->ptMinTrackSize = {900, 520}; return 0;
    case WM_COMMAND:
      switch (LOWORD(w)) {
        case IDC_START: start_capture(); break;
        case IDC_STOP: g.cap.stop(); set_status(); break;
        case IDC_CLEAR: clear_all(); break;
        case IDC_OPEN: open_pcap(); break;
        case IDC_SAVE: save_pcap(); break;
        case IDC_APPLY: apply_filter(); break;
        case IDC_DEMO: run_demo(); break;
      }
      return 0;
    case WM_NOTIFY: {
      NMHDR* nm = (NMHDR*)l;
      if (nm->hwndFrom == g.list) {
        if (nm->code == LVN_GETDISPINFOA) {
          NMLVDISPINFOA* di = (NMLVDISPINFOA*)l;
          if ((di->item.mask & LVIF_TEXT) && di->item.iItem >= 0 && di->item.iItem < int(g.view.size())) {
            const Dissected& d = g.dis[g.view[di->item.iItem]];
            double t0 = g.dis.empty() ? 0 : g.dis[0].ts; char buf[64]; std::string s;
            switch (di->item.iSubItem) {
              case 0: s = std::to_string(d.no); break;
              case 1: std::snprintf(buf, sizeof buf, "%.6f", d.ts - t0); s = buf; break;
              case 2: s = d.src; break; case 3: s = d.dst; break; case 4: s = d.proto; break;
              case 5: s = std::to_string(d.caplen); break; default: s = d.info; break;
            }
            std::snprintf(di->item.pszText, size_t(di->item.cchTextMax), "%s", s.c_str());
          }
        } else if (nm->code == LVN_ITEMCHANGED) {
          NMLISTVIEW* nl = (NMLISTVIEW*)l;
          if ((nl->uChanged & LVIF_STATE) && (nl->uNewState & LVIS_SELECTED) && !(nl->uOldState & LVIS_SELECTED)) show_packet(nl->iItem);
        } else if (nm->code == NM_CUSTOMDRAW) {
          NMLVCUSTOMDRAW* cd = (NMLVCUSTOMDRAW*)l;
          if (cd->nmcd.dwDrawStage == CDDS_PREPAINT) return CDRF_NOTIFYITEMDRAW;
          if (cd->nmcd.dwDrawStage == CDDS_ITEMPREPAINT) {
            int i = int(cd->nmcd.dwItemSpec);
            if (i >= 0 && i < int(g.view.size()) && !(cd->nmcd.uItemState & CDIS_SELECTED)) {
              cd->clrTextBk = row_color(g.dis[g.view[i]].color); cd->clrText = RGB(0, 0, 0);
            }
            return CDRF_NEWFONT;
          }
        }
      } else if (nm->hwndFrom == g.tree && nm->code == TVN_SELCHANGEDA) {
        NMTREEVIEWA* tv = (NMTREEVIEWA*)l;
        size_t k = size_t(tv->itemNew.lParam);
        if (k < g.ranges.size()) hex_select(g.hex, g.ranges[k].first, g.ranges[k].second);
      }
      return 0;
    }
    case WM_APP_PKT: g.pending = false; pump(); return 0;
    case WM_APP_LOG: {
      std::unique_ptr<std::string> s((std::string*)l);
      g.lastLog = s->substr(0, s->find('\n'));
      set_status();
      return 0;
    }
    case WM_APP_DEMO_DONE: pump(); g.lastLog = "Demo finished"; set_status(); return 0;
    case WM_DESTROY:
      g.cap.stop();
      if (g.demo.joinable()) g.demo.join();
      PostQuitMessage(0);
      return 0;
  }
  return DefWindowProcA(h, m, w, l);
}

int WINAPI WinMain(HINSTANCE inst, HINSTANCE, LPSTR, int show) {
  INITCOMMONCONTROLSEX ic{sizeof ic, ICC_LISTVIEW_CLASSES | ICC_TREEVIEW_CLASSES | ICC_BAR_CLASSES};
  InitCommonControlsEx(&ic);
  net_init();
  WNDCLASSA hc{}; hc.lpfnWndProc = HexProc; hc.hInstance = inst; hc.lpszClassName = "MiniWSHex"; hc.hCursor = LoadCursor(nullptr, IDC_ARROW);
  RegisterClassA(&hc);
  WNDCLASSA wc{}; wc.lpfnWndProc = MainProc; wc.hInstance = inst; wc.lpszClassName = "MiniWSMain"; wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
  wc.hbrBackground = (HBRUSH)(COLOR_BTNFACE + 1);
  RegisterClassA(&wc);
  HWND hw = CreateWindowA("MiniWSMain", "Mini-Wireshark - ARP + Telnet", WS_OVERLAPPEDWINDOW, CW_USEDEFAULT, CW_USEDEFAULT, 1280, 820, nullptr, nullptr, inst, nullptr);
  ShowWindow(hw, show);
  start_capture();  // live capture is on from the start, like Wireshark after picking an interface
  MSG msg;
  while (GetMessage(&msg, nullptr, 0, 0) > 0) { TranslateMessage(&msg); DispatchMessage(&msg); }
  return int(msg.wParam);
}
