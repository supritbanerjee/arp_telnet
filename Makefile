# Linux / WSL build of the core (everything except the Win32 GUI).   make test | make all | make gui-check
CXX ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -Iinclude -Isrc -pthread
CLI := arp_lab telnet_server telnet_client sniffer_cli
TESTS := phase1_test phase2_test phase3_test phase4_test
all: $(addprefix build/,$(CLI) $(TESTS))
build/%: src/%_main.cpp include/*.hpp ; @mkdir -p build && $(CXX) $(CXXFLAGS) $< -o $@
build/phase%_test: src/phase%_test.cpp include/*.hpp src/test_util.hpp ; @mkdir -p build && $(CXX) $(CXXFLAGS) -g -fsanitize=address,undefined $< -o $@
test: $(addprefix build/,$(TESTS)) ; cd build && for t in $(TESTS); do ./$$t || exit 1; done
# Cross-compile the Win32 GUI from Linux (needs g++-mingw-w64-x86-64) just to verify it builds
gui-check: ; x86_64-w64-mingw32-g++-posix -std=c++17 -O2 -Iinclude src/mini_wireshark_main.cpp -o build/mini_wireshark.exe -static -mwindows -lws2_32 -lcomctl32 -lcomdlg32 -lgdi32
.PHONY: all test gui-check
