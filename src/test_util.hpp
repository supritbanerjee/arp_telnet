#pragma once
#include <cstdio>
static int g_fail = 0, g_pass = 0;
#define CHECK(c) do { if (c) g_pass++; else { g_fail++; std::printf("  FAIL %s:%d  %s\n", __FILE__, __LINE__, #c); } } while (0)
#define TEST_MAIN_END(name) std::printf("%s: %d passed, %d failed\n", name, g_pass, g_fail); return g_fail ? 1 : 0
