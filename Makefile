# Each directory under tests/ builds to build/<dir>.exe (all .c in it + common/t.c).
# The DLL under test is deliberately NOT linked; everything resolves via GetProcAddress.
CC      = x86_64-w64-mingw32-gcc
CFLAGS  ?= -O1 -Wall -Wno-unused-function -Wno-unused-variable -Wno-unused-but-set-variable -Wno-format
AREAS   := $(notdir $(wildcard tests/*))
EXES    := $(addprefix build/,$(addsuffix .exe,$(AREAS)))
all: $(EXES)
.SECONDEXPANSION:
COMMON  := common/t.c common/t.h common/modules.h
build/%.exe: $$(wildcard tests/$$*/*.c) $$(wildcard tests/$$*/*.h) $(COMMON)
	@mkdir -p build
	$(CC) $(CFLAGS) -Icommon -o $@ $(wildcard tests/$*/*.c) common/t.c -static -lkernel32 -ladvapi32 -lntdll
# Harness self-test (not part of "all"): sources in selftest/; run it on the oracle in std and adm mode.
build/selftest.exe: $(wildcard selftest/*.c) $(wildcard selftest/*.h) $(COMMON)
	@mkdir -p build
	$(CC) $(CFLAGS) -Icommon -o $@ $(wildcard selftest/*.c) common/t.c -static -lkernel32 -ladvapi32 -lntdll
selftest: build/selftest.exe
clean: ; rm -rf build
# Validation under Wine in a headless sandbox (see tools/wine_run.sh). Windows is the authority.
wine-run: all
	@for e in $(EXES); do echo "== $$e"; tools/wine_run.sh $$e | grep -E '^(FAIL|SKIP|SUMMARY)|^  (FAIL|NOTE)'; done
.PHONY: all clean wine-run selftest
