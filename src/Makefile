ifndef MSYSTEM
	CPREFIX = x86_64-w64-mingw32-
endif

WINDIVERTHEADERS = ../../../include
WINDIVERTLIBS = ../../binary
MINGWLIB = /usr/x86_64-w64-mingw32/lib/

TARGET = goodbyedpi.exe
LIBS = -L$(WINDIVERTLIBS) -lWinDivert -lws2_32 -ladvapi32 -lshell32 -l:libssp.a
CC = $(CPREFIX)gcc

CCWINDRES = $(CPREFIX)windres
ifeq (, $(shell which $(CPREFIX)windres))
	CCWINDRES = windres
endif

CFLAGS = -std=c99 -pie -fPIE -pipe -I$(WINDIVERTHEADERS) -L$(WINDIVERTLIBS) \
         -O2 -D_FORTIFY_SOURCE=2 -D_WIN32_WINNT=0x0601 -fstack-protector \
         -Wall -Wextra -Wformat=2 -Wformat-overflow=2 -Wformat-truncation=2 \
         -Wformat-security -Wno-format-nonliteral -Wshadow -Wstrict-aliasing=1 \
         -Wnull-dereference -Warray-bounds=2 -Wimplicit-fallthrough=3 \
         -Wstringop-overflow=4 -Wstrict-overflow=2 -Wcast-align=strict \
         -Wfloat-equal -Wcast-align

LDFLAGS = -fstack-protector -Wl,-O1,-pie,--dynamicbase,--nxcompat,--sort-common,--as-needed \
-Wl,--disable-auto-image-base

ifdef BIT64
	LDFLAGS += -Wl,--high-entropy-va -Wl,--pic-executable,-e,mainCRTStartup
else
	CFLAGS += -m32
	LDFLAGS += -Wl,--pic-executable,-e,_mainCRTStartup -m32
endif

ifdef OPTIMIZE
ifdef BIT64
	CFLAGS += -O3 -flto -march=x86-64-v2 -fno-plt
else
	CFLAGS += -O3 -flto -msse4.2
endif
	LDFLAGS += -O3 -flto
endif

HOSTCC ?= gcc
HOST_CFLAGS = -std=gnu99 -I. -I../tests/shim -Wall -Wextra -Werror
ifdef OPTIMIZE
	HOST_CFLAGS += -O3 -flto -march=x86-64-v2 -fno-plt
else
	HOST_CFLAGS += -O2 -g
endif
ifdef SANITIZE
	HOST_CFLAGS += -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer
endif

HOST_SRCS = conntrack.c desync.c probe.c

.PHONY: default all clean test

default: $(TARGET)
all: default

OBJECTS = main.o conntrack.o desync.o probe.o goodbyedpi-rc.o
HEADERS = turkdpi.h

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) -c $< -o $@

goodbyedpi-rc.o:
	$(CCWINDRES) goodbyedpi-rc.rc goodbyedpi-rc.o

.PRECIOUS: $(TARGET) $(OBJECTS)

$(TARGET): $(OBJECTS)
	$(CC) $(OBJECTS) $(LDFLAGS) $(LIBS) -s -o $@

test:
	$(HOSTCC) $(HOST_CFLAGS) ../tests/bench_hotpath.c $(HOST_SRCS) -lm -o /tmp/goodbyedpi_bench_hotpath
	/tmp/goodbyedpi_bench_hotpath

clean:
	-rm -f *.o /tmp/goodbyedpi_bench_hotpath
	-rm -f $(TARGET)
