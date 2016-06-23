CC ?= $(CROSS_COMPILE)gcc
CFLAGS += -g

TARGET_BINARIES := ut-client ut-server ut-bridge

all: $(TARGET_BINARIES)

ut-client: ut_client.o library.o
	$(CC) -o $@ $^ $(LDFLAGS)

ut-server: ut_server.o library.o
	$(CC) -o $@ $^ $(LDFLAGS)

ut-bridge: ut_bridge.o library.o
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c library.h list.h
	$(CC) -c -Wall $(CFLAGS) -o $@ $<

install: all
	cp -f $(TARGET_BINARIES) /usr/local/bin/

up: clean
	@echo "Nothing done"

clean:
	rm -f *.o $(TARGET_BINARIES)
