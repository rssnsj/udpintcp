CC ?= $(CROSS_COMPILE)gcc
CFLAGS += -g

all: ut-client ut-server

ut-client: ut_client.o library.o
	$(CC) -o $@ $^ $(LDFLAGS)

ut-server: ut_server.o library.o
	$(CC) -o $@ $^ $(LDFLAGS)

%.o: %.c library.h list.h
	$(CC) -c -Wall $(CFLAGS) -o $@ $<

install: all
	cp -f ut-client ut-server /usr/local/bin/

up: clean
	rsync -av ./ root@bj1.rssn.cn:udpintcp/
	rsync -av ./ root@bj2.rssn.cn:udpintcp/
	rsync -av ./ root@is1.rssn.cn:udpintcp/

clean:
	rm -f ut-client ut-server *.o
