#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stddef.h>
#include <unistd.h>
#include <time.h>
#include <signal.h>
#include <fcntl.h>
#include <syslog.h>
#include <errno.h>
#include <assert.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <netdb.h>

#include "library.h"

struct server_conn_ctx {
	int tcpfd;
	struct sockaddr_storage server_addr;
	time_t last_tcp_recv;
	time_t last_tcp_send;
	size_t tcp_rx_dlen;
	char tcp_rx_buf[UT_TCP_RX_BUFFER_SIZE];
};

static inline void init_server_conn_ctx(struct server_conn_ctx *ctx)
{
	memset(ctx, 0x0, sizeof(*ctx));
	ctx->tcpfd = -1;
}

static inline void server_conn_established(struct server_conn_ctx *ctx)
{
	int b_sockopt = 1;
	setsockopt(ctx->tcpfd, IPPROTO_TCP, TCP_NODELAY, &b_sockopt,
			sizeof(b_sockopt));
	set_nonblock(ctx->tcpfd);
	ctx->tcp_rx_dlen = 0;
	ctx->last_tcp_recv = ctx->last_tcp_send = time(NULL);
}

static void print_help(int argc, char *argv[])
{
	printf("Usage:\n");
}

int main(int argc, char *argv[])
{
	struct server_conn_ctx conn_ctxs[2];
	int opt;
	bool is_daemon = false;

	while ((opt = getopt(argc, argv, "dh")) > 0) {
		switch (opt) {
		case 'd': is_daemon = true; break;
		default: print_help(argc, argv); exit(1);
		}
	}

	if (argc - optind < 2) {
		print_help(argc, argv);
		exit(1);
	}

	openlog("ut-bridge", LOG_PID|LOG_CONS|LOG_PERROR|LOG_NDELAY, LOG_USER);

	init_server_conn_ctx(&conn_ctxs[0]);
	init_server_conn_ctx(&conn_ctxs[1]);

	get_sockaddr_inx_pair(argv[optind++], &conn_ctxs[0].server_addr);
	get_sockaddr_inx_pair(argv[optind++], &conn_ctxs[1].server_addr);

	if (is_daemon)
		do_daemonize();

	signal(SIGPIPE, SIG_IGN);

	for (;;) {
		fd_set rset;
		struct timeval timeo;
		int maxfd = 0, nfds, i;

		/* Check state of both connections and reconnect if neccessary */
		for (i = 0; i < 2; i++) {
			struct server_conn_ctx *ctx = &conn_ctxs[i];

			if (ctx->tcpfd < 0 ||
				time(NULL) - ctx->last_tcp_recv >= TCP_DEAD_TIMEOUT) {
				char s_addr[64] = ""; int port = 0;

				sockaddr_to_print(&ctx->server_addr, s_addr, &port);

				if (ctx->tcpfd >= 0) {
					syslog(LOG_WARNING, "Close TCP connection due to keepalive failure.\n");
					close(ctx->tcpfd);
				}

				ctx->tcpfd = socket(AF_INET, SOCK_STREAM, 0);
				assert(ctx->tcpfd >= 0);

				if (connect(ctx->tcpfd, (struct sockaddr *)&ctx->server_addr,
					sizeof_sockaddr(&ctx->server_addr)) < 0) {
					syslog(LOG_WARNING, "Failed to connect '%s:%d': %s. Retrying later.\n",
							s_addr, port, strerror(errno));
					sleep(5);
					continue;
				}

				server_conn_established(ctx);
				syslog(LOG_INFO, "Connected to server '%s:%d'.\n", s_addr, port);
			}
		}
	}

	return 0;
}

