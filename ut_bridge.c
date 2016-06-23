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

struct bridge_conn_ctx {
	int tcpfd;
	struct sockaddr_storage server_addr;
	struct bridge_conn_ctx *mate_ctx; /* the other connection of the pair */
	time_t last_tcp_recv;
	time_t last_tcp_send;
	size_t tcp_rx_dlen;
	char tcp_rx_buf[UT_TCP_RX_BUFFER_SIZE];
};

static inline void init_bridge_conn_ctx_pair(struct bridge_conn_ctx ctx[2])
{
	memset(ctx, 0x0, sizeof(*ctx) * 2);
	ctx[0].tcpfd = -1;
	ctx[0].mate_ctx = &ctx[1];
	ctx[1].tcpfd = -1;
	ctx[1].mate_ctx = &ctx[0];
}

static inline void bridge_conn_established(struct bridge_conn_ctx *ctx)
{
	int b_sockopt = 1;
	setsockopt(ctx->tcpfd, IPPROTO_TCP, TCP_NODELAY, &b_sockopt,
			sizeof(b_sockopt));
	set_nonblock(ctx->tcpfd);
	ctx->tcp_rx_dlen = 0;
	ctx->last_tcp_recv = ctx->last_tcp_send = time(NULL);
}

static inline void destroy_bridge_connection(struct bridge_conn_ctx *ctx)
{
	close(ctx->tcpfd);
	ctx->tcpfd = -1;
	/* Rewind the receive pointer */
	ctx->tcp_rx_dlen = 0;
	ctx->last_tcp_recv = ctx->last_tcp_send = 0;
}

static int process_bridge_conn_receive(struct bridge_conn_ctx *ctx)
{
	size_t rpos = 0, remain;
	time_t current_ts = time(NULL);
	int rc;

	rc = recv(ctx->tcpfd, ctx->tcp_rx_buf + ctx->tcp_rx_dlen,
			UT_TCP_RX_BUFFER_SIZE - ctx->tcp_rx_dlen, 0);
	if (rc <= 0) {
		syslog(LOG_INFO, "TCP connection closed.\n");
		destroy_bridge_connection(ctx);
		return -1;
	}
	ctx->tcp_rx_dlen += rc;

	/* >>>> Handle the received data - begin <<<< */
	while ((remain = ctx->tcp_rx_dlen - rpos) >= UT_TCP_HDR_LEN) {
		struct ut_tcp_hdr *hdr = (void *)(ctx->tcp_rx_buf + rpos);
		/* char *pkt_data = ctx->tcp_rx_buf + rpos + UT_TCP_HDR_LEN; */
		size_t pkt_len = ntohs(hdr->data_len);

		if (pkt_len == 0) {
			/* Keep-alive frame */
			ctx->last_tcp_recv = current_ts;
			printf("Heartbeat received.\n");
		} else if (remain - UT_TCP_HDR_LEN >= pkt_len) {
			/**
			 * A complete packet seen.
			 * Send to the other side of the bridge if the
			 * connection is alive.
			 */
			if (ctx->mate_ctx->tcpfd >= 0) {
				int rc = send_all(ctx->mate_ctx->tcpfd, hdr,
						UT_TCP_HDR_LEN + pkt_len, 0);
				if (rc <= 0) {
					syslog(LOG_INFO, "Bridge connection broken.\n");
					destroy_bridge_connection(ctx->mate_ctx);
				}
			}
		} else {
			break;
		}

		/* Prepare buffer pointer for the next frame */
		rpos += UT_TCP_HDR_LEN + pkt_len;
	}

	/* Keep the incomplete packet data in buffer */
	if (rpos > 0) {
		memmove(ctx->tcp_rx_buf, ctx->tcp_rx_buf + rpos, ctx->tcp_rx_dlen - rpos);
		ctx->tcp_rx_dlen -= rpos;
	}
	/* >>>> Handle the received data - end <<<< */

	return 0;
}

static void send_bridge_keepalive(struct bridge_conn_ctx *ctx)
{
	struct ut_tcp_hdr hdr;
	if (ctx->tcpfd < 0)
		return;
	hdr.data_len = htons(0);
	send_all(ctx->tcpfd, &hdr, UT_TCP_HDR_LEN, 0);
	ctx->last_tcp_send = time(NULL);
	printf("Bridge heartbeat sent. TCP buffer: %lu\n", (unsigned long)ctx->tcp_rx_dlen);;
}

static void print_help(int argc, char *argv[])
{
	printf("Usage:\n");
}

int main(int argc, char *argv[])
{
	struct bridge_conn_ctx conn_pair[2];
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

	init_bridge_conn_ctx_pair(conn_pair);

	get_sockaddr_inx_pair(argv[optind++], &conn_pair[0].server_addr);
	get_sockaddr_inx_pair(argv[optind++], &conn_pair[1].server_addr);

	if (is_daemon)
		do_daemonize();

	signal(SIGPIPE, SIG_IGN);

	for (;;) {
		fd_set rset;
		int maxfd, i;

		/* Check state of both connections and reconnect if neccessary */
		for (i = 0; i < 2; i++) {
			struct bridge_conn_ctx *ctx = &conn_pair[i];

			/* Check and close it if an existing connection is dead */
			if (ctx->tcpfd >= 0 &&
				time(NULL) - ctx->last_tcp_recv >= TCP_DEAD_TIMEOUT) {
				syslog(LOG_WARNING, "Close TCP connection due to keepalive failure.\n");
				destroy_bridge_connection(ctx);
			}

			/* Try to reconnect */
			if (ctx->tcpfd < 0 && time(NULL) - ctx->last_tcp_send >= 5) {
				char s_addr[64] = ""; int port = 0;

				sockaddr_to_print(&ctx->server_addr, s_addr, &port);

				ctx->tcpfd = socket(AF_INET, SOCK_STREAM, 0);
				assert(ctx->tcpfd >= 0);
				if (connect(ctx->tcpfd, (struct sockaddr *)&ctx->server_addr,
					sizeof_sockaddr(&ctx->server_addr)) == 0) {
					bridge_conn_established(ctx);
					syslog(LOG_INFO, "Connected to server '%s:%d'.\n", s_addr, port);
				} else {
					syslog(LOG_WARNING, "Failed to connect '%s:%d': %s. Retrying later.\n",
							s_addr, port, strerror(errno));
					/* Mark the failure time to avoid connecting too fast */
					ctx->last_tcp_send = time(NULL);
				}
			}
		}

		/* Process receiving of each socket */
		FD_ZERO(&rset);
		maxfd = -1;

		for (i = 0; i < 2; i++) {
			struct bridge_conn_ctx *ctx = &conn_pair[i];
			if (ctx->tcpfd >= 0) {
				FD_SET(ctx->tcpfd, &rset);
				SET_IF_LARGER(maxfd, ctx->tcpfd);
			}
		}

		if (maxfd >= 0) {
			struct timeval timeo = { 0, 300 * 1000 };
			int nfds;

			nfds = select(maxfd + 1, &rset, NULL, NULL, &timeo);
			if (nfds == 0) {
				/* No receive event, just do keep-alive */
				goto heartbeat;
			} else if (nfds < 0) {
				if (errno == EINTR || errno == ERESTART) {
					continue;
				} else {
					syslog(LOG_ERR, "*** select() error: %s.\n", strerror(errno));
					exit(1);
				}
			}
		} else {
			/* Delay for reconnecting */
			usleep(300 * 1000);
			continue;
		}

		for (i = 0; i < 2; i++) {
			struct bridge_conn_ctx *ctx = &conn_pair[i];
			if (ctx->tcpfd >= 0 && FD_ISSET(ctx->tcpfd, &rset))
				process_bridge_conn_receive(ctx);
		}

heartbeat:
		/* Send keep-alive packet */
		for (i = 0; i < 2; i++) {
			struct bridge_conn_ctx *ctx = &conn_pair[i];
			if (ctx->tcpfd >= 0 &&
				time(NULL) - ctx->last_tcp_send >= KEEPALIVE_INTERVAL)
				send_bridge_keepalive(ctx);
		}
	}

	return 0;
}

