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

int do_daemonize(void)
{
	pid_t pid;

	if ((pid = fork()) < 0) {
		return -1;
	} else if (pid > 0) {
		exit(0);
	} else {
		int fd;
		setsid();
		if ((fd = open("/dev/null", O_RDWR)) >= 0) {
			dup2(fd, 0); dup2(fd, 1); dup2(fd, 2);
			if (fd > 2)
				close(fd);
		}
		chdir("/tmp");
	}
	return 0;
}

int get_sockaddr_inx_pair(const char *pair,
		struct sockaddr_storage *sa, socklen_t *sa_len)
{
	struct addrinfo hints, *result;
	char host[51] = "", s_port[10] = "";
	int port = 0, rc;

	/* Only getting an INADDR_ANY address. */
	if (pair == NULL) {
		struct sockaddr_in *sa4 = (struct sockaddr_in *)sa;
		sa4->sin_family = AF_INET;
		sa4->sin_addr.s_addr = 0;
		sa4->sin_port = 0;
		return 0;
	}

	if (sscanf(pair, "[%50[^]]]:%d", host, &port) == 2) {
	} else if (sscanf(pair, "%50[^:]:%d", host, &port) == 2) {
	} else {
		/**
		 * Address with a single port number, usually for
		 * local IPv4 listen address.
		 * e.g., "10000" is considered as "0.0.0.0:10000"
		 */
		const char *sp;
		for (sp = pair; *sp; sp++) {
			if (!(*sp >= '0' && *sp <= '9'))
				return -EINVAL;
		}
		sscanf(pair, "%d", &port);
		strcpy(host, "0.0.0.0");
	}
	sprintf(s_port, "%d", port);
	if (port <= 0 || port > 65535)
		return -EINVAL;

	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family = AF_UNSPEC;  /* Allow IPv4 or IPv6 */
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE;  /* For wildcard IP address */
	hints.ai_protocol = 0;        /* Any protocol */
	hints.ai_canonname = NULL;
	hints.ai_addr = NULL;
	hints.ai_next = NULL;

	if ((rc = getaddrinfo(host, s_port, &hints, &result)))
		return -EAGAIN;

	/* Get the first resolution. */
	memcpy(sa, result->ai_addr, result->ai_addrlen);
	*sa_len = result->ai_addrlen;

	freeaddrinfo(result);
	return 0;
}

char *sockaddr_to_print(const void *addr, char *host, int *port)
{
	const union __sa_union {
		struct sockaddr_storage ss;
		struct sockaddr_in sa4;
		struct sockaddr_in6 sa6;
	} *sa = addr;

	if (sa->ss.ss_family == AF_INET) {
		inet_ntop(AF_INET, &sa->sa4.sin_addr, host, 16);
		*port = ntohs(sa->sa4.sin_port);
	} else if (sa->ss.ss_family == AF_INET6) {
		inet_ntop(AF_INET6, &sa->sa6.sin6_addr, host, 40);
		*port = ntohs(sa->sa6.sin6_port);
	} else {
		return NULL;
	}
	return host;
}

void init_comm_context(struct ut_comm_context *ctx, bool is_front_end)
{
	memset(ctx, 0x0, sizeof(*ctx));
	ctx->tcpfd = -1;
	ctx->is_front_end = is_front_end;
	if (is_front_end) {
		INIT_LIST_HEAD(&ctx->front_end.conn_list);
	} else {
		ctx->back_end.udpfd = -1;
	}
}

static struct front_end_conn *get_conn_by_client_addr(
		struct ut_comm_context *ctx, be32 client_ip, be16 client_port)
{
	struct front_end_conn *ce;

	list_for_each_entry (ce, &ctx->front_end.conn_list, list) {
		if (ce->client_ip == client_ip && ce->client_port == client_port)
			return ce;
	}

	/* Create new session */
	ce = malloc(sizeof(struct front_end_conn));
	memset(ce, 0x0, sizeof(*ce));
	ce->client_ip = client_ip;
	ce->client_port = client_port;

	ce->sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	assert(ce->sockfd);
	if (connect(ce->sockfd, (struct sockaddr *)&ctx->udp_peer_addr,
		ctx->udp_peer_alen) < 0) {
		syslog(LOG_ERR, "*** Failed to connect UDP remote server: %s.\n",
				strerror(errno));
		close(ce->sockfd);
		free(ce);
		return NULL;
	}

	list_add(&ce->list, &ctx->front_end.conn_list);

	syslog(LOG_INFO, "New UDP session from: %s:%d.\n",
			inet_ntoa(*(struct in_addr *)&client_ip), (int)htons(client_port));
	return ce;
}

void recycle_front_end_conn(struct ut_comm_context *ctx)
{
	struct front_end_conn *ce, *__ce;
	time_t current_ts = time(NULL);

	assert(ctx->is_front_end);

	list_for_each_entry_safe (ce, __ce, &ctx->front_end.conn_list, list) {
		if (current_ts - ce->last_active >= UDP_SESSION_TIMEOUT) {
			list_del(&ce->list);
			syslog(LOG_INFO, "Recycled UDP session: %s:%d.\n",
					inet_ntoa(*(struct in_addr *)&ce->client_ip),
					(int)htons(ce->client_port));
			close(ce->sockfd);
			free(ce);
		}
	}
}

#if 0
static struct front_end_conn *get_conn_by_upstream_udpfd(
		struct ut_comm_context *ctx, int udpfd)
{
	struct front_end_conn *ce;

	list_for_each_entry (ce, &ctx->front_end.conn_list, list) {
		if (ce->sockfd == udpfd)
			return ce;
	}

	return NULL;
}
#endif

int create_udp_client_fd(struct sockaddr_storage *addr, socklen_t alen)
{
	int fd, rc, port = 0;
	char s_addr[64] = "";

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	assert(fd >= 0);
	if ((rc = connect(fd, (struct sockaddr *)addr, alen)) < 0) {
		sockaddr_to_print(addr, s_addr, &port);
		syslog(LOG_ERR, "*** Failed to connect %s:%d: %s.\n",
				s_addr, port, strerror(errno));
		close(fd);
		return rc;
	}
	set_nonblock(fd);
	return fd;
}

int create_udp_server_fd(struct sockaddr_storage *addr, socklen_t alen)
{
	int fd, rc, port = 0;
	char s_addr[64] = "";

	fd = socket(AF_INET, SOCK_DGRAM, 0);
	assert(fd >= 0);
	if ((rc = bind(fd, (struct sockaddr *)addr, alen)) < 0) {
		sockaddr_to_print(addr, s_addr, &port);
		syslog(LOG_ERR, "*** Failed to bind %s:%d: %s.\n",
				s_addr, port, strerror(errno));
		close(fd);
		return rc;
	}
	set_nonblock(fd);
	return fd;
}

static ssize_t send_all(int sockfd, const void *buf, size_t len, int flags)
{
	const char *b = (char *)buf;
	ssize_t rpos = 0, rc;

	if (len == 0)
		return 0;

	for (;;) {
		rc = send(sockfd, b + rpos, len - rpos, flags);
		if (rc > 0) {
			rpos += rc;
			if (rpos == len)
				break;
		} else if (rc == 0) {
			return 0;
		} else if (errno == EAGAIN || errno == EWOULDBLOCK) {
			/* I/O is busy, wait for it ready */
			fd_set wset;
			struct timeval timeo;
			int nfds;
again:
			FD_ZERO(&wset);
			FD_SET(sockfd, &wset);
			timeo.tv_sec = TCP_DEAD_TIMEOUT; timeo.tv_usec = 0;
			nfds = select(sockfd + 1, NULL, &wset, NULL, &timeo);
			if (nfds == 0) {
				/* Connection stuck */
				errno = ECONNABORTED;
				return -1;
			} else if (nfds < 0) {
				if (errno == EINTR || errno == ERESTART) {
					goto again;
				} else {
					syslog(LOG_ERR, "*** select() error: %s.\n", strerror(errno));
					return nfds;
				}
			}
			if (!FD_ISSET(sockfd, &wset))
				goto again;
			/* Continue the loop. */
		} else {
			return rc;
		}
	}
	return rpos;
}

static void __handle_tcp_rx_data(struct ut_comm_context *ctx)
{
	size_t rpos = 0, remain;
	time_t current_ts = time(NULL);

	while ((remain = ctx->tcp_rx_dlen - rpos) >= UT_TCP_HDR_LEN) {
		struct ut_tcp_hdr *hdr = (void *)(ctx->tcp_rx_buf + rpos);
		char *pkt_data = ctx->tcp_rx_buf + rpos + UT_TCP_HDR_LEN;
		size_t pkt_len = ntohs(hdr->data_len);

		if (pkt_len == 0) {
			/* Keep-alive frame */
			ctx->last_tcp_recv = current_ts;
			printf("Heartbeat received.\n");
		} else if (remain - UT_TCP_HDR_LEN >= pkt_len) {
			/* A complete packet seen */
			ctx->last_tcp_recv = current_ts;
			if (ctx->is_front_end) {
				struct front_end_conn *ce = get_conn_by_client_addr(ctx,
						hdr->client_ip, hdr->client_port);
				if (ce) {
					send(ce->sockfd, pkt_data, pkt_len, 0);
					ce->last_active = current_ts;
				}
			} else {
				struct sockaddr_in addr;
				addr.sin_family = AF_INET;
				addr.sin_addr.s_addr = hdr->client_ip;
				addr.sin_port = hdr->client_port;
				sendto(ctx->back_end.udpfd, pkt_data, pkt_len, 0,
						(struct sockaddr *)&addr, sizeof(addr));
			}
		} else {
			break;
		}

		/* Prepare buffer pointer for the next frame */
		rpos += UT_TCP_HDR_LEN + pkt_len;
	}

	/* Keep the incomplete packet data in buffer */
	memmove(ctx->tcp_rx_buf, ctx->tcp_rx_buf + rpos, ctx->tcp_rx_dlen - rpos);
	ctx->tcp_rx_dlen -= rpos;
}

int process_tcp_receive(struct ut_comm_context *ctx)
{
	int rc;

	rc = recv(ctx->tcpfd, ctx->tcp_rx_buf + ctx->tcp_rx_dlen,
			UT_TCP_RX_BUFFER_SIZE - ctx->tcp_rx_dlen, 0);
	if (rc <= 0) {
		syslog(LOG_INFO, "TCP connection closed.\n");
		destroy_tcp_connection(ctx);
		return -1;
	}
	ctx->tcp_rx_dlen += rc;

	__handle_tcp_rx_data(ctx);
	return 0;
}

int process_udp_receive(struct ut_comm_context *ctx, struct front_end_conn *ce)
{
	char tx_buf[UT_TCP_HDR_LEN + UT_UDP_RX_BUFFER_SIZE],
		*rx_buf = tx_buf + UT_TCP_HDR_LEN;
	struct ut_tcp_hdr *tx_hdr = (struct ut_tcp_hdr *)tx_buf;
	be32 client_ip = 0;
	be16 client_port = 0;
	time_t current_ts = time(NULL);
	size_t rx_len = 0;
	int rc;

	if (ctx->is_front_end) {
		rc = recv(ce->sockfd, rx_buf, UT_UDP_RX_BUFFER_SIZE, 0);
		if (rc <= 0)
			return -1;
		client_ip = ce->client_ip;
		client_port = ce->client_port;
		ce->last_active = current_ts;
	} else {
		struct sockaddr_storage client_addr;
		socklen_t client_alen = sizeof(client_addr);

		rc = recvfrom(ctx->back_end.udpfd, rx_buf, UT_UDP_RX_BUFFER_SIZE,
				0, (struct sockaddr *)&client_addr, &client_alen);
		assert(client_addr.ss_family == AF_INET);

		client_ip = ((struct sockaddr_in *)&client_addr)->sin_addr.s_addr;
		client_port = ((struct sockaddr_in *)&client_addr)->sin_port;
	}
	if (rc <= 0) {
		/* Error */
		syslog(LOG_ERR, "*** Failed to receive from UDP socket: %s.\n",
				strerror(errno));
		return -1;
	}
	rx_len = rc;

	/* Send the packet */
	if (ctx->tcpfd < 0)
		return 0;

	tx_hdr->data_len = htons(rx_len);
	tx_hdr->client_ip = client_ip;
	tx_hdr->client_port = client_port;

	rc = send_all(ctx->tcpfd, tx_buf, UT_TCP_HDR_LEN + rx_len, 0);
	if (rc <= 0) {
		syslog(LOG_INFO, "TCP connection closed.\n");
		destroy_tcp_connection(ctx);
		return -1;
	}
	ctx->last_tcp_send = current_ts;

	return 0;
}

void tcp_connection_established(struct ut_comm_context *ctx)
{
	int b_sockopt = 1;
	setsockopt(ctx->tcpfd, IPPROTO_TCP, TCP_NODELAY, &b_sockopt,
			sizeof(b_sockopt));
	set_nonblock(ctx->tcpfd);
	ctx->tcp_rx_dlen = 0;
	ctx->last_tcp_recv = ctx->last_tcp_send = time(NULL);
}

void destroy_tcp_connection(struct ut_comm_context *ctx)
{
	close(ctx->tcpfd);
	ctx->tcpfd = -1;
	/* Rewind the receive pointer */
	ctx->tcp_rx_dlen = 0;
}

void send_tcp_keepalive(struct ut_comm_context *ctx)
{
	struct ut_tcp_hdr hdr;
	if (ctx->tcpfd < 0)
		return;
	hdr.data_len = htons(0);
	send_all(ctx->tcpfd, &hdr, UT_TCP_HDR_LEN, 0);
	ctx->last_tcp_send = time(NULL);
	printf("Heartbeat sent. TCP buffer: %lu\n", (unsigned long)ctx->tcp_rx_dlen);;
}

