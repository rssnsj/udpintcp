#ifndef __LIBRARY_H
#define __LIBRARY_H

#include <stddef.h>
#include <time.h>
#include <fcntl.h>
#include <errno.h>
#include <assert.h>
#include <arpa/inet.h>
#include <netinet/in.h>

#include "list.h"

typedef uint32_t be32;
typedef uint16_t be16;
typedef int bool;
#define true  1
#define false 0

#ifndef __linux__
	#define ERESTART 700
#endif

#define SET_IF_LARGER(a, b)  do { if ((b) > (a)) (a) = (b); } while(0)

#define sizeof_sockaddr(s)  ((s)->ss_family == AF_INET6 ? \
		sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in))

int get_sockaddr_inx_pair(const char *pair, struct sockaddr_storage *sa);
char *sockaddr_to_print(const struct sockaddr_storage *addr,
		char *host, int *port);
int do_daemonize(void);
ssize_t send_all(int sockfd, const void *buf, size_t len, int flags);

static inline int set_nonblock(int sockfd)
{
	int rc = fcntl(sockfd, F_GETFD, 0);
	if (fcntl(sockfd, F_SETFL, rc | O_NONBLOCK) == -1)
		return -1;
	return 0;
}

static inline void hexdump(void *d, size_t len)
{
	unsigned char *s;
	for (s = d; len; len--, s++)
		printf("%02x ", (unsigned int)*s);
	printf("\n");
}

#ifdef __SUPPRESS_SYSLOG__
	#define openlog_x(...)  openlog(__VA_ARGS__)
	#define syslog_x(...)   ((void)0)
#else
	#define openlog_x(...)  openlog(__VA_ARGS__)
	#define syslog_x(...)   syslog(__VA_ARGS__)
#endif

#define TCP_DEAD_TIMEOUT  15
#define UDP_SESSION_TIMEOUT  60
#define KEEPALIVE_INTERVAL  3
#define FRONTEND_RECYCLE_INTERVAL  5

struct front_end_conn {
	struct list_head list;
	time_t last_active;
	int udpfd;
	be32 client_ip;
	be16 client_port;
};

#define UT_TCP_RX_BUFFER_SIZE  (1024 * 64)
#define UT_UDP_RX_BUFFER_SIZE  (1024 * 64)

struct ut_comm_context {
	int tcpfd;

	time_t last_tcp_recv;
	time_t last_tcp_send;
	time_t last_fe_recycle;
	size_t tcp_rx_dlen;

	bool is_front_end;
	union {
		struct {
			struct list_head conn_list;
		} front_end;
		struct {
			int udpfd;
		} back_end;
	};

	struct sockaddr_storage udp_peer_addr;

	char tcp_rx_buf[UT_TCP_RX_BUFFER_SIZE];
};

struct ut_tcp_hdr {
	be16 data_len;
	be16 client_port;
	be32 client_ip;
};
#define UT_TCP_HDR_LEN  (sizeof(struct ut_tcp_hdr))

void init_comm_context(struct ut_comm_context *ctx, bool is_front_end);
void recycle_front_end_conn(struct ut_comm_context *ctx);

int create_udp_client_fd(struct sockaddr_storage *addr);
int create_udp_server_fd(struct sockaddr_storage *addr);

int process_tcp_receive(struct ut_comm_context *ctx);
int process_udp_receive(struct ut_comm_context *ctx, struct front_end_conn *ce);

void tcp_connection_established(struct ut_comm_context *ctx);
void destroy_tcp_connection(struct ut_comm_context *ctx);
void send_tcp_keepalive(struct ut_comm_context *ctx);

#endif /* __LIBRARY_H */
