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

static void print_help(int argc, char *argv[])
{
	printf("Usage:\n");
	printf(" %s tcp_listen_addr udp_remote_addr [-d]     client-to-server UDP connections\n", argv[0]);
	printf(" %s tcp_listen_addr udp_listen_addr -r [-d]  server-to-client UDP connections\n", argv[0]);
}

int main(int argc, char *argv[])
{
	struct ut_comm_context ctx;
	char *s_listen_addr, *s_udp_addr;
	struct sockaddr_storage listen_addr, udp_addr;
	int lsnfd = -1, b_sockopt = 1, opt;
	bool is_front_end = true, is_daemon = false;

	while ((opt = getopt(argc, argv, "rdh")) > 0) {
		switch (opt) {
		case 'd': is_daemon = true; break;
		case 'r': is_front_end = false; break;
		default: print_help(argc, argv); exit(1);
		}
	}
	if (argc - optind < 2) {
		print_help(argc, argv);
		exit(1);
	}

	openlog("ut-server", LOG_PID|LOG_CONS|LOG_PERROR|LOG_NDELAY, LOG_USER);

	s_listen_addr = argv[optind++];
	s_udp_addr = argv[optind++];
	get_sockaddr_inx_pair(s_listen_addr, &listen_addr);
	get_sockaddr_inx_pair(s_udp_addr, &udp_addr);

	init_comm_context(&ctx, is_front_end);

	if (ctx.is_front_end) {
		ctx.udp_peer_addr = udp_addr;
	} else {
		ctx.back_end.udpfd = create_udp_server_fd(&udp_addr);
		if (ctx.back_end.udpfd < 0)
			exit(1);
	}

	lsnfd = socket(AF_INET, SOCK_STREAM, 0);
	assert(lsnfd >= 0);

	setsockopt(lsnfd, SOL_SOCKET, SO_REUSEADDR, &b_sockopt, sizeof(b_sockopt));
	if (bind(lsnfd, (struct sockaddr *)&listen_addr,
		sizeof_sockaddr(&listen_addr)) < 0) {
		char s_addr[64] = ""; int port = 0;
		sockaddr_to_print(&listen_addr, s_addr, &port);
		fprintf(stderr, "*** Failed to bind '%s:%d': %s.\n", s_addr, port,
				strerror(errno));
		exit(1);
	}
	listen(lsnfd, 10);

	if (is_daemon)
		do_daemonize();

	signal(SIGPIPE, SIG_IGN);

	for (;;) {
		fd_set rset;
		struct timeval timeo;
		int maxfd = -1, nfds;
		struct front_end_conn *ce;
		time_t current_ts = time(NULL);

		if (ctx.tcpfd >= 0 && current_ts - ctx.last_tcp_recv >= TCP_DEAD_TIMEOUT) {
			destroy_tcp_connection(&ctx);
			syslog(LOG_WARNING, "Close TCP connection due to keepalive failure.\n");
		}

		FD_ZERO(&rset);

		/* The listener socket */
		FD_SET(lsnfd, &rset);
		SET_IF_LARGER(maxfd, lsnfd);

		/* The TCP socket */
		if (ctx.tcpfd >= 0 && ctx.tcp_rx_dlen < UT_TCP_RX_BUFFER_SIZE) {
			FD_SET(ctx.tcpfd, &rset);
			SET_IF_LARGER(maxfd, ctx.tcpfd);
		}

		if (ctx.is_front_end) {
			list_for_each_entry (ce, &ctx.front_end.conn_list, list) {
				FD_SET(ce->udpfd, &rset);
				SET_IF_LARGER(maxfd, ce->udpfd);
			}
		} else {
			FD_SET(ctx.back_end.udpfd, &rset);
			SET_IF_LARGER(maxfd, ctx.back_end.udpfd);
		}

		timeo.tv_sec = 0; timeo.tv_usec = 300 * 1000;

		nfds = select(maxfd + 1, &rset, NULL, NULL, &timeo);
		if (nfds == 0) {
			goto heartbeat;
		} else if (nfds < 0) {
			if (errno == EINTR || errno == ERESTART) {
				continue;
			} else {
				syslog(LOG_ERR, "*** select() error: %s.\n", strerror(errno));
				exit(1);
			}
		}

		if (FD_ISSET(lsnfd, &rset)) {
			struct sockaddr_storage cli_addr;
			socklen_t cli_alen = sizeof(cli_addr);
			char s_cli_addr[64] = "";
			int cli_sock, cli_port = 0;

			cli_sock = accept(lsnfd, (struct sockaddr *)&cli_addr, &cli_alen);
			if (cli_sock >= 0) {
				if (ctx.tcpfd >= 0)
					close(ctx.tcpfd);

				ctx.tcpfd = cli_sock;

				tcp_connection_established(&ctx);

				sockaddr_to_print(&cli_addr, s_cli_addr, &cli_port);
				syslog(LOG_INFO, "Client '%s:%d' connected, dropped old connection.\n", s_cli_addr, cli_port);
				continue;
			}
		}

		if (FD_ISSET(ctx.tcpfd, &rset)) {
			if (process_tcp_receive(&ctx) < 0)
				goto heartbeat;
		}

		if (ctx.is_front_end) {
			list_for_each_entry (ce, &ctx.front_end.conn_list, list) {
				if (FD_ISSET(ce->udpfd, &rset))
					process_udp_receive(&ctx, ce);
			}
		} else {
			if (FD_ISSET(ctx.back_end.udpfd, &rset))
				process_udp_receive(&ctx, NULL);
		}

heartbeat:
		current_ts = time(NULL);
		/* Send keep-alive packet */
		if (ctx.tcpfd >= 0 && current_ts - ctx.last_tcp_send >= KEEPALIVE_INTERVAL) {
			ctx.last_tcp_send = current_ts;
			send_tcp_keepalive(&ctx);
		}
		if (ctx.is_front_end && current_ts - ctx.last_fe_recycle >= FRONTEND_RECYCLE_INTERVAL) {
			recycle_front_end_conn(&ctx);
			ctx.last_fe_recycle = current_ts;
		}
	}

	return 0;
}

