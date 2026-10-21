/* Regression for AgentX sockets closed and reopened with the same fd. */
#include "config.h"

#ifndef _WITH_SNMP_
#error "Configure with --enable-snmp to build this test"
#endif

#include <stdio.h>
#include <stdlib.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <unistd.h>

#include "scheduler.h"

#define CHECK(expr) do { \
	if (!(expr)) { \
		fprintf(stderr, "%s:%d: %s failed\n", __FILE__, __LINE__, #expr); \
		exit(EXIT_FAILURE); \
	} \
} while (0)

static int sockets[2];
static enum { NO_RECONNECT, IN_TIMEOUT, IN_ALARM, DROP_SOCKET } reconnect_at;

static void
reconnect_socket(void)
{
	int replacement[2];

	CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, replacement) == 0);
	CHECK(close(sockets[0]) == 0);
	CHECK(dup2(replacement[0], sockets[0]) == sockets[0]);
	CHECK(close(replacement[0]) == 0);
	CHECK(close(sockets[1]) == 0);
	sockets[1] = replacement[1];
}

/* Replace the net-snmp callbacks, retaining the real scheduler and epoll. */
int
snmp_select_info(int *nfds, fd_set *readfds, struct timeval *timeout, int *block)
{
	timeout->tv_sec = 1;
	timeout->tv_usec = 0;
	if (sockets[0] < 0) {
		*nfds = 0;
		*block = 1;
		return 0;
	}
	FD_SET(sockets[0], readfds);
	*nfds = sockets[0] + 1;
	*block = 0;
	return 1;
}

void
snmp_timeout(void)
{
	if (reconnect_at == IN_TIMEOUT)
		reconnect_socket();
	else if (reconnect_at == DROP_SOCKET) {
		CHECK(close(sockets[0]) == 0);
		CHECK(close(sockets[1]) == 0);
		sockets[0] = sockets[1] = -1;
	}
}

void
run_alarms(void)
{
	if (reconnect_at == IN_ALARM)
		reconnect_socket();
}

void
snmp_read(fd_set *readfds)
{
	(void)readfds;
}

void
netsnmp_check_outstanding_agent_requests(void)
{
}

static void
check_ready(const char *label)
{
	struct epoll_event event;
	char byte;
	int ready;

	CHECK(write(sockets[1], "x", 1) == 1);
	ready = epoll_wait(master->epoll_fd, &event, 1, 100);
	printf("%s: %s\n", label, ready == 1 ? "PASS" : "FAIL");
	CHECK(ready == 1);
	CHECK(event.events & EPOLLIN);
	CHECK(read(sockets[0], &byte, 1) == 1);
}

static void
run_timeout(void)
{
	thread_t timeout = { .master = master };

	thread_cancel(master->snmp_timer_thread);
	snmp_timeout_thread(&timeout);
	if (sockets[0] >= 0)
		CHECK(master->snmp_timer_thread->sands.tv_sec != TIMER_DISABLED);
}

int
main(void)
{
	unsigned i;

	setbuf(stdout, NULL);
	master = thread_make_master();
	CHECK(master);
	CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
	master->snmp_timer_thread = thread_add_timer(master, snmp_timeout_thread, NULL, TIMER_NEVER);
	snmp_epoll_info(master);
	check_ready("initial registration");
	run_timeout();
	check_ready("unchanged socket");
	reconnect_at = IN_TIMEOUT;
	run_timeout();
	check_ready("fd reused by snmp_timeout");
	reconnect_at = IN_ALARM;
	for (i = 0; i < 10; i++) {
		run_timeout();
		check_ready("fd reused by run_alarms");
	}
	reconnect_at = DROP_SOCKET;
	run_timeout();
	CHECK(master->snmp_fdsetsize == 0);
	CHECK(socketpair(AF_UNIX, SOCK_STREAM, 0, sockets) == 0);
	reconnect_at = NO_RECONNECT;
	run_timeout();
	check_ready("socket added after disconnect");
	snmp_epoll_clear(master);
	close(sockets[0]);
	close(sockets[1]);
	thread_destroy_master(master);
	return 0;
}
