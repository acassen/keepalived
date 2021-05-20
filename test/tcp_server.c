#include <strings.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <stdio.h>
#include <unistd.h>
#include <signal.h>
#include <string.h>
#include <stdbool.h>
#include <errno.h>
#include <time.h>
#include <fcntl.h>

#include "tcp_server_html.h"

/*
 * NOTE:
 *
 * This may be completely unnecessary, since ncat probably provides the
 * functionality provided here.
 */

const char *html_hdr =
	"HTTP/%s 200 OK\r\n"
	"Date: %s\r\n"		// Mon, 26 Oct 2020 22:18:55 GMT
	"Server: Apache/2.4.46 (Fedora) OpenSSL/1.1.1g\r\n"
	"Last-Modified: Sat, 14 Oct 2017 12:43:39 GMT\r\n"
	"ETag: \"17c3-55b811f6254c0\"\r\n"
	"Accept-Ranges: bytes\r\n"
	"Content-Length: %zu\r\n"
	"Connection: close\r\n"
	"Content-Type: text/html\r\n"
	"\r\n";

typedef enum {
	TYPE_STD,
	TYPE_HTML
} cr_t;

struct cmd_resp {
	struct cmd_resp *next;
	cr_t type;
	char *cmd;
	char *resp;
	const char *html_version;
	bool close_conn;
};

static struct cmd_resp *cmd_resp_list;
static char EOL = '\r';
static struct timespec rep_delay;
static bool random_delay;
static int random_seed = 0;

static bool debug;
static bool debug_data;

static unsigned long connection_num;
static unsigned long connection_mod = 1;

static bool email_server = false;
static const char *email_server_name = "keepalived.org";

static void
send_html_resp(int fd, struct cmd_resp *p)
{
	char time_buf[30];	// Mon, 26 Oct 2020 22:18:55 GMT
	char header_buf[strlen(html_hdr) + 6 + 30];
	time_t t;
	struct tm *tm_p;

	t = time(NULL);
	tm_p = localtime(&t);

	strftime(time_buf, sizeof(time_buf), "%a, %e %b %Y %T %Z", tm_p);
	sprintf(header_buf, html_hdr, p->html_version, time_buf, strlen(p->resp));

	if (debug)
		printf("(%d) Sending HTML header\n'%s'", getpid(),  header_buf);

	write(fd, header_buf, strlen(header_buf));
}

static void find_resp(int fd, const char *cmd)
{
	struct cmd_resp *p;
	const char *s, *e;
	size_t len;
	const char *resp;
	struct timespec delay;
	bool use_p = false;

	if (debug)
		printf("(%d) Processing: '%s', end = %d\n", getpid(),  cmd, cmd[strlen(cmd)-1]);

	s = cmd;
	for (s = cmd; *s; s = *e ? e + 1 : e) {
		e = strchr(s, EOL);
		if (!e)
			e = s + strlen(s);
		len = e - s;
//printf("(%d) Looking at %p, len 0x%x (%d)\n", getpid(), s, len, len);

		if (debug)
			printf("(%d) Looking at '%.*s'\n", getpid(), (int)len, s);

		resp = s;
		for (p = cmd_resp_list; p; p = p->next) {
			if (len == strlen(p->cmd) &&
			    !strncmp(p->cmd, s, len)) {
				if (debug)
					printf("(%d) Found %s -> %s\n", getpid(),  p->cmd, p->resp);

				resp = p->resp;
				len = strlen(resp);
				if (!len)
{
printf("(%d) Exit for !len\n", getpid());
					exit(0);
}
				use_p = true;

				if (debug)
					printf("(%d) Found match, close after %d\n", getpid(),  p->close_conn);

				break;
			}
		}

		if (rep_delay.tv_nsec || rep_delay.tv_sec) {
			if (random_delay) {
				delay.tv_nsec = (rep_delay.tv_sec * 1000000000 + rep_delay.tv_nsec) * random();
				delay.tv_sec = delay.tv_nsec / 1000000000;
				delay.tv_nsec %= 1000000000;
			} else
				delay = rep_delay;
			nanosleep(&delay, NULL);
		}

		if (use_p && p->type == TYPE_HTML)
			send_html_resp(fd, p);

		if (debug_data)
			printf("(%d) Replying '%.*s'\n", getpid(), (int)len, resp);

		write(fd, resp, len);

		if (use_p && p->close_conn) {
			char buf[1024];

			/* Strip any remaining received data, otherwise RST gets sent instead of FIN */
			fcntl(fd, F_SETFL, O_NONBLOCK);
			while (read(fd, buf, 1024) > 0);

			close(fd);
//printf("(%d) Exiting\n", getpid());
			exit(0);
		}
		return;
	}
}

static struct cmd_resp *
new_cr(const char *cmd, const char *resp, bool close_after_send, cr_t type)
{
	struct cmd_resp *cr;

	cr = malloc(sizeof(struct cmd_resp));
	cr->next = cmd_resp_list;
	cmd_resp_list = cr;
	cr->cmd = strdup(cmd);
	cr->resp = strdup(resp);
	cr->type = type;

	cr->close_conn = close_after_send;

	return cr;
}

static void
new_html_cr(const char *url, const char *resp, const char *html_version, bool close_after_send)
{
	char *cmd = malloc(14 + strlen(url));	// GET %s HTTP/1.1";
	struct cmd_resp *cr;

	sprintf(cmd, "GET %s HTTP/%s", url, html_version);

	cr = new_cr(cmd, resp, close_after_send, TYPE_HTML);
	cr->html_version = strdup(html_version);
}

static void
send_email_response(int fd, char *buf)
{
	char *reply;

	if (debug_data && buf[0])
		printf("Received: %s", buf);

	if (!buf[0]) {
		sprintf(buf, "220 %s ESMTP Keepalived Mail Server\r\n", email_server_name);
		reply = buf;
	} else if (!strncmp(buf, "HELO ", 5)) {
		sprintf(buf, "250 %s\r\n", email_server_name);
		reply = buf;
	} else if (!strncmp(buf, "MAIL FROM:", 10))
		reply = "250 2.1.0 Ok\r\n";
	else if (!strncmp(buf, "RCPT TO:", 8))
		reply = "250 2.1.5 Ok\r\n";
	else if (!strncmp(buf, "DATA\r\n", 6))
		reply = "354 End data with <CR><LF>.<CR><LF>\r\n";
	else if (!strncmp(buf + strlen(buf) - 5, "\r\n.\r\n", 5))	// What if strlen(buf) < 5? Also handle buffer end
		reply = "250 2.0.0 Ok: queued as AB8132E22C\r\n";
	else if (!strncmp(buf, "QUIT\r\n", 6))
		reply = "221 2.0.0 Bye\r\n";
	else
		return;

printf("Replying: %s", reply);
	write(fd, reply, strlen(reply));
}

static void
process_data(int fd)
{
	char buf[1024];
	int len;

	if (email_server) {
		buf[0] = '\0';
		send_email_response(fd, buf);
	}

	while ((len = read(fd, buf, sizeof(buf) - 1)) > 0) {
//printf("(%d) Read %d bytes\n", getpid(),  len);
		buf[len] = '\0';

		/* Exit if receive ^D */
		if (len == 1 && buf[0] == 4)
//{
//printf("(%d) Got <CNTL>-D\n", getpid());
			return;
//}
		if (email_server)
			send_email_response(fd, buf);
		else if (cmd_resp_list)
			find_resp(fd, buf);
		else
			write(fd, buf, len);
//printf("(%d) Going to read again\n", getpid());
	}
//printf("(%d) Process_data returning, len = %d, errno %d - %m\n", getpid(),  len, errno);
}

static void
print_usage(FILE *fp, const char *name)
{
	fprintf(fp, "Usage: %s [options]\n", name);
	fprintf(fp, "\t-4\t\tUse IPv4\n");
	fprintf(fp, "\t-6\t\tUse IPv6\n");
	fprintf(fp, "\t-a addr\t\tbind to addr\n");
	fprintf(fp, "\t-p port\t\tlisten on port\n");
	fprintf(fp, "\t-s\t\tsilent\n");
	fprintf(fp, "\t-u\t\tuse UDP\n");
	fprintf(fp, "\t-e\t\techo\n");
	fprintf(fp, "\t-b len\t\tbacklog length\n");
	fprintf(fp, "\t-c cmd resp\tsend resp if receive cmd\n");
	fprintf(fp, "\t-v ver\t\tset HTML version to use (default 1.1)\n");
	fprintf(fp, "\t-w url resp\tsend HTTP response for url\n");
	fprintf(fp, "\t-W\t\tsend a pre-build HTTP response for GET /\n");
	fprintf(fp, "\t-M[mail server name]\t\tbe an email server\n");
	fprintf(fp, "\t-l val\t\tASCII value to use for EOL char\n");
	fprintf(fp, "\t-d delay\tdelay in ms before replying\n");
	fprintf(fp, "\t-r\t\tuse random delay\n");
	fprintf(fp, "\t-m mod\t\tOnly report every mod'th connection\n");
	fprintf(fp, "\t-Z\t\ttoggle close on send (default off)\n");
	fprintf(fp, "\t-g\t\tdebug data\n");
	fprintf(fp, "\t-G\t\tdebug\n");
	fprintf(fp, "\t-h\t\tprint this\n");
}

int main(int argc, char **argv)
{
	int family = AF_UNSPEC;
	int port = 30080;
	int listenfd, connfd;
	pid_t childpid;
	socklen_t clilen;
	struct sockaddr_in cliaddr, servaddr;
	struct sockaddr_in6 cliaddr6, servaddr6;
	int opt;
	int sock_type = SOCK_STREAM;
	int n;
	char buf[128];
	struct sigaction sa;
	bool silent = false;
	char *addr_str = NULL;
	char addr_buf[sizeof (struct in6_addr)] __attribute__((align(__alignof__(struct in6_addr))));
	bool echo_data = false;
	char *endptr;
	long port_num;
	unsigned backlog = 4;
	bool close_after_send = false;
	char *html_version = "1.1";

	while ((opt = getopt(argc, argv, ":h46a:p:sueb:c:l:d:rm:v:WM::w:ZDgG")) != -1) {
		switch (opt) {
		case '4':
			family = AF_INET;
			break;
		case '6':
			family = AF_INET6;
			break;
		case 'a':
			addr_str = optarg;
			break;
		case 'p':
			port_num = strtol(optarg, &endptr, 10);
			if (*endptr || port_num <= 0 || port_num > 65535) {
				fprintf(stderr, "Port number '%s' invalid\n", optarg);
				exit(EXIT_FAILURE);
			}
			port = port_num;
			break;
		case 's':
			silent = true;
			break;
		case 'u':
			sock_type = SOCK_DGRAM;
			break;
		case 'e':
			echo_data = true;
			break;
		case 'b':
			backlog = strtoul(optarg, &endptr, 10);
			if (*endptr || backlog > 65535) {
				fprintf(stderr, "Backlog '%s' invalid\n", optarg);
				exit(EXIT_FAILURE);
			}
			break;
		case 'c':
			if (optind >= argc) {
				fprintf(stderr, "-%c '%s' missing response\n", optind, optarg);
				exit(EXIT_FAILURE);
			}

			new_cr(optarg, argv[optind++], close_after_send, TYPE_STD);
			break;
		case 'v':
			html_version = optarg;
			break;
		case 'W':
			new_html_cr("/", html_resp, html_version, close_after_send);
			break;
		case 'M':
			email_server = true;
			if (optarg)
				email_server_name = optarg;
			break;
		case 'w':
			if (optind >= argc) {
				fprintf(stderr, "-%c '%s' missing response\n", optind, optarg);
				exit(EXIT_FAILURE);
			}

			new_html_cr(optarg, argv[optind++], html_version, close_after_send);
			break;
		case 'l':
			EOL = strtoul(optarg, &endptr, 10);
			break;
		case 'd':
			rep_delay.tv_nsec = strtoul(optarg, &endptr, 10);
			rep_delay.tv_sec = rep_delay.tv_nsec / 1000;
			rep_delay.tv_nsec %= 1000;
			rep_delay.tv_nsec *= 1000000;
			break;
		case 'r':
			random_delay = true;
			if (optind < argc && argv[optind][0] != '-')
				random_seed = strtoul(argv[optind++], &endptr, 10);
			break;
		case 'm':
			connection_mod = strtoul(optarg, NULL, 0);
			break;
		case 'Z':
			close_after_send = !close_after_send;
			break;
		case 'g':
			debug_data = true;
			break;
		case 'G':
			debug= true;
			break;
		case 'h':
			print_usage(stdout, argv[0]);
			exit(0);
		case ':':
			fprintf(stderr, "Option '%c' is missing an argument\n", optopt);
			break;
		default: /* '?' */
			print_usage(stderr, argv[0]);
			exit(EXIT_FAILURE);
		}
	}

	if (random_delay) {
		if (!random_seed)
			random_seed = time(NULL);
		srandom(random_seed);
	}

	if (addr_str) {
		if (family == AF_UNSPEC) {
			if (strchr(addr_str, ':'))
				family = AF_INET6;
			else
				family = AF_INET;
		}

		if (inet_pton(family, addr_str, addr_buf) != 1) {
			printf("(%d) Invalid IPv%d address - %s\n", getpid(),  family == AF_INET ? 4 : 6, addr_str);
			exit (1);
		}
	}
	else if (family == AF_UNSPEC)
		family = AF_INET6;

	if ((listenfd = socket(family, sock_type, 0)) == -1) {
		printf ("Unable to create socket, errno %d (%m)\n", errno);
		exit(1);
	}

	struct linger li = { .l_onoff = 1, .l_linger = 1 };
	if (setsockopt(listenfd, SOL_SOCKET, SO_LINGER, (char *)&li, sizeof (struct linger))) {
		printf("(%d) Set SO_LINGER failed, errno %d (%m)\n", getpid(),  errno);
		exit(1);
	}

	if (setsockopt(listenfd, SOL_SOCKET, SO_REUSEADDR, &li.l_onoff, sizeof (li.l_onoff))) {
		printf("(%d) Set SO_REUSEADDR failed, errno %d (%m)\n", getpid(),  errno);
		exit(1);
	}

	if (family == AF_INET) {
		bzero(&servaddr, sizeof(servaddr));
		servaddr.sin_family = AF_INET;
		servaddr.sin_addr.s_addr = addr_str ? *(uint32_t*)addr_buf : htonl(INADDR_ANY);
		servaddr.sin_port = htons(port);

		if (bind(listenfd, (struct sockaddr *)&servaddr, sizeof(servaddr))) {
			printf ("bind returned %d (%m)\n", errno);
			exit(1);
		}
	} else {
		bzero(&servaddr6, sizeof(servaddr6));
		servaddr6.sin6_family = AF_INET6;
		servaddr6.sin6_addr = addr_str ? *(struct in6_addr *)addr_buf : in6addr_any;
		servaddr6.sin6_port = htons(port);

		if (bind(listenfd, (struct sockaddr *)&servaddr6, sizeof(servaddr6))) {
			printf ("bind returned %d (%m)\n", errno);
			exit(1);
		}
	}

	memset(&sa, 0, sizeof(sa));
	sa.sa_handler = SIG_DFL;
	sa.sa_flags = SA_NOCLDWAIT;
	sigaction(SIGCHLD, &sa, NULL);

	if (sock_type == SOCK_STREAM) {
		listen(listenfd, backlog);

		for (;;) {
			if (family == AF_INET) {
				clilen = sizeof (cliaddr);
				connfd = accept(listenfd, (struct sockaddr *)&cliaddr, &clilen);
			}
			else {
				clilen = sizeof (cliaddr6);
				connfd = accept(listenfd, (struct sockaddr *)&cliaddr6, &clilen);
			}

			if (!silent && (!(++connection_num % connection_mod) || connection_num == 1))
				printf("(%d) Received connection %lu\n", getpid(), connection_num);
			if ((childpid = fork()) == 0) {
				close(listenfd);
				if (echo_data || cmd_resp_list || email_server)
					process_data(connfd);
				else
					sleep (1);
				exit(0);
			}

			close(connfd);
		}
	}
	else
	{
		for (;;) {
			if (family == AF_INET) {
				clilen = sizeof (cliaddr);
				n = recvfrom(listenfd, buf, sizeof(buf), 0, (struct sockaddr *)&cliaddr, &clilen);
				if (echo_data)
					sendto(listenfd, buf, n, 0, (struct sockaddr *)&cliaddr, clilen);
			}
			else {
				clilen = sizeof (cliaddr6);
				n = recvfrom(listenfd, buf, sizeof(buf), 0, (struct sockaddr *)&cliaddr6, &clilen);
				if (echo_data)
					sendto(listenfd, buf, n, 0, (struct sockaddr *)&cliaddr6, clilen);
			}
			if (!silent)
				printf("(%d) Received %d bytes\n", getpid(),  n);
		}
	}
}
