/*
 * libipvs:	Library for manipulating IPVS through [gs]etsockopt
 *
 * Version:     $Id: libipvs.c,v 1.7 2003/06/08 09:31:39 wensong Exp $
 *
 * Authors:     Wensong Zhang <wensong@linuxvirtualserver.org>
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>

#include "libipvs.h"


typedef struct ipvs_servicedest_s {
	ipvs_service_t		svc;
	ipvs_dest_t		dest;
} ipvs_servicedest_t;

static int sockfd = -1;
static void* ipvs_func = NULL;
struct ip_vs_getinfo ipvs_info;

int ipvs_init(void)
{
	socklen_t len;

	len = sizeof(ipvs_info);
	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
		return -1;

	if (getsockopt(sockfd, IPPROTO_IP, IP_VS_SO_GET_INFO,
		       (char *)&ipvs_info, &len))
		return -1;

	return 0;
}


int ipvs_getinfo(void)
{
	socklen_t len;

	len = sizeof(ipvs_info);
	return getsockopt(sockfd, IPPROTO_IP, IP_VS_SO_GET_INFO,
			  (char *)&ipvs_info, &len);
}


unsigned int ipvs_version(void)
{
	return ipvs_info.version;
}


int ipvs_flush(void)
{
	return setsockopt(sockfd, IPPROTO_IP, IP_VS_SO_SET_FLUSH,
			  NULL, 0);
}


int ipvs_add_service(ipvs_service_t *svc)
{
	ipvs_func = ipvs_add_service;
	return setsockopt(sockfd, IPPROTO_IP,
			  IP_VS_SO_SET_ADD, (char *)svc, sizeof(*svc));
}


int ipvs_update_service(ipvs_service_t *svc)
{
	ipvs_func = ipvs_update_service;
	return setsockopt(sockfd, IPPROTO_IP,
			  IP_VS_SO_SET_EDIT, (char *)svc, sizeof(*svc));
}


int ipvs_del_service(ipvs_service_t *svc)
{
	ipvs_func = ipvs_del_service;
	return setsockopt(sockfd, IPPROTO_IP,
			  IP_VS_SO_SET_DEL, (char *)svc, sizeof(*svc));
}


int ipvs_zero_service(ipvs_service_t *svc)
{
	ipvs_func = ipvs_zero_service;
	return setsockopt(sockfd, IPPROTO_IP,
			  IP_VS_SO_SET_ZERO, (char *)svc, sizeof(*svc));
}


int ipvs_add_dest(ipvs_service_t *svc, ipvs_dest_t *dest)
{
	ipvs_servicedest_t svcdest = {*svc, *dest};

	ipvs_func = ipvs_add_dest;
	return setsockopt(sockfd, IPPROTO_IP, IP_VS_SO_SET_ADDDEST,
			  (char *)&svcdest, sizeof(svcdest));
}


int ipvs_update_dest(ipvs_service_t *svc, ipvs_dest_t *dest)
{
	ipvs_servicedest_t svcdest = {*svc, *dest};

	ipvs_func = ipvs_update_dest;
	return setsockopt(sockfd, IPPROTO_IP, IP_VS_SO_SET_EDITDEST,
			  (char *)&svcdest, sizeof(svcdest));
}


int ipvs_del_dest(ipvs_service_t *svc, ipvs_dest_t *dest)
{
	ipvs_servicedest_t svcdest = {*svc, *dest};

	ipvs_func = ipvs_del_dest;
	return setsockopt(sockfd, IPPROTO_IP, IP_VS_SO_SET_DELDEST,
			  (char *)&svcdest, sizeof(svcdest));
}


int ipvs_set_timeout(ipvs_timeout_t *to)
{
	ipvs_func = ipvs_set_timeout;
	return setsockopt(sockfd, IPPROTO_IP, IP_VS_SO_SET_TIMEOUT,
			  (char *)to, sizeof(*to));
}


static int _ipvs_start_daemon(void *dm)
{
	ipvs_func = ipvs_start_daemon;
	setsockopt(sockfd, IPPROTO_IP, IP_VS_SO_SET_STARTDAEMON,
		   (char *)dm, sizeof(struct ip_vs_daemon_user));
	exit(0);
}


static int _ipvs_stop_daemon(void *dm)
{
	ipvs_func = ipvs_stop_daemon;
	setsockopt(sockfd, IPPROTO_IP, IP_VS_SO_SET_STOPDAEMON,
		   (char *)dm, sizeof(struct ip_vs_daemon_user));
	exit(0);
}

int ipvs_start_daemon(ipvs_daemon_t *dm)
{
	pid_t pid;

	pid = fork();
	if (pid == 0) {
		_ipvs_start_daemon(dm);
		exit(0);
	} else if (pid > 0)
		return 0;
	return 1;
}

int ipvs_stop_daemon(ipvs_daemon_t *dm)
{
	pid_t pid;

	pid = fork();
	if (pid == 0) {
		_ipvs_stop_daemon(dm);
		exit(0);
	} else if (pid > 0)
		return 0;
	return 1;
}

struct ip_vs_get_services *ipvs_get_services(void)
{
	struct ip_vs_get_services *get;
	socklen_t len;

	len = sizeof(*get) +
		sizeof(ipvs_service_entry_t)*ipvs_info.num_services;
	if (!(get = malloc(len)))
		return NULL;

	ipvs_func = ipvs_get_services;
	get->num_services = ipvs_info.num_services;
	if (getsockopt(sockfd, IPPROTO_IP,
		       IP_VS_SO_GET_SERVICES, get, &len) < 0) {
		free(get);
		return NULL;
	}
	return get;
}


typedef int (*qsort_cmp_t)(const void *, const void *);

int
ipvs_cmp_services(ipvs_service_entry_t *s1, ipvs_service_entry_t *s2)
{
	int r;

	r = s1->fwmark - s2->fwmark;
	if (r != 0)
		return r;

	r = s1->protocol - s2->protocol;
	if (r != 0)
		return r;

	r = ntohl(s1->addr) - ntohl(s2->addr);
	if (r != 0)
		return r;

	return ntohs(s1->port) - ntohs(s2->port);
}


void
ipvs_sort_services(struct ip_vs_get_services *s, ipvs_service_cmp_t f)
{
	qsort(s->entrytable, s->num_services,
	      sizeof(ipvs_service_entry_t), (qsort_cmp_t)f);
}


struct ip_vs_get_dests *ipvs_get_dests(ipvs_service_entry_t *svc)
{
	struct ip_vs_get_dests *d;
	socklen_t len;

	len = sizeof(*d) + sizeof(ipvs_dest_entry_t)*svc->num_dests;
	if (!(d = malloc(len)))
		return NULL;

	ipvs_func = ipvs_get_dests;

	d->fwmark = svc->fwmark;
	d->protocol = svc->protocol;
	d->addr = svc->addr;
	d->port = svc->port;
	d->num_dests = svc->num_dests;

	if (getsockopt(sockfd, IPPROTO_IP,
		       IP_VS_SO_GET_DESTS, d, &len) < 0) {
		free(d);
		return NULL;
	}
	return d;
}


int ipvs_cmp_dests(ipvs_dest_entry_t *d1, ipvs_dest_entry_t *d2)
{
	int r;

	r = ntohl(d1->addr) - ntohl(d2->addr);
	if (r != 0)
		return r;

	return ntohs(d1->port) - ntohs(d2->port);
}


void ipvs_sort_dests(struct ip_vs_get_dests *d, ipvs_dest_cmp_t f)
{
	qsort(d->entrytable, d->num_dests,
	      sizeof(ipvs_dest_entry_t), (qsort_cmp_t)f);
}


ipvs_service_entry_t *
ipvs_get_service(__u32 fwmark, __u16 protocol, __u32 addr, __u16 port)
{
	ipvs_service_entry_t *svc;
	socklen_t len;

	len = sizeof(*svc);
	if (!(svc = malloc(len)))
		return NULL;

	ipvs_func = ipvs_get_service;

	svc->fwmark = fwmark;
	svc->protocol = protocol;
	svc->addr = addr;
	svc->port = port;
	if (getsockopt(sockfd, IPPROTO_IP, IP_VS_SO_GET_SERVICE,
		       (char *)svc, &len)) {
		free(svc);
		return NULL;
	}
	return svc;
}


ipvs_timeout_t *ipvs_get_timeout(void)
{
	ipvs_timeout_t *u;
	socklen_t len;

	len = sizeof(*u);
	if (!(u = malloc(len)))
		return NULL;

	ipvs_func = ipvs_get_timeout;
	if (getsockopt(sockfd, IPPROTO_IP, IP_VS_SO_GET_TIMEOUT,
		       (char *)u, &len)) {
		free(u);
		return NULL;
	}
	return u;
}


ipvs_daemon_t *ipvs_get_daemon(void)
{
	ipvs_daemon_t *u;
	socklen_t len;

	/* note that we need to get the info about two possible
	   daemons, master and backup. */
	len = sizeof(*u) * 2;
	if (!(u = malloc(len)))
		return NULL;

	ipvs_func = ipvs_get_daemon;
	if (getsockopt(sockfd, IPPROTO_IP,
		       IP_VS_SO_GET_DAEMON, (char *)u, &len)) {
		free(u);
		return NULL;
	}
	return u;
}


void ipvs_close(void)
{
	close(sockfd);
}


const char *ipvs_strerror(int err)
{
	unsigned int i;
	struct table_struct {
		void *func;
		int err;
		const char *message;
	} table [] = {
		{ 0, EPERM, "Permission denied (you must be root)" },
		{ 0, EINVAL, "Module is wrong version" },
		{ 0, ENOPROTOOPT, "Protocol not available" },
		{ 0, ENOMEM, "Memory allocation problem" },
		{ ipvs_add_service, EEXIST, "Service already exists" },
		{ ipvs_add_service, ENOENT, "Scheduler not found" },
		{ ipvs_update_service, ESRCH, "No such service" },
		{ ipvs_update_service, ENOENT, "Scheduler not found" },
		{ ipvs_del_service, ESRCH, "No such service" },
		{ ipvs_zero_service, ESRCH, "No such service" },
		{ ipvs_add_dest, ESRCH, "Service not defined" },
		{ ipvs_add_dest, EEXIST, "Destination already exists" },
		{ ipvs_update_dest, ESRCH, "Service not defined" },
		{ ipvs_update_dest, ENOENT, "No such destination" },
		{ ipvs_del_dest, ESRCH, "Service not defined" },
		{ ipvs_del_dest, ENOENT, "No such destination" },
		{ ipvs_start_daemon, EEXIST, "Daemon has already run" },
		{ ipvs_stop_daemon, ESRCH, "No daemon is running" },
		{ ipvs_get_services, ESRCH, "No such service" },
		{ ipvs_get_dests, ESRCH, "No such service" },
		{ ipvs_get_service, ESRCH, "No such service" },
	};

	for (i = 0; i < sizeof(table)/sizeof(struct table_struct); i++) {
		if ((!table[i].func || table[i].func == ipvs_func)
		    && table[i].err == err)
			return table[i].message;
	}

	return strerror(err);
}
