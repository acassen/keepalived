/*
 * libipvs:	Library for manipulating IPVS through [gs]etsockopt
 *
 * Version:     $Id: libipvs.c,v 1.4 2001/11/23 14:34:17 wensong Exp $
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

#define SET_CMD(cmd)	(cmd - IP_VS_BASE_CTL)
#define GET_CMD(cmd)	(cmd - IP_VS_BASE_CTL + 128)

static int sockfd = -1;
static int ipvs_cmd = 0;
struct ip_vs_getinfo ipvs_info;


int ipvs_init(void)
{
	socklen_t len;

	len = sizeof(ipvs_info);
	if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) == -1)
		return -1;

	ipvs_cmd = GET_CMD(IP_VS_SO_GET_INFO);
	if (getsockopt(sockfd, IPPROTO_IP, IP_VS_SO_GET_INFO,
		       (char *)&ipvs_info, &len))
		return -1;

	return 0;
}


int ipvs_getinfo(void)
{
	socklen_t len;

	len = sizeof(ipvs_info);
	ipvs_cmd = GET_CMD(IP_VS_SO_GET_INFO);
	return getsockopt(sockfd, IPPROTO_IP, IP_VS_SO_GET_INFO,
			  (char *)&ipvs_info, &len);
}


unsigned int ipvs_version(void)
{
	return ipvs_info.version;
}


int ipvs_command(int cmd, struct ip_vs_rule_user *urule)
{
	ipvs_cmd = SET_CMD(cmd);
	return setsockopt(sockfd, IPPROTO_IP,
			  cmd, (char *)urule, sizeof(*urule));
}


struct ip_vs_get_services *ipvs_get_services(void)
{
	struct ip_vs_get_services *get;
	socklen_t len;

	len = sizeof(*get) +
		sizeof(struct ip_vs_service_user)*ipvs_info.num_services;
	if (!(get = malloc(len)))
		return NULL;

	ipvs_cmd = GET_CMD(IP_VS_SO_GET_SERVICES);
	get->num_services = ipvs_info.num_services;
	if (getsockopt(sockfd, IPPROTO_IP,
		       IP_VS_SO_GET_SERVICES, get, &len) < 0) {
		free(get);
		return NULL;
	}
	return get;
}


struct ip_vs_get_dests *ipvs_get_dests(struct ip_vs_service_user *svc)
{
	struct ip_vs_get_dests *d;
	socklen_t len;

	len = sizeof(*d) + sizeof(struct ip_vs_dest_user)*svc->num_dests;
	if (!(d = malloc(len)))
		return NULL;

	ipvs_cmd = GET_CMD(IP_VS_SO_GET_DESTS);
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

struct ip_vs_service_user *
ipvs_get_service(__u32 fwmark, __u16 protocol, __u32 vaddr, __u16 vport)
{
	struct ip_vs_service_user *svc;
	socklen_t len;

	len = sizeof(*svc);
	if (!(svc = malloc(len)))
		return NULL;

	ipvs_cmd = GET_CMD(IP_VS_SO_GET_SERVICE);
	svc->fwmark = fwmark;
	svc->protocol = protocol;
	svc->addr = vaddr;
	svc->port = vport;
	if (getsockopt(sockfd, IPPROTO_IP, IP_VS_SO_GET_SERVICE,
		       (char *)svc, &len)) {
		free(svc);
		return NULL;
	}
	return svc;
}


struct ip_vs_timeout_user *ipvs_get_timeouts(void)
{
	struct ip_vs_timeout_user *u;
	socklen_t len;

	len = sizeof(*u);
	if (!(u = malloc(len)))
		return NULL;

	ipvs_cmd = GET_CMD(IP_VS_SO_GET_TIMEOUTS);
	if (getsockopt(sockfd, IPPROTO_IP, IP_VS_SO_GET_TIMEOUTS,
		       (char *)u, &len)) {
		free(u);
		return NULL;
	}
	return u;
}


struct ip_vs_daemon_user *ipvs_get_daemon(void)
{
	struct ip_vs_daemon_user *u;
	socklen_t len;

	len = sizeof(*u);
	if (!(u = malloc(len)))
		return NULL;

	ipvs_cmd = GET_CMD(IP_VS_SO_GET_DAEMON);
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
		int cmd;
		int err;
		const char *message;
	} table [] =
	  { { 0, EPERM, "Permission denied (you must be root)" },
	    { 0, EINVAL, "Module is wrong version" },
	    { 0, ENOPROTOOPT, "Protocol not available" },
	    { 0, ENOMEM, "Memory allocation problem" },
	    { SET_CMD(IP_VS_SO_SET_ADD), EEXIST, "Service already exists" },
	    { SET_CMD(IP_VS_SO_SET_ADD), ENOENT, "Scheduler not found" },
	    { SET_CMD(IP_VS_SO_SET_EDIT), ESRCH, "No such service" },
	    { SET_CMD(IP_VS_SO_SET_EDIT), ENOENT, "Scheduler not found" },
	    { SET_CMD(IP_VS_SO_SET_DEL), ESRCH, "No such service" },
	    { SET_CMD(IP_VS_SO_SET_ADDDEST), ESRCH, "Service not defined" },
	    { SET_CMD(IP_VS_SO_SET_ADDDEST), EEXIST,
	      "Destination already exists" },
	    { SET_CMD(IP_VS_SO_SET_EDITDEST), ESRCH, "Service not defined" },
	    { SET_CMD(IP_VS_SO_SET_EDITDEST), ENOENT, "No such destination" },
	    { SET_CMD(IP_VS_SO_SET_DELDEST), ESRCH, "Service not defined" },
	    { SET_CMD(IP_VS_SO_SET_DELDEST), ENOENT, "No such destination" },
	    { SET_CMD(IP_VS_SO_SET_STARTDAEMON), EEXIST,
	      "Daemon has already run" },
	    { SET_CMD(IP_VS_SO_SET_STOPDAEMON), ESRCH,
	      "No daemon is running" },
	    { SET_CMD(IP_VS_SO_SET_STOPDAEMON), ESRCH,
	      "No daemon is running" },
	    { SET_CMD(IP_VS_SO_SET_ZERO), ESRCH, "No such service" },
	    { GET_CMD(IP_VS_SO_GET_SERVICE), ESRCH, "No such service" },
	    { GET_CMD(IP_VS_SO_GET_DESTS), ESRCH, "No such service" },
	  };

	for (i = 0; i < sizeof(table)/sizeof(struct table_struct); i++) {
		if ((!table[i].cmd || table[i].cmd == ipvs_cmd)
		    && table[i].err == err)
			return table[i].message;
	}

	return strerror(err);
}
