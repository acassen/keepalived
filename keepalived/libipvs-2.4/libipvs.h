/*
 * libipvs.h:   header file for the library ipvs
 *
 * Version:     $Id: libipvs.h,v 1.3 2002/07/09 14:41:19 wensong Exp $
 *
 * Authors:     Wensong Zhang <wensong@linuxvirtualserver.org>
 *
 */

#ifndef _LIBIPVS_H
#define _LIBIPVS_H

#include <net/ip_vs.h>

/*
 * The default IPVS_SVC_PERSISTENT_TIMEOUT is a little larger than average
 * connection time plus IPVS TCP FIN timeout (2*60 seconds). Because the
 * connection template won't be released until its controlled connection
 * entries are expired.
 * If IPVS_SVC_PERSISTENT_TIMEOUT is too less, the template will expire
 * soon and will be put in expire again and again, which causes additional
 * overhead. If it is too large, the same will always visit the same
 * server, which may make dynamic load imbalance worse.
 */
#define IPVS_SVC_PERSISTENT_TIMEOUT     (6*60)

/* ipvs info variable */
extern struct ip_vs_getinfo ipvs_info;

/* init socket and get ipvs info */
extern int ipvs_init(void);

/* get ipvs info separately */
extern int ipvs_getinfo(void);

/* get the version number */
extern unsigned int ipvs_version(void);

/* set command */
extern int ipvs_command(int cmd, struct ip_vs_rule_user *urule);

/* get all the ipvs services */
extern struct ip_vs_get_services *ipvs_get_services(void);

/* get the destination array of the specified service */
extern struct ip_vs_get_dests *ipvs_get_dests(struct ip_vs_service_user *svc);

/* get ipvs service */
extern struct ip_vs_service_user *
ipvs_get_service(__u32 fwmark, __u16 protocol, __u32 vaddr, __u16 vport);

/* get ipvs timeout */
extern struct ip_vs_timeout_user *ipvs_get_timeouts(void);

/* get ipvs daemon information */
extern struct ip_vs_daemon_user *ipvs_get_daemon(void);

/* close the socket */
extern void ipvs_close(void);

extern const char *ipvs_strerror(int err);

#endif /* _LIBIPVS_H */
