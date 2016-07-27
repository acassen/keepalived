/*
 * libipvs.h:	header file for the library ipvs
 *
 * Authors:	Wensong Zhang <wensong@linuxvirtualserver.org>
 *
 */

#ifndef _LIBIPVS_H
#define _LIBIPVS_H

#include "ip_vs.h"


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
#define IPVS_SVC_PERSISTENT_TIMEOUT	(6*60)


typedef struct ip_vs_service_app	ipvs_service_t;
typedef struct ip_vs_dest_app		ipvs_dest_t;
typedef struct ip_vs_timeout_user	ipvs_timeout_t;
typedef struct ip_vs_daemon_app		ipvs_daemon_t;
typedef struct ip_vs_service_entry_app	ipvs_service_entry_t;
typedef struct ip_vs_dest_entry_app	ipvs_dest_entry_t;


/* init socket and get ipvs info */
extern int ipvs_init(void);

/* Set timeout parameters */
extern int ipvs_set_timeout(ipvs_timeout_t *to);

/* flush all the rules */
extern int ipvs_flush(void);

/* add a virtual service */
extern int ipvs_add_service(ipvs_service_t *svc);

/* update a virtual service with new options */
extern int ipvs_update_service(ipvs_service_t *svc);

/* delete a virtual service */
extern int ipvs_del_service(ipvs_service_t *svc);

/* zero the counters of a service or all */
extern int ipvs_zero_service(ipvs_service_t *svc);

/* add a destination server into a service */
extern int ipvs_add_dest(ipvs_service_t *svc, ipvs_dest_t *dest);

/* update a destination server with new options */
extern int ipvs_update_dest(ipvs_service_t *svc, ipvs_dest_t *dest);

/* remove a destination server from a service */
extern int ipvs_del_dest(ipvs_service_t *svc, ipvs_dest_t *dest);

#ifdef _INCLUDE_UNUSED_CODE_
/* set timeout */
extern int ipvs_set_timeout(ipvs_timeout_t *to);
#endif

/* start a connection synchronizaiton daemon (master/backup) */
extern int ipvs_start_daemon(ipvs_daemon_t *dm);

/* stop a connection synchronizaiton daemon (master/backup) */
extern int ipvs_stop_daemon(ipvs_daemon_t *dm);

#ifdef _WITH_SNMP_CHECKER_
/* get the destination array of the specified service */
extern struct ip_vs_get_dests_app *ipvs_get_dests(ipvs_service_entry_t *svc);

/* get an ipvs service entry */
extern ipvs_service_entry_t *
ipvs_get_service(__u32 fwmark, __u16 af, __u16 protocol, union nf_inet_addr addr, __u16 port);
#endif

/* close the socket */
extern void ipvs_close(void);

extern const char *ipvs_strerror(int err);

#endif /* _LIBIPVS_H */
