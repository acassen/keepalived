#ifndef _LIBIPVS_H
#define _LIBIPVS_H

#include <net/ip_vs.h>

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
