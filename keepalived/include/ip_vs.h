/*
 *      IP Virtual Server
 *      data structure and functionality definitions
 */

#ifndef KEEPALIVED_IP_VS_H
#define KEEPALIVED_IP_VS_H

#include <linux/ip_vs.h>
#include <linux/netfilter.h>	/* For nf_inet_addr */

struct ip_vs_service_app {
	struct ip_vs_service_user user;
	u_int16_t		af;
	union nf_inet_addr	nf_addr;
	char			pe_name[IP_VS_PENAME_MAXLEN];
};

struct ip_vs_dest_app {
	struct ip_vs_dest_user	user;
	u_int16_t		af;
	union nf_inet_addr	nf_addr;
};


struct ip_vs_service_entry_app {
	struct ip_vs_service_entry user;
	u_int16_t		af;
	union nf_inet_addr	nf_addr;
	char			pe_name[IP_VS_PENAME_MAXLEN];

};

struct ip_vs_dest_entry_app {
	struct ip_vs_dest_entry user;
	u_int16_t		af;
	union nf_inet_addr	nf_addr;
};

struct ip_vs_get_dests_app {
	struct {	// Can we avoid this duplication of definition?
	/* which service: user fills in these */
	__u16			protocol;
	__be32			addr;		/* virtual address */
	__be16			port;
	__u32			fwmark;		/* firwall mark of service */

	/* number of real servers */
	unsigned int		num_dests;

	/* the real servers */
	struct ip_vs_dest_entry_app	entrytable[0];
	} user;

	u_int16_t		af;
	union nf_inet_addr	nf_addr;
};

/* The argument to IP_VS_SO_GET_SERVICES */
struct ip_vs_get_services_app {
	struct {
	/* number of virtual services */
	unsigned int		num_services;

	/* service table */
	struct ip_vs_service_entry_app entrytable[0];
	} user;
};

/* The argument to IP_VS_SO_GET_DAEMON */
struct ip_vs_daemon_kern {
	/* sync daemon state (master/backup) */
	int			state;

	/* multicast interface name */
	char			mcast_ifn[IP_VS_IFNAME_MAXLEN];

	/* SyncID we belong to */
	int			syncid;
};

struct ip_vs_daemon_app {
	/* sync daemon state (master/backup) */
	int			state;

	/* multicast interface name */
	char			mcast_ifn[IP_VS_IFNAME_MAXLEN];

	/* SyncID we belong to */
	int			syncid;

#ifdef _HAVE_IPVS_SYNCD_ATTRIBUTES_
	/* UDP Payload Size */
	int			sync_maxlen;

	/* Multicast Port (base) */
	u_int16_t		mcast_port;

	/* Multicast TTL */
	u_int16_t		mcast_ttl;

	/* Multicast Address Family */
	u_int16_t		mcast_af;

	/* Multicast Address */
	union nf_inet_addr	mcast_group;
#endif
};

#endif	/* KEEPALIVED_IP_VS_H */
