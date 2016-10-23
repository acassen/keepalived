/*
 *      IP Virtual Server
 *      data structure and functionality definitions
 */

#ifndef KEEPALIVED_IP_VS_H
#define KEEPALIVED_IP_VS_H

#ifdef HAVE_LINUX_IP_VS_H
#include <linux/ip_vs.h>
#else
#include <net/ip_vs.h>
#endif
/* Prior to Linux 4.2 have to include linux/in.h and linux/in6.h
 * or linux/netlink.h to include linux/netfilter.h */
#include <linux/netfilter.h>	/* For nf_inet_addr */

#ifdef _WITH_LVS_64BIT_STATS_
struct ip_vs_stats64 {
	__u64                   conns;          /* connections scheduled */
	__u64                   inpkts;         /* incoming packets */
	__u64                   outpkts;        /* outgoing packets */
	__u64                   inbytes;        /* incoming bytes */
	__u64                   outbytes;       /* outgoing bytes */

	__u64			cps;		/* current connection rate */
	__u64			inpps;		/* current in packet rate */
	__u64			outpps;		/* current out packet rate */
	__u64			inbps;		/* current in byte rate */
	__u64			outbps;		/* current out byte rate */
};
typedef struct ip_vs_stats64 ip_vs_stats_t;
#else
typedef struct ip_vs_stats_user ip_vs_stats_t;
#endif

struct ip_vs_service_app {
	struct ip_vs_service_user user;
	u_int16_t		af;
	union nf_inet_addr	nf_addr;
#ifdef _HAVE_PE_NAME_
	char			pe_name[IP_VS_PENAME_MAXLEN];
#endif
};

struct ip_vs_dest_app {
	struct ip_vs_dest_user	user;
	u_int16_t		af;
	union nf_inet_addr	nf_addr;
};


struct ip_vs_service_entry_app {
	struct ip_vs_service_entry user;
	ip_vs_stats_t		stats;
	u_int16_t		af;
	union nf_inet_addr	nf_addr;
#ifdef _HAVE_PE_NAME_
	char			pe_name[IP_VS_PENAME_MAXLEN];
#endif

};

struct ip_vs_dest_entry_app {
	struct ip_vs_dest_entry user;
	ip_vs_stats_t		stats;
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
	uint16_t		sync_maxlen;

	/* Multicast Port (base) */
	u_int16_t		mcast_port;

	/* Multicast TTL */
	u_int8_t		mcast_ttl;

	/* Multicast Address Family */
	u_int16_t		mcast_af;

	/* Multicast Address */
	union nf_inet_addr	mcast_group;
#endif
};

#endif	/* KEEPALIVED_IP_VS_H */
