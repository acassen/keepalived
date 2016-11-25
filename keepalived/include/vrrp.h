/*
 * Soft:        Vrrpd is an implementation of VRRPv2 as specified in rfc2338.
 *              VRRP is a protocol which elect a master server on a LAN. If the
 *              master fails, a backup server takes over.
 *              The original implementation has been made by jerome etienne.
 *
 * Part:        vrrp.c program include file.
 *
 * Author:      Alexandre Cassen, <acassen@linux-vs.org>
 *
 *              This program is distributed in the hope that it will be useful,
 *              but WITHOUT ANY WARRANTY; without even the implied warranty of
 *              MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.
 *              See the GNU General Public License for more details.
 *
 *              This program is free software; you can redistribute it and/or
 *              modify it under the terms of the GNU General Public License
 *              as published by the Free Software Foundation; either version
 *              2 of the License, or (at your option) any later version.
 *
 * Copyright (C) 2001-2012 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _VRRP_H
#define _VRRP_H

/* system include */
#include <unistd.h>
#include <stdbool.h>

/* local include */
#include "vrrp_ipaddress.h"
#include "vrrp_ipsecah.h"
#include "vrrp_if.h"
#include "vrrp_track.h"
#include "timer.h"
#include "utils.h"
#include "vector.h"
#include "list.h"
#include "notify.h"

/* Special value for parameters when we want to know they haven't been set */
#define	PARAMETER_UNSET		UINT_MAX

typedef struct _vrrphdr {			/* rfc2338.5.1 */
	uint8_t			vers_type;	/* 0-3=type, 4-7=version */
	uint8_t			vrid;		/* virtual router id */
	uint8_t			priority;	/* router priority */
	uint8_t			naddr;		/* address counter */
	union {
		struct {
	uint8_t			auth_type;	/* authentification type */
			uint8_t adver_int;	/* advertisement interval (in sec) */
		} v2;
		struct {
			uint16_t adver_int;	/* advertisement interval (in centi-sec (100ms)) */
		} v3;
	};
	uint16_t		chksum;		/* checksum (ip-like one) */
	/* here <naddr> ip addresses */
	/* here authentification infos */
} vrrphdr_t;

typedef struct {
	uint32_t src;
	uint32_t dst;
	uint8_t  zero;
	uint8_t  proto;
	uint16_t len;
} ipv4_phdr_t;

/* protocol constants */
#define INADDR_VRRP_GROUP	0xe0000012	/* multicast addr - rfc2338.5.2.2 */
#define VRRP_IP_TTL		255		/* in and out pkt ttl -- rfc2338.5.2.3 */
#define IPPROTO_VRRP		112		/* IP protocol number -- rfc2338.5.2.4 */
#define VRRP_VERSION_2		2		/* VRRP version 2 -- rfc2338.5.3.1 */
#define VRRP_VERSION_3		3		/* VRRP version 3 -- rfc5798.5.2.1 */
#define VRRP_PKT_ADVERT		1		/* packet type -- rfc2338.5.3.2 */
#define VRRP_PRIO_OWNER		255		/* priority of the ip owner -- rfc2338.5.3.4 */
#define VRRP_PRIO_DFL		100		/* default priority -- rfc2338.5.3.4 */
#define VRRP_PRIO_STOP		0		/* priority to stop -- rfc2338.5.3.4 */
#define VRRP_MAX_ADDR		0xFF		/* count addr field is 8 bits wide */
#define VRRP_AUTH_NONE		0		/* no authentification -- rfc2338.5.3.6 */
#ifdef _WITH_VRRP_AUTH_
#define VRRP_AUTH_PASS		1		/* password authentification -- rfc2338.5.3.6 */
#define VRRP_AUTH_AH		2		/* AH(IPSec) authentification - rfc2338.5.3.6 */
#endif
#define VRRP_ADVER_DFL		1		/* advert. interval (in sec) -- rfc2338.5.3.7 */
#define VRRP_GARP_DELAY		(5 * TIMER_HZ)	/* Default delay to launch gratuitous arp */
#define VRRP_GARP_REP		5		/* Default repeat value for MASTER state gratuitous arp */
#define VRRP_GARP_REFRESH	0		/* Default interval for refresh gratuitous arp (0 = none) */
#define VRRP_GARP_REFRESH_REP	1		/* Default repeat value for refresh gratuitous arp */

/*
 * parameters per vrrp sync group. A vrrp_sync_group is a set
 * of VRRP instances that need to be state sync together.
 */
typedef struct _vrrp_sgroup {
	char			*gname;			/* Group name */
	vector_t		*iname;			/* Set of VRRP instances in this group */
	list			index_list;		/* List of VRRP instances */
	int			state;			/* current stable state */
	int			global_tracking;	/* Use floating priority and scripts
							 * All VRRP must share same tracking conf
							 */

	/* State transition notification */
	bool			notify_exec;
	notify_script_t		*script_backup;
	notify_script_t		*script_master;
	notify_script_t		*script_fault;
	notify_script_t		*script;
	bool			smtp_alert;
} vrrp_sgroup_t;

/* Statistics */
typedef struct _vrrp_stats {
	uint64_t	advert_rcvd;
	uint32_t	advert_sent;

	uint32_t	become_master;
	uint32_t	release_master;

	uint64_t	packet_len_err;
	uint64_t	advert_interval_err;
	uint64_t	ip_ttl_err;
	uint64_t	invalid_type_rcvd;
	uint64_t	addr_list_err;

	uint32_t	invalid_authtype;
	uint32_t	authtype_mismatch;
	uint32_t	auth_failure;

	uint64_t	pri_zero_rcvd;
	uint64_t	pri_zero_sent;

#ifdef _WITH_SNMP_RFC_
	uint32_t	chk_err;
	uint32_t	vers_err;
	uint32_t	vrid_err;
	timeval_t	uptime;
#ifdef _WITH_SNMP_RFCV3_
	uint32_t	master_reason;
	uint32_t	proto_err_reason;
#endif
#endif
} vrrp_stats;

/* parameters per virtual router -- rfc2338.6.1.2 */
typedef struct _vrrp_t {
	sa_family_t		family;			/* AF_INET|AF_INET6 */
	char			*iname;			/* Instance Name */
	vrrp_sgroup_t		*sync;			/* Sync group we belong to */
	vrrp_stats		*stats;			/* Statistics */
	interface_t		*ifp;			/* Interface we belong to */
	bool			dont_track_primary;	/* If set ignores ifp faults */
	bool			skip_check_adv_addr;	/* If set, don't check the VIPs in subsequent
							 * adverts from the same master */
	unsigned		strict_mode;		/* Enforces strict VRRP compliance */
#ifdef _HAVE_VRRP_VMAC_
	unsigned long		vmac_flags;		/* VRRP VMAC flags */
	char			vmac_ifname[IFNAMSIZ];	/* Name of VRRP VMAC interface */
	ifindex_t		vmac_ifindex;		/* ifindex of vmac interface */
#endif
	list			track_ifp;		/* Interface state we monitor */
	list			track_script;		/* Script state we monitor */
	struct sockaddr_storage	saddr;			/* Src IP address to use in VRRP IP header */
	struct sockaddr_storage	pkt_saddr;		/* Src IP address received in VRRP IP header */
	list			unicast_peer;		/* List of Unicast peer to send advert to */
	struct sockaddr_storage master_saddr;		/* Store last heard Master address */
	uint8_t			master_priority;	/* Store last heard priority */
	timeval_t		last_transition;	/* Store transition time */
	unsigned		garp_delay;		/* Delay to launch gratuitous ARP */
	timeval_t		garp_refresh;		/* Next scheduled gratuitous ARP refresh */
	timeval_t		garp_refresh_timer;	/* Next scheduled gratuitous ARP timer */
	unsigned		garp_rep;		/* gratuitous ARP repeat value */
	unsigned		garp_refresh_rep;	/* refresh gratuitous ARP repeat value */
	unsigned		garp_lower_prio_delay;	/* Delay to second set or ARP messages */
	bool			garp_pending;		/* Are there gratuitous ARP messages still to be sent */
	bool			gna_pending;		/* Are there gratuitous NA messages still to be sent */
	unsigned		garp_lower_prio_rep;	/* Number of ARP messages to send at a time */
	unsigned		lower_prio_no_advert;	/* Don't send advert after lower prio
							 * advert received */
	uint8_t			vrid;			/* virtual id. from 1(!) to 255 */
	uint8_t			base_priority;		/* configured priority value */
	uint8_t			effective_priority;	/* effective priority value */
	bool			vipset;			/* All the vips are set ? */
	list			vip;			/* list of virtual ip addresses */
	list			evip;			/* list of protocol excluded VIPs.
							 * Those VIPs will not be presents into the
							 * VRRP adverts
							 */
	bool			promote_secondaries;	/* Set promote_secondaries option on interface */
	bool			evip_add_ipv6;		/* Enable IPv6 for eVIPs if this is an IPv4 instance */
	list			vroutes;		/* list of virtual routes */
	list			vrules;			/* list of virtual rules */
	unsigned		adver_int;		/* locally configured delay between advertisements*/
	unsigned		master_adver_int;	/* In v3, when we become BACKUP, we use the MASTER's
							 * adver_int. If we become MASTER again, we use the
							 * value we were originally configured with.
							 */
	unsigned		accept;			/* Allow the non-master owner to process
							 * the packets destined to VIP.
							 */
	bool			iptable_rules_set;	/* Iptable drop rules set to VIP list ? */
	bool			nopreempt;		/* true if higher prio does not preempt lower */
	unsigned long		preempt_delay;		/* Seconds*TIMER_HZ after startup until
							 * preemption based on higher prio over lower
							 * prio is allowed.  0 means no delay.
							 */
	timeval_t		preempt_time;		/* Time after which preemption can happen */
	int			state;			/* internal state (init/backup/master) */
	int			init_state;		/* the initial state of the instance */
	int			wantstate;		/* user explicitly wants a state (back/mast) */
	int			fd_in;			/* IN socket descriptor */
	int			fd_out;			/* OUT socket descriptor */

	int			debug;			/* Debug level 0-4 */

	bool			quick_sync;		/* Will be set when waiting for the other members
							 * in the sync group to become master.
							 * If set the next check will occur in one interval
							 * instead of three intervals.
							 */

	int version;		/* VRRP version (2 or 3) */

	/* State transition notification */
	bool			smtp_alert;
	bool			notify_exec;
	notify_script_t		*script_backup;
	notify_script_t		*script_master;
	notify_script_t		*script_fault;
	notify_script_t		*script_stop;
	notify_script_t		*script;

	/* rfc2338.6.2 */
	uint32_t		ms_down_timer;
	timeval_t		sands;

	/* Sending buffer */
	char			*send_buffer;		/* Allocated send buffer */
	size_t			send_buffer_size;

#if defined _WITH_VRRP_AUTH_
	/* Authentication data (only valid for VRRPv2) */
	uint8_t			auth_type;		/* authentification type. VRRP_AUTH_* */
	uint8_t			auth_data[8];		/* authentification data */
#endif

	/*
	 * To have my own ip_id creates collision with kernel ip->id
	 * but it should be ok because the packets are unlikely to be
	 * fragmented (they are non routable and small)
	 * This packet isnt routed, i can check the outgoing MTU
	 * to warn the user only if the outoing mtu is too small
	 */
	int			ip_id;

	/* IPSEC AH counter def (only valid for VRRPv2) --rfc2402.3.3.2 */
	seq_counter_t		*ipsecah_counter;
} vrrp_t;

/* VRRP state machine -- rfc2338.6.4 */
#define VRRP_STATE_INIT			0	/* rfc2338.6.4.1 */
#define VRRP_STATE_BACK			1	/* rfc2338.6.4.2 */
#define VRRP_STATE_MAST			2	/* rfc2338.6.4.3 */
#define VRRP_STATE_FAULT		3	/* internal */
#define VRRP_STATE_GOTO_MASTER		4	/* internal */
#define VRRP_STATE_GOTO_FAULT		98	/* internal */
#define VRRP_DISPATCHER			99	/* internal */
#define VRRP_MCAST_RETRY		10	/* internal */
#define VRRP_MAX_FSM_STATE		4	/* internal */

/* VRRP packet handling */
#define VRRP_PACKET_OK       0
#define VRRP_PACKET_KO       1
#define VRRP_PACKET_DROP     2
#define VRRP_PACKET_NULL     3
#define VRRP_PACKET_OTHER    4	/* Muliple VRRP on LAN, Identify "other" VRRP */

/* VRRP Packet fixed length */
#define VRRP_AUTH_LEN		8
#define VRRP_VIP_TYPE		(1 << 0)
#define VRRP_EVIP_TYPE		(1 << 1)

/* VRRP macro */
#define VRRP_IS_BAD_VERSION(id)		((id) < 2 || (id) > 3)
#define VRRP_IS_BAD_VID(id)		((id) < 1 || (id) > 255)	/* rfc2338.6.1.vrid */
#define VRRP_IS_BAD_PRIORITY(p)		((p)<1 || (p)>255)	/* rfc2338.6.1.prio */
#define VRRP_IS_BAD_ADVERT_INT(d)	((d)<1)
#define VRRP_IS_BAD_DEBUG_INT(d)	((d)<0 || (d)>4)
#define VRRP_IS_BAD_PREEMPT_DELAY(d)	((d)>TIMER_MAX_SEC)
#define VRRP_SEND_BUFFER(V)		((V)->send_buffer)
#define VRRP_SEND_BUFFER_SIZE(V)	((V)->send_buffer_size)

/* We have to do some reduction of the calculation for VRRPv3 in order not to overflow a uint32; 625 / 16 == TIMER_CENTI_HZ / 256 */
#define VRRP_TIMER_SKEW(svr)	((svr)->version == VRRP_VERSION_3 ? (((256U-(svr)->base_priority) * ((svr)->adver_int / TIMER_CENTI_HZ) * 625U) / 16U) : ((256U-(svr)->base_priority) * TIMER_HZ/256U))
#define VRRP_VIP_ISSET(V)	((V)->vipset)

#define VRRP_MIN(a, b)	((a) < (b)?(a):(b))
#define VRRP_MAX(a, b)	((a) > (b)?(a):(b))

#define VRRP_PKT_SADDR(V) (((V)->saddr.ss_family) ? ((struct sockaddr_in *) &(V)->saddr)->sin_addr.s_addr : IF_ADDR((V)->ifp))
#define VRRP_PKT_SADDR6(V) (((V)->saddr.ss_family) ? ((struct sockaddr_in6 *) &(V)->saddr)->sin6_addr : IF_ADDR6((V)->ifp))

#define VRRP_IF_ISUP(V)		((IF_ISUP((V)->ifp) || (V)->dont_track_primary) & \
				((!LIST_ISEMPTY((V)->track_ifp)) ? TRACK_ISUP((V)->track_ifp) : 1))

#define VRRP_SCRIPT_ISUP(V)	((!LIST_ISEMPTY((V)->track_script)) ? SCRIPT_ISUP((V)->track_script) : 1)

#define VRRP_ISUP(V)		(VRRP_IF_ISUP(V) && VRRP_SCRIPT_ISUP(V))

/* prototypes */
extern vrrphdr_t *vrrp_get_header(sa_family_t, char *, unsigned *);
extern int open_vrrp_send_socket(sa_family_t, int, ifindex_t, bool);
extern int open_vrrp_read_socket(sa_family_t, int, ifindex_t, bool);
extern int new_vrrp_socket(vrrp_t *);
extern void vrrp_send_link_update(vrrp_t *, unsigned);
extern int vrrp_send_adv(vrrp_t *, uint8_t);
extern int vrrp_state_fault_rx(vrrp_t *, char *, ssize_t);
extern int vrrp_state_master_rx(vrrp_t *, char *, ssize_t);
extern int vrrp_state_master_tx(vrrp_t *, const int);
extern void vrrp_state_backup(vrrp_t *, char *, ssize_t);
extern void vrrp_state_goto_master(vrrp_t *);
extern void vrrp_state_leave_master(vrrp_t *);
extern bool vrrp_complete_init(void);
#ifdef _WITH_LVS_
extern bool vrrp_ipvs_needed(void);
#endif
extern void restore_vrrp_interfaces(void);
extern void shutdown_vrrp_instances(void);
extern void clear_diff_vrrp(void);
extern void clear_diff_script(void);
extern void vrrp_restore_interface(vrrp_t *, bool, bool);
extern void vrrp_remove_delayed_arp_na(vrrp_t *);

#endif
