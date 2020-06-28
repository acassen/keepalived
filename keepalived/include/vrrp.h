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
 * Copyright (C) 2001-2017 Alexandre Cassen, <acassen@gmail.com>
 */

#ifndef _VRRP_H
#define _VRRP_H

#include "config.h"

/* system include */
#include <stdint.h>
#include <stdbool.h>
#include <net/if.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip6.h>

/* local include */
#include "vector.h"
#include "timer.h"
#include "notify.h"
#include "tracker.h"
#if defined _WITH_VRRP_AUTH_
#include "vrrp_ipsecah.h"
#endif
#include "vrrp_if.h"
#include "vrrp_sock.h"
#include "vrrp_track.h"

/* Special value for parameters when we want to know they haven't been set */
#define	PARAMETER_UNSET		UINT_MAX

struct _ip_address;

typedef struct _vrrphdr {			/* rfc2338.5.1 */
	uint8_t			vers_type;	/* 0-3=type, 4-7=version */
	uint8_t			vrid;		/* virtual router id */
	uint8_t			priority;	/* router priority */
	uint8_t			naddr;		/* address counter */
	union {
		struct {
			uint8_t	auth_type;	/* authentification type */
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
#define INADDR_VRRP_GROUP	"224.0.0.18"	/* multicast IPv4 addr - rfc2338.5.2.2 */
#define INADDR6_VRRP_GROUP	"ff02::12"	/* multicast IPv6 addr - rfc5798.5.1.2.2 */
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
	const char		*gname;			/* Group name */
	const vector_t		*iname;			/* Set of VRRP instances in this group, only used during initialisation */
	list_head_t		vrrp_instances;		/* vrrp_t - VRRP instances */
	unsigned		num_member_fault;	/* Number of members of group in fault state */
	unsigned		num_member_init;	/* Number of members of group in pending state */
	int			state;			/* current stable state */
	bool			sgroup_tracking_weight;	/* Use floating priority and scripts
							 * Used if need different priorities needed on a track object in a sync group.
							 * It probably won't work properly. */
	list_head_t		track_ifp;		/* tracked_if_t - Interface state we monitor */
	list_head_t		track_script;		/* Script state we monitor */
	list_head_t		track_file;		/* tracked_file_monitor_t - Files whose value we monitor */
#ifdef _WITH_CN_PROC_
	list_head_t		track_process;		/* tracked_process_t - Processes we monitor */
#endif
#ifdef _WITH_BFD_
	list_head_t		track_bfd;		/* tracked_bfd_t - BFD instances we monitor */
#endif

	/* State transition notification */
	bool			notify_exec;
	notify_script_t		*script_backup;
	notify_script_t		*script_master;
	notify_script_t		*script_fault;
	notify_script_t		*script_stop;
	notify_script_t		*script;
	int			smtp_alert;
	int			last_email_state;

	/* linked list member */
	list_head_t		e_list;
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
#ifdef _WITH_VRRP_AUTH_
	uint32_t	authtype_mismatch;
	uint32_t	auth_failure;
#endif

	uint64_t	pri_zero_rcvd;
	uint64_t	pri_zero_sent;

#ifdef _WITH_SNMP_RFC_
	uint32_t	chk_err;
	uint32_t	vers_err;
	uint32_t	vrid_err;
	timeval_t	uptime;
#ifdef _WITH_SNMP_RFCV3_
	uint32_t	master_reason;
	uint32_t	next_master_reason;
	uint32_t	proto_err_reason;
#endif
#endif
} vrrp_stats;

#ifdef _WITH_UNICAST_CHKSUM_COMPAT_
/* Whether we are using v1.3.6 and earlier VRRPv3 unicast checksums */
typedef enum chksum_compatibility {
	CHKSUM_COMPATIBILITY_NONE,		/* Default setting, will revert to old if receive advert with old */
	CHKSUM_COMPATIBILITY_NEVER,		/* Do not auto set old checksum mode */
	CHKSUM_COMPATIBILITY_MIN_COMPAT,	/* Values before this are new chksum, values after are old */
	CHKSUM_COMPATIBILITY_CONFIG,		/* Configuration specifies old chksum */
	CHKSUM_COMPATIBILITY_AUTO,		/* Use old chksum mode due to received advert with old mode */
} chksum_compatibility_t;
#endif

#ifdef _CHECKSUM_DEBUG_
typedef struct {
	uint32_t		last_rx_checksum;
	uint32_t		last_tx_checksum;
	uint8_t			last_rx_priority;
	uint8_t			last_tx_priority;
	in_addr_t		last_rx_from;
	bool			sent_to;
	bool			received_from;
} checksum_check_t;
#endif

typedef struct _unicast_peer_t {
	struct sockaddr_storage	address;
#ifdef _CHECKSUM_DEBUG_
	checksum_check_t	chk;
#endif
	unsigned char		min_ttl;
	unsigned char		max_ttl;

	/* Linked list member */
	list_head_t		e_list;
} unicast_peer_t;

/* parameters per virtual router -- rfc2338.6.1.2 */
typedef struct _vrrp_t {
	sa_family_t		family;			/* AF_INET|AF_INET6 */
	const char		*iname;			/* Instance Name */
	vrrp_sgroup_t		*sync;			/* Sync group we belong to */
	vrrp_stats		*stats;			/* Statistics */
	interface_t		*ifp;			/* Interface we belong to */
	bool			dont_track_primary;	/* If set ignores ifp faults */
	bool			linkbeat_use_polling;	/* Don't use netlink for interface status */
	bool			skip_check_adv_addr;	/* If set, don't check the VIPs in subsequent
							 * adverts from the same master */
	unsigned		strict_mode;		/* Enforces strict VRRP compliance */
#ifdef _HAVE_VRRP_VMAC_
	unsigned long		vmac_flags;		/* VRRP VMAC flags */
	char			vmac_ifname[IFNAMSIZ];	/* Name of VRRP VMAC interface */
	bool			duplicate_vrid_fault;	/* Set if we have a fault due to duplicate VRID */
#ifdef _HAVE_VRRP_IPVLAN_
	struct _ip_address	*ipvlan_addr;		/* Address to configure on an ipvlan interface */
	int			ipvlan_type;		/* Bridge, private or VEPA mode */
#endif
	interface_t		*configured_ifp;	/* Interface the configuration says we are on */
#endif
	list_head_t		track_ifp;		/* tracked_if_t - Interface state we monitor */
	list_head_t		track_script;		/* tracked_sc_t - Script state we monitor */
	list_head_t		track_file;		/* tracked_file_monitor_t - Files whose value we monitor */
#ifdef _WITH_CN_PROC_
	list_head_t		track_process;		/* tracked_process_t - Processes we monitor */
#endif
#ifdef _WITH_BFD_
	list_head_t		track_bfd;		/* tracked_bfd_t - BFD instance state we monitor */
#endif
	unsigned		num_script_if_fault;	/* Number of scripts and interfaces in fault state */
	unsigned		num_script_init;	/* Number of scripts in init state */
	bool			notifies_sent;		/* Set when initial notifies have been sent */
	struct sockaddr_storage	saddr;			/* Src IP address to use in VRRP IP header */
	bool			saddr_from_config;	/* Set if the source address is from configuration */
	bool			track_saddr;		/* Fault state if configured saddr is missing */
	struct sockaddr_storage	pkt_saddr;		/* Src IP address received in VRRP IP header */
	int			rx_ttl_hop_limit;	/* Received TTL/hop limit returned */
#ifdef IPV6_RECVPKTINFO
	bool			multicast_pkt;		/* Last IPv6 packet received was multicast */
#endif
	list_head_t		unicast_peer;		/* unicast_peer_t - peers to send unicast advert to */
	int			ttl;			/* TTL to send packet with if unicasting */
	bool			check_unicast_src;	/* It set, check the source address of a unicast advert */
#ifdef _WITH_UNICAST_CHKSUM_COMPAT_
	chksum_compatibility_t	unicast_chksum_compat;	/* Whether v1.3.6 and earlier chksum is used */
#endif
#ifdef _CHECKSUM_DEBUG_
	checksum_check_t	chk;
#endif
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
	unsigned		lower_prio_no_advert;	/* Don't send advert after lower prio advert received */
	unsigned		higher_prio_send_advert; /* Send advert after higher prio advert received */
	uint8_t			vrid;			/* virtual id. from 1(!) to 255 */
	uint8_t			base_priority;		/* configured priority value */
	uint8_t			effective_priority;	/* effective priority value */
	int			total_priority;		/* base_priority +/- track_script, track_interface and track_file weights.
							   effective_priority is this within the range [1,254]. */
	bool			vipset;			/* All the vips are set ? */
	list_head_t		vip;			/* ip_address_t - list of virtual ip addresses */
	unsigned		vip_cnt;		/* size of vip list */
	list_head_t		evip;			/* ip_address_t - list of protocol excluded VIPs.
							 * Those VIPs will not be presents into the
							 * VRRP adverts
							 */
	bool			promote_secondaries;	/* Set promote_secondaries option on interface */
	bool			evip_other_family;	/* There are eVIPs of the different address family from the vrrp family */
#ifdef _HAVE_FIB_ROUTING_
	list_head_t		vroutes;		/* ip_route_t - list of virtual routes */
	list_head_t		vrules;			/* ip_rule_t - list of virtual rules */
#endif
	unsigned		adver_int;		/* locally configured delay between advertisements*/
	unsigned		master_adver_int;	/* In v3, when we become BACKUP, we use the MASTER's
							 * adver_int. If we become MASTER again, we use the
							 * value we were originally configured with.
							 * In v2, this will always be the configured adver_int.
							 */
	size_t			kernel_rx_buf_size;	/* Socket receive buffer size */

#ifdef _WITH_FIREWALL_
	unsigned		accept;			/* Allow the non-master owner to process
							 * the packets destined to VIP. */
	bool			firewall_rules_set;	/* Firewall drop rules set to VIP list ? */
#endif
	bool			nopreempt;		/* true if higher prio does not preempt lower */
	unsigned long		preempt_delay;		/* Seconds*TIMER_HZ after startup until
							 * preemption based on higher prio over lower
							 * prio is allowed.  0 means no delay.
							 */
	timeval_t		preempt_time;		/* Time after which preemption can happen */
	int			state;			/* internal state (init/backup/master/fault) */
#ifdef _WITH_SNMP_VRRP_
	int			configured_state;	/* the configured state of the instance */
#endif
	int			wantstate;		/* user explicitly wants a state (back/mast) */
	bool			reload_master;		/* set if the instance is a master being reloaded */
	sock_t			*sockets;		/* In and out socket descriptors */

	int			debug;			/* Debug level 0-4 */

	int			version;		/* VRRP version (2 or 3) */

	/* State transition notification */
	int			smtp_alert;
	int			last_email_state;
	bool			notify_exec;
	bool			notify_deleted;
	notify_script_t		*script_backup;
	notify_script_t		*script_master;
	notify_script_t		*script_fault;
	notify_script_t		*script_stop;
	notify_script_t		*script_deleted;
	notify_script_t		*script_master_rx_lower_pri;
	notify_script_t		*script;
	int			notify_priority_changes;

	/* rfc2338.6.2 */
	uint32_t		ms_down_timer;
	timeval_t		sands;

	/* Sending buffer */
	char			*send_buffer;		/* Allocated send buffer */
	size_t			send_buffer_size;
	uint32_t		ipv4_csum;		/* Checksum ip IPv4 pseudo header for VRRPv3 */

#if defined _WITH_VRRP_AUTH_
	/* Authentication data (only valid for VRRPv2) */
	uint8_t			auth_type;		/* authentification type. VRRP_AUTH_* */
	uint8_t			auth_data[8];		/* authentification data */

	/* IPSEC AH counter def (only valid for VRRPv2) --rfc2402.3.3.2 */
	seq_counter_t		ipsecah_counter;
#endif

	/*
	 * To have my own ip_id creates collision with kernel ip->id
	 * but it should be ok because the packets are unlikely to be
	 * fragmented (they are non routable and small)
	 * This packet isnt routed, i can check the outgoing MTU
	 * to warn the user only if the outoing mtu is too small
	 */
	int			ip_id;

	/* RB tree on a sock_t for receiving data */
	rb_node_t		rb_vrid;

	/* RB tree on a sock_t for vrrp sands */
	rb_node_t		rb_sands;

	/* Sync group list member */
	list_head_t		s_list;			/* vrrp_sgroup_t->vrrp_instances */

	/* Linked list member */
	list_head_t		e_list;
} vrrp_t;

/* VRRP state machine -- rfc2338.6.4 */
#define VRRP_STATE_INIT			0	/* rfc2338.6.4.1 */
#define VRRP_STATE_BACK			1	/* rfc2338.6.4.2 */
#define VRRP_STATE_MAST			2	/* rfc2338.6.4.3 */
#define VRRP_STATE_FAULT		3	/* internal */
#define VRRP_STATE_DELETED		97	/* internal */
#define VRRP_STATE_STOP			98	/* internal */
#define VRRP_EVENT_MASTER_RX_LOWER_PRI	1000	/* Dummy state for sending event notify */
#define VRRP_EVENT_MASTER_PRIORITY_CHANGE 1001	/* Dummy state for sending event notify */
#define VRRP_EVENT_BACKUP_PRIORITY_CHANGE 1002	/* Dummy state for sending event notify */

/* VRRP packet handling */
#define VRRP_PACKET_OK       0
#define VRRP_PACKET_KO       1
#define VRRP_PACKET_DROP     2
#define VRRP_PACKET_NULL     3
#define VRRP_PACKET_OTHER    4	/* Multiple VRRP on LAN, Identify "other" VRRP */

/* VRRP Packet fixed length */
#define VRRP_AUTH_LEN		8
#define VRRP_VIP_TYPE		(1 << 0)
#define VRRP_EVIP_TYPE		(1 << 1)

/* We have to do some reduction of the calculation for VRRPv3 in order not to overflow a uint32; 625 / 16 == TIMER_CENTI_HZ / 256 */
#define VRRP_TIMER_SKEW(svr)	((svr)->version == VRRP_VERSION_3 ? (((256U-(svr)->effective_priority) * ((svr)->master_adver_int / TIMER_CENTI_HZ) * 625U) / 16U) : ((256U-(svr)->effective_priority) * TIMER_HZ/256U))
#define VRRP_TIMER_SKEW_MIN(svr)	((svr)->version == VRRP_VERSION_3 ? ((((svr)->master_adver_int / TIMER_CENTI_HZ) * 625U) / 16U) : (TIMER_HZ/256U))
#define VRRP_VIP_ISSET(V)	((V)->vipset)

#define VRRP_MIN(a, b)	((a) < (b)?(a):(b))
#define VRRP_MAX(a, b)	((a) > (b)?(a):(b))

#ifdef _HAVE_VRRP_VMAC_
#define VRRP_CONFIGURED_IFP(V)	((V)->configured_ifp)
#else
#define VRRP_CONFIGURED_IFP(V)	((V)->ifp)
#endif
#define VRRP_PKT_SADDR(V) (((V)->saddr.ss_family) ? ((struct sockaddr_in *) &(V)->saddr)->sin_addr.s_addr : IF_ADDR(VRRP_CONFIGURED_IFP(V)))

#define VRRP_ISUP(V)		(!(V)->num_script_if_fault)


/* Configuration summary flags */
extern bool have_ipv4_instance;
extern bool have_ipv6_instance;

#ifdef _NETWORK_TIMESTAMP_
extern bool do_network_timestamp;
#endif

#ifdef _CHECKSUM_DEBUG_
extern bool do_checksum_debug;
#endif

/* prototypes */
extern void clear_summary_flags(void);
extern size_t vrrp_adv_len(const vrrp_t *) __attribute__ ((pure));
extern const vrrphdr_t *vrrp_get_header(sa_family_t, const char *, size_t);
extern void open_sockpool_socket(sock_t *);
extern int new_vrrp_socket(vrrp_t *);
extern void vrrp_send_adv(vrrp_t *, uint8_t);
extern void vrrp_send_link_update(vrrp_t *, unsigned);
extern void add_vrrp_to_interface(vrrp_t *, interface_t *, int, bool, bool, track_t);
extern void del_vrrp_from_interface(vrrp_t *, interface_t *);
extern bool vrrp_state_master_rx(vrrp_t *, const vrrphdr_t *, const char *, ssize_t);
extern void vrrp_state_master_tx(vrrp_t *);
extern void vrrp_state_backup(vrrp_t *, const vrrphdr_t *, const char *, ssize_t);
extern void vrrp_state_goto_master(vrrp_t *);
extern void vrrp_state_leave_master(vrrp_t *, bool);
extern void vrrp_state_leave_fault(vrrp_t *);
extern bool vrrp_complete_init(void);
extern void vrrp_restore_interfaces_startup(void);
extern void restore_vrrp_interfaces(void);
extern void shutdown_vrrp_instances(void);
extern void clear_diff_vrrp(void);
extern void clear_diff_script(void);
extern void clear_diff_bfd(void);
extern void vrrp_restore_interface(vrrp_t *, bool, bool);
#ifdef THREAD_DUMP
extern void register_vrrp_fifo_addresses(void);
#endif

#endif
