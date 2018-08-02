/*
 * Soft:        Keepalived is a failover program for the LVS project
 *              <www.linuxvirtualserver.org>. It monitor & manipulate
 *              a loadbalanced server pool using multi-layer checks.
 *
 * Part:        NETLINK IPv4 address manipulation.
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

#include "config.h"

/* Global include */
#include <errno.h>
#include <arpa/inet.h>
#include <stdio.h>

/* local include */
#include "vrrp_ipaddress.h"
#ifdef _HAVE_LIBIPTC_
#include "vrrp_iptables.h"
#endif
#include "vrrp.h"
#include "keepalived_netlink.h"
#include "vrrp_data.h"
#include "logger.h"
#include "utils.h"
#include "bitops.h"
#include "global_data.h"
#include "rttables.h"
#include "memory.h"
#if !defined _HAVE_LIBIPTC_ || defined _LIBIPTC_DYNAMIC_
#include "utils.h"
#endif
#ifdef _WITH_LIBIPTC_
#include "vrrp_iptables.h"
#endif
#include "parser.h"


#define INFINITY_LIFE_TIME      0xFFFFFFFF

#if !defined _HAVE_LIBIPTC_ || defined _LIBIPTC_DYNAMIC_
static bool iptables_cmd_available;
static bool ip6tables_cmd_available;
#endif

char *
ipaddresstos(char *buf, ip_address_t *ipaddress)
{
	static char addr_str[INET6_ADDRSTRLEN];

	if (!buf)
		buf = addr_str;

	if (IP_IS6(ipaddress)) {
		inet_ntop(AF_INET6, &ipaddress->u.sin6_addr, buf, INET6_ADDRSTRLEN);
	} else {
		inet_ntop(AF_INET, &ipaddress->u.sin.sin_addr, buf, INET_ADDRSTRLEN);
	}

	return buf;
}

/* Add/Delete IP address to a specific interface_t */
int
netlink_ipaddress(ip_address_t *ipaddress, int cmd)
{
	struct ifa_cacheinfo cinfo;
	int status = 1;
	struct {
		struct nlmsghdr n;
		struct ifaddrmsg ifa;
		char buf[256];
	} req;
#if HAVE_DECL_IFA_FLAGS
	uint32_t ifa_flags = 0;
#else
	uint8_t ifa_flags = 0;
#endif

	if (cmd == IPADDRESS_ADD) {
		/* We can't add the address if the interface doesn't exist */
		if (!ipaddress->ifp->ifindex) {
			log_message(LOG_INFO, "Not adding address %s to %s since interface doesn't exist", ipaddresstos(NULL, ipaddress), ipaddress->ifp->ifname);
			return -1;
		}

		/* Make sure the ifindex for the address is current */
		ipaddress->ifa.ifa_index = ipaddress->ifp->ifindex;
	}
	else if (!ipaddress->ifp->ifindex) {
		/* The interface has been deleted, so there is no point deleting the address */
		return 0;
	}

	memset(&req, 0, sizeof (req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof (struct ifaddrmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = (cmd == IPADDRESS_DEL) ? RTM_DELADDR : RTM_NEWADDR;
	req.ifa = ipaddress->ifa;

	if (cmd == IPADDRESS_ADD)
		ifa_flags = ipaddress->flags;

	if (IP_IS6(ipaddress)) {
		if (cmd == IPADDRESS_ADD) {
			/* Mark IPv6 address as deprecated (rfc3484) in order to prevent
			 * using VRRP VIP as source address in healthchecking use cases.
			 */
			if (ipaddress->ifa.ifa_prefixlen == 128) {
				memset(&cinfo, 0, sizeof(cinfo));
				cinfo.ifa_prefered = 0;
				cinfo.ifa_valid = INFINITY_LIFE_TIME;

				addattr_l(&req.n, sizeof(req), IFA_CACHEINFO, &cinfo,
					  sizeof(cinfo));
			}

			/* Disable, per VIP, Duplicate Address Detection algorithm (DAD).
			 * Using the nodad flag has the following benefits:
			 *
			 * (1) The address becomes immediately usable after they're
			 *     configured.
			 * (2) In the case of a temporary layer-2 / split-brain problem
			 *     we can avoid that the active VIP transitions into the
			 *     dadfailed phase and stays there forever - leaving us
			 *     without service. HA/VRRP setups have their own "DAD"-like
			 *     functionality, so it's not really needed from the IPv6 stack.
			 */
#ifdef IFA_F_NODAD	/* Since Linux 2.6.19 */
			if (!(ipaddress->flagmask & IFA_F_NODAD))
				ifa_flags |= IFA_F_NODAD;
#endif
		}

		addattr_l(&req.n, sizeof(req), IFA_LOCAL,
			  &ipaddress->u.sin6_addr, sizeof(ipaddress->u.sin6_addr));
	} else {
		addattr_l(&req.n, sizeof(req), IFA_LOCAL,
			  &ipaddress->u.sin.sin_addr, sizeof(ipaddress->u.sin.sin_addr));

		if (cmd == IPADDRESS_ADD) {
			if (ipaddress->u.sin.sin_brd.s_addr)
				addattr_l(&req.n, sizeof(req), IFA_BROADCAST,
					  &ipaddress->u.sin.sin_brd, sizeof(ipaddress->u.sin.sin_brd));
		}
		else {
			/* IPADDRESS_DEL */
			addattr_l(&req.n, sizeof(req), IFA_ADDRESS,
				  &ipaddress->u.sin.sin_addr, sizeof(ipaddress->u.sin.sin_addr));
		}
	}

	if (cmd == IPADDRESS_ADD) {
#if HAVE_DECL_IFA_FLAGS
		if (ifa_flags)
			addattr32(&req.n, sizeof(req), IFA_FLAGS, ifa_flags);
#else
		req.ifa.ifa_flags = ifa_flags;
#endif
		if (ipaddress->label)
			addattr_l(&req.n, sizeof (req), IFA_LABEL,
				  ipaddress->label, strlen(ipaddress->label) + 1);

		if (ipaddress->have_peer)
                        addattr_l(&req.n, sizeof(req), IFA_ADDRESS, &ipaddress->peer, req.ifa.ifa_family == AF_INET6 ? 16 : 4);
	}

	/* If the state of the interface or its parent is down, it might be because the interface
	 * has been deleted, but we get the link status change message before the RTM_DELLINK message */
	if (cmd == IPADDRESS_DEL &&
	    (((ipaddress->ifp->ifi_flags & (IFF_UP | IFF_RUNNING)) != (IFF_UP | IFF_RUNNING)) ||
	     ((IF_BASE_IFP(ipaddress->ifp)->ifi_flags & (IFF_UP | IFF_RUNNING)) != (IFF_UP | IFF_RUNNING))))
		netlink_error_ignore = ENODEV;
	if (netlink_talk(&nl_cmd, &req.n) < 0)
		status = -1;
	netlink_error_ignore = 0;

	return status;
}

/* Add/Delete a list of IP addresses */
bool
netlink_iplist(list ip_list, int cmd, bool force)
{
	ip_address_t *ipaddr;
	element e;
	bool changed_entries = false;

	/* No addresses in this list */
	if (LIST_ISEMPTY(ip_list))
		return false;

	/*
	 * If "--dont-release-vrrp" is set then try to release addresses
	 * that may be there, even if we didn't set them.
	 */
	for (e = LIST_HEAD(ip_list); e; ELEMENT_NEXT(e)) {
		ipaddr = ELEMENT_DATA(e);
		if ((cmd == IPADDRESS_ADD && !ipaddr->set) ||
		    (cmd == IPADDRESS_DEL &&
		     (force || ipaddr->set || __test_bit(DONT_RELEASE_VRRP_BIT, &debug)))) {
			/* If we are removing addresses left over from previous run
			 * and they don't exist, don't report an error */
			if (force)
				netlink_error_ignore = ENODEV;

			if (netlink_ipaddress(ipaddr, cmd) > 0) {
				ipaddr->set = !(cmd == IPADDRESS_DEL);
				changed_entries = true;
			}
			else
				ipaddr->set = false;
		}
	}

	return changed_entries;
}

#if !defined _HAVE_LIBIPTC_ || defined _LIBIPTC_DYNAMIC_
static void
handle_iptable_rule_to_NA(ip_address_t *ipaddress, int cmd, bool force)
{
	char  *argv[14];
	int i = 0;
	int if_specifier = -1;
	int type_specifier ;
	char *addr_str;

	if (global_data->vrrp_iptables_inchain[0] == '\0')
		return;

	addr_str = ipaddresstos(NULL, ipaddress);

	argv[i++] = "ip6tables";
	argv[i++] = cmd ? "-A" : "-D";
	argv[i++] = global_data->vrrp_iptables_inchain;
	argv[i++] = "-d";
	argv[i++] = addr_str;
	if (IN6_IS_ADDR_LINKLOCAL(&ipaddress->u.sin6_addr)) {
		if_specifier = i;
		argv[i++] = "-i";
		argv[i++] = ipaddress->ifp->ifname;
	}
	argv[i++] = "-p";
	argv[i++] = "icmpv6";
	argv[i++] = "--icmpv6-type";
	type_specifier = i;
	argv[i++] = "136";
	argv[i++] = "-j";
	argv[i++] = "ACCEPT";
	argv[i] = NULL;

	if (fork_exec(argv) < 0 && !force)
		log_message(LOG_ERR, "Failed to %s ip6table rule to accept NAs sent"
				     " to vip %s", (cmd) ? "set" : "remove", addr_str);

	argv[type_specifier] = "135";

	if (fork_exec(argv) < 0 && !force)
		log_message(LOG_ERR, "Failed to %s ip6table rule to accept NSs sent"
				     " to vip %s", (cmd) ? "set" : "remove", addr_str);

	if (global_data->vrrp_iptables_outchain[0] == '\0')
		return;

	argv[2] = global_data->vrrp_iptables_outchain;
	argv[3] = "-s";
	if (if_specifier >= 0)
		argv[if_specifier] = "-o";

	/* Allow NSs to be sent - this should only happen if the underlying interface
	   doesn't have an IPv6 address */
	if (fork_exec(argv) < 0 && !force)
		log_message(LOG_ERR, "Failed to %s ip6table rule to allow NSs to be"
				     " sent from vip %s", (cmd) ? "set" : "remove", addr_str);

	argv[type_specifier] = "136";

	/* Allow NAs to be sent in reply to an NS */
	if (fork_exec(argv) < 0 && !force)
		log_message(LOG_ERR, "Failed to %s ip6table rule to allow NAs to be"
				     " sent from vip %s", (cmd) ? "set" : "remove", addr_str);
}

/* add/remove iptable drop rule to VIP */
static void
handle_iptable_rule_to_vip_cmd(ip_address_t *ipaddress, int cmd, bool force)
{
	char *argv[10];
	int i = 0;
	int if_specifier = -1;
	char *addr_str;
	char *ifname = NULL;

	if (IP_IS6(ipaddress)) {
		if (!ip6tables_cmd_available)
			return;
	} else {
		if (!iptables_cmd_available)
			return;
	}

	if (IP_IS6(ipaddress)) {
		if (IN6_IS_ADDR_LINKLOCAL(&ipaddress->u.sin6_addr))
			ifname = ipaddress->ifp->ifname;
		handle_iptable_rule_to_NA(ipaddress, cmd, force);
		argv[i++] = "ip6tables";
	} else {
		argv[i++] = "iptables";
	}

	addr_str = ipaddresstos(NULL, ipaddress);

	argv[i++] = cmd ? "-A" : "-D";
	argv[i++] = global_data->vrrp_iptables_inchain;
	argv[i++] = "-d";
	argv[i++] = addr_str;
	if (ifname) {
		if_specifier = i;
		argv[i++] = "-i";
		argv[i++] = ifname;
	}
	argv[i++] = "-j";
	argv[i++] = "DROP";
	argv[i] = NULL;

	if (fork_exec(argv) < 0) {
		if (!force)
			log_message(LOG_ERR, "Failed to %s ip%stable drop rule"
					     " to vip %s", (cmd) ? "set" : "remove", IP_IS6(ipaddress) ? "6" : "", addr_str);
	}
	else
		ipaddress->iptable_rule_set = (cmd != IPADDRESS_DEL);

	if (global_data->vrrp_iptables_outchain[0] == '\0')
		return;

	argv[2] = global_data->vrrp_iptables_outchain ;
	argv[3] = "-s";
	if (if_specifier >= 0)
		argv[if_specifier] = "-o";

	if (fork_exec(argv) < 0 && !force)
		log_message(LOG_ERR, "Failed to %s ip%stable drop rule"
				     " from vip %s", (cmd) ? "set" : "remove", IP_IS6(ipaddress) ? "6" : "", addr_str);
}
#endif

static inline void
handle_iptable_rule_to_vip(ip_address_t *ipaddr, int cmd,
#ifdef _HAVE_LIBIPTC_
							     struct ipt_handle *h,
#else
							     __attribute__((unused)) void *unused,
#endif
												   bool force)
{
	if (IP_IS6(ipaddr)) {
		if (!block_ipv6)
			return;
	} else {
		if (!block_ipv4)
			return;
	}

#ifdef _HAVE_LIBIPTC_
#ifdef _LIBIPTC_DYNAMIC_
	if ((IP_IS6(ipaddr) && using_libip6tc) ||
	    (!IP_IS6(ipaddr) && using_libip4tc))
#endif
	{
		handle_iptable_rule_to_vip_lib(ipaddr, cmd, h, force);
		return;
	}
#endif
#if !defined _HAVE_LIBIPTC_ || defined _LIBIPTC_DYNAMIC_
	handle_iptable_rule_to_vip_cmd(ipaddr, cmd, force);
#endif
}

/* add/remove iptable drop rules to iplist */
void
handle_iptable_rule_to_iplist(struct ipt_handle *h, list ip_list, int cmd, bool force)
{
	ip_address_t *ipaddr;
	element e;

	/* No addresses in this list */
	if (LIST_ISEMPTY(ip_list))
		return;

	for (e = LIST_HEAD(ip_list); e; ELEMENT_NEXT(e)) {
		ipaddr = ELEMENT_DATA(e);
		if ((cmd == IPADDRESS_DEL) == ipaddr->iptable_rule_set ||
		    force)
			handle_iptable_rule_to_vip(ipaddr, cmd, h, force);
	}
}

/* IP address dump/allocation */
void
free_ipaddress(void *if_data)
{
	ip_address_t *ipaddr = if_data;

	FREE_PTR(ipaddr->label);
	FREE(ipaddr);
}

static void
format_ipaddress(ip_address_t *ipaddr, char *buf, size_t buf_len)
{
	char peer[INET6_ADDRSTRLEN];
	char *buf_p = buf;
	char *buf_end = buf + buf_len;

	buf_p += snprintf(buf_p, buf_end - buf_p, "%s", ipaddresstos(NULL, ipaddr));
	if (!ipaddr->have_peer)
		buf_p += snprintf(buf_p, buf_end - buf_p, "/%d", ipaddr->ifa.ifa_prefixlen);
	if (!IP_IS6(ipaddr) && ipaddr->u.sin.sin_brd.s_addr) {
		buf_p += snprintf(buf_p, buf_end - buf_p, " brd %s",
			 inet_ntop2(ipaddr->u.sin.sin_brd.s_addr));
	}
	buf_p += snprintf(buf_p, buf_end - buf_p, " dev %s scope %s",
			    IF_NAME(ipaddr->ifp),
			    get_rttables_scope(ipaddr->ifa.ifa_scope));
	if (ipaddr->label)
		buf_p += snprintf(buf_p, buf_end - buf_p, " label %s", ipaddr->label);
	if (ipaddr->have_peer) {
		inet_ntop(ipaddr->ifa.ifa_family, &ipaddr->peer, peer, sizeof(peer));
		buf_p += snprintf(buf_p, buf_end - buf_p, " peer %s/%d" , peer , ipaddr->ifa.ifa_prefixlen);
	}
#ifdef IFA_F_HOMEADDRESS		/* Linux 2.6.19 */
	if (ipaddr->flags & IFA_F_HOMEADDRESS)
		buf_p += snprintf(buf_p, buf_end - buf_p, " home");
#endif
#ifdef IFA_F_NODAD			/* Linux 2.6.19 */
	if (ipaddr->flagmask & IFA_F_NODAD)
		buf_p += snprintf(buf_p, buf_end - buf_p, " -nodad");
#endif
#ifdef IFA_F_MANAGETEMPADDR		/* Linux 3.14 */
	if (ipaddr->flags & IFA_F_MANAGETEMPADDR)
		buf_p += snprintf(buf_p, buf_end - buf_p, " mngtmpaddr");
#endif
#ifdef IFA_F_NOPREFIXROUTE		/* Linux 3.14 */
	if (ipaddr->flags & IFA_F_NOPREFIXROUTE)
		buf_p += snprintf(buf_p, buf_end - buf_p, " noprefixroute");
#endif
#ifdef IFA_F_MCAUTOJOIN			/* Linux 4.1 */
	if (ipaddr->flags & IFA_F_MCAUTOJOIN)
		buf_p += snprintf(buf_p, buf_end - buf_p, " autojoin");
#endif
	if (ipaddr->dont_track)
		buf_p += snprintf(buf_p, buf_end - buf_p, "%s", " no_track");

	if (ipaddr->track_group)
		buf_p += snprintf(buf_p, buf_end - buf_p, " track_group %s", ipaddr->track_group->gname);
}

void
dump_ipaddress(FILE *fp, void *if_data)
{
	ip_address_t *ipaddr = if_data;
	char buf[256];

	format_ipaddress(ipaddr, buf, sizeof(buf));

	conf_write(fp, "     %s", buf);
}

ip_address_t *
parse_ipaddress(ip_address_t *ip_address, char *str, int allow_default)
{
	ip_address_t *new = ip_address;
	void *addr;
	char *p;
	unsigned prefixlen;

	/* No ip address, allocate a brand new one */
	if (!new) {
		new = (ip_address_t *) MALLOC(sizeof(ip_address_t));
	}

	/* Handle the specials */
	if (allow_default) {
		if (!strcmp(str, "default")) {
			new->ifa.ifa_family = AF_INET;
			return new;
		} else if (!strcmp(str, "default6")) {
			new->ifa.ifa_family = AF_INET6;
			return new;
		}
	}

	/* Parse ip address */
	new->ifa.ifa_family = (strchr(str, ':')) ? AF_INET6 : AF_INET;
	new->ifa.ifa_prefixlen = (IP_IS6(new)) ? 128 : 32;
	p = strchr(str, '/');
	if (p) {
		*p = 0;
		if (!read_unsigned(p + 1, &prefixlen, 1, new->ifa.ifa_prefixlen, true))
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid address prefix len %s for address %s - using %d", p + 1, str, new->ifa.ifa_prefixlen);
		else
			new->ifa.ifa_prefixlen = prefixlen;
	}

	addr = (IP_IS6(new)) ? (void *) &new->u.sin6_addr :
			       (void *) &new->u.sin.sin_addr;
	if (!inet_pton(IP_FAMILY(new), str, addr)) {
		report_config_error(CONFIG_GENERAL_ERROR, "VRRP parsed invalid IP %s. skipping IP...", str);
		if (!ip_address)
			FREE(new);
		new = NULL;
	}

	/* Restore slash */
	if (p) {
		*p = '/';
	}

	return new;
}
void
alloc_ipaddress(list ip_list, vector_t *strvec, interface_t *ifp, bool allow_track_group)
{
/* The way this works is slightly strange.
 *
 * If !ifp, then this is being called for a static address, in which
 * case either dev DEVNAME must be specified, or we will attempt to
 * add the address to DFTL_INT.
 * Otherwise, we are being called for a VIP/eVIP. We don't set the
 * interface for the address unless dev DEVNAME is specified, in case
 * a VMAC is added later. When the complete configuration is checked,
 * if the ifindex is 0, then it will be set to the interface of the
 * vrrp_instance (VMAC or physical interface).
 */
	ip_address_t *new;
	interface_t *ifp_local;
	char *str;
	unsigned int i = 0, addr_idx = 0;
	uint8_t scope;
	bool param_avail;
	bool param_missing = false;
	char *param;
	ip_address_t peer = { .ifa.ifa_family = AF_UNSPEC };
	int brd_len = 0;
	uint32_t mask;
	bool have_broadcast = false;

	new = (ip_address_t *) MALLOC(sizeof(ip_address_t));

	/* We expect the address first */
	if (!parse_ipaddress(new, strvec_slot(strvec,0), false)) {
		FREE(new);
		return;
	}

	addr_idx = i++;

	/* FMT parse */
	while (i < vector_size(strvec)) {
		str = strvec_slot(strvec, i);

		/* cmd parsing */
		param_avail = (vector_size(strvec) >= i+2);

		if (!strcmp(str, "dev")) {
			if (!param_avail) {
				param_missing = true;
				break;
			}

			if (new->ifp) {
				report_config_error(CONFIG_GENERAL_ERROR, "Cannot specify static ipaddress device more than once for %s", FMT_STR_VSLOT(strvec, addr_idx));
				FREE(new);
				return;
			}
			if (!(ifp_local = if_get_by_ifname(strvec_slot(strvec, ++i), IF_CREATE_IF_DYNAMIC))) {
				report_config_error(CONFIG_GENERAL_ERROR, "WARNING - interface %s for ip address %s doesn't exist",
						FMT_STR_VSLOT(strvec, i), FMT_STR_VSLOT(strvec, addr_idx));
				FREE(new);
				return;
			}
			new->ifp = ifp_local;
		} else if (!strcmp(str, "scope")) {
			if (!param_avail) {
				param_missing = true;
				break;
			}

			if (!find_rttables_scope(strvec_slot(strvec, ++i), &scope))
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid scope '%s' specified for %s - ignoring", FMT_STR_VSLOT(strvec,i), FMT_STR_VSLOT(strvec, addr_idx));
			else
				new->ifa.ifa_scope = scope;
		} else if (!strcmp(str, "broadcast") || !strcmp(str, "brd")) {
			if (!param_avail) {
				param_missing = true;
				break;
			}

			if (IP_IS6(new)) {
				report_config_error(CONFIG_GENERAL_ERROR, "VRRP is trying to assign a broadcast %s to the IPv6 address %s !!?? "
						      "WTF... skipping VIP..."
						    , FMT_STR_VSLOT(strvec, i), FMT_STR_VSLOT(strvec, addr_idx));
				FREE(new);
				return;
			}

			have_broadcast = true;

			param = strvec_slot(strvec, ++i);
			if (!strcmp(param, "-"))
				brd_len = -2;
			else if (!strcmp(param, "+"))
				brd_len = -1;
			else if (!inet_pton(AF_INET, param, &new->u.sin.sin_brd)) {
				report_config_error(CONFIG_GENERAL_ERROR, "VRRP is trying to assign invalid broadcast %s. "
						      "skipping VIP...", FMT_STR_VSLOT(strvec, i));
				FREE(new);
				return;
			}
		} else if (!strcmp(str, "label")) {
			if (!param_avail) {
				param_missing = true;
				break;
			}

			new->label = MALLOC(IFNAMSIZ);
			strncpy(new->label, strvec_slot(strvec, ++i), IFNAMSIZ);
		} else if (!strcmp(str, "peer")) {
			if (!param_avail) {
				param_missing = true;
				break;
			}

			i++;
			if (new->have_peer) {
				report_config_error(CONFIG_GENERAL_ERROR, "Peer %s - another peer has already been specified", FMT_STR_VSLOT(strvec, i));
				continue;
			}

			if (!parse_ipaddress(&peer, strvec_slot(strvec,i), false))
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid peer address %s", FMT_STR_VSLOT(strvec, i));
			else if (peer.ifa.ifa_family != new->ifa.ifa_family)
				report_config_error(CONFIG_GENERAL_ERROR, "Peer address %s does not match address family", FMT_STR_VSLOT(strvec, i));
			else {
				if ((new->ifa.ifa_family == AF_INET6 && new->ifa.ifa_prefixlen != 128) ||
				    (new->ifa.ifa_family == AF_INET && new->ifa.ifa_prefixlen != 32))
					report_config_error(CONFIG_GENERAL_ERROR, "Cannot specify address prefix when specifying peer address - ignoring");
				new->have_peer = true;
				new->ifa.ifa_prefixlen = peer.ifa.ifa_prefixlen;
				if (new->ifa.ifa_family == AF_INET6)
					new->peer.sin6_addr = peer.u.sin6_addr;
				else
					new->peer.sin_addr = peer.u.sin.sin_addr;
			}
#ifdef IFA_F_HOMEADDRESS		/* Linux 2.6.19 */
		} else if (!strcmp(str, "home")) {
			new->flags |= IFA_F_HOMEADDRESS;
			new->flagmask |= IFA_F_HOMEADDRESS;
#endif
#ifdef IFA_F_NODAD			/* Linux 2.6.19 */
		} else if (!strcmp(str, "-nodad")) {
			new->flagmask |= IFA_F_NODAD;
#endif
#ifdef IFA_F_MANAGETEMPADDR		/* Linux 3.14 */
		} else if (!strcmp(str, "mngtmpaddr")) {
			new->flags |= IFA_F_MANAGETEMPADDR;
			new->flagmask |= IFA_F_MANAGETEMPADDR;
#endif
#ifdef IFA_F_NOPREFIXROUTE		/* Linux 3.14 */
		} else if (!strcmp(str, "noprefixroute")) {
			new->flags |= IFA_F_NOPREFIXROUTE;
			new->flagmask |= IFA_F_NOPREFIXROUTE;
#endif
#ifdef IFA_F_MCAUTOJOIN			/* Linux 4.1 */
		} else if (!strcmp(str, "autojoin")) {
			new->flags |= IFA_F_MCAUTOJOIN;
			new->flagmask |= IFA_F_MCAUTOJOIN;
#endif
		} else if (!strcmp(str, "no_track")) {
			new->dont_track = true;
		} else if (allow_track_group && !strcmp(str, "track_group")) {
			if (!param_avail) {
				param_missing = true;
				break;
			}
			i++;
			if (new->track_group) {
				report_config_error(CONFIG_GENERAL_ERROR, "track_group %s is a duplicate", FMT_STR_VSLOT(strvec, i));
				break;
			}
			if (!(new->track_group = find_track_group(strvec_slot(strvec, i))))
                                report_config_error(CONFIG_GENERAL_ERROR, "track_group %s not found", FMT_STR_VSLOT(strvec, i));
		} else
			report_config_error(CONFIG_GENERAL_ERROR, "Unknown configuration entry '%s' for ip address - ignoring", str);
		i++;
	}

	/* Check if there was a missing parameter for a keyword */
	if (param_missing) {
		report_config_error(CONFIG_GENERAL_ERROR, "No %s parameter specified for %s", str, FMT_STR_VSLOT(strvec, addr_idx));
		free(new);
		return;
	}

	/* Set the broadcast address if necessary */
	if (have_broadcast && new->have_peer) {
		report_config_error(CONFIG_GENERAL_ERROR, "Cannot specify broadcast and peer addresses - ignoring broadcast address");
		new->u.sin.sin_brd.s_addr = 0;
	}
	else if (brd_len < 0 && new->ifa.ifa_prefixlen <= 30) {
		new->u.sin.sin_brd = (new->have_peer) ? new->peer.sin_addr : new->u.sin.sin_addr;
		mask = 0xffffffffU >> new->ifa.ifa_prefixlen;
		mask = htonl(mask);
		if (brd_len == -1)	/* '+' */
			new->u.sin.sin_brd.s_addr |= mask;
		else
			new->u.sin.sin_brd.s_addr &= ~mask;
	}
	else if (brd_len < 0)
		report_config_error(CONFIG_GENERAL_ERROR, "Address prefix length %d too long for broadcast", new->ifa.ifa_prefixlen);

	if (!ifp && !new->ifp) {
		if (!global_data->default_ifp) {
			global_data->default_ifp = if_get_by_ifname(DFLT_INT, IF_CREATE_IF_DYNAMIC);
			if (!global_data->default_ifp) {
				report_config_error(CONFIG_GENERAL_ERROR, "Default interface %s doesn't exist for static address %s.",
							DFLT_INT, FMT_STR_VSLOT(strvec, addr_idx));
				FREE(new);
				return;
			}
		}
		new->ifp = global_data->default_ifp;
	}

	if (new->ifa.ifa_family == AF_INET6) {
		if (new->ifa.ifa_scope) {
			report_config_error(CONFIG_GENERAL_ERROR, "Cannot specify scope for IPv6 addresses (%s) - ignoring scope", FMT_STR_VSLOT(strvec, addr_idx));
			new->ifa.ifa_scope = 0;
		}
		if (new->label) {
			report_config_error(CONFIG_GENERAL_ERROR, "Cannot specify label for IPv6 addresses (%s) - ignoring label", FMT_STR_VSLOT(strvec, addr_idx));
			FREE(new->label);
			new->label = NULL;
		}
	}

	if (new->track_group && !new->ifp) {
		report_config_error(CONFIG_GENERAL_ERROR, "Static route have track_group if interface not specified");
		new->track_group = NULL;
	}

	list_add(ip_list, new);
}

/* Find an address in a list */
static bool
address_exist(list l, ip_address_t *ipaddress)
{
	ip_address_t *ipaddr;
	element e;

	LIST_FOREACH(l, ipaddr, e) {
		if (IP_ISEQ(ipaddr, ipaddress)) {
			ipaddr->set = ipaddress->set;
			ipaddr->iptable_rule_set = ipaddress->iptable_rule_set;
			ipaddr->ifa.ifa_index = ipaddress->ifa.ifa_index;
			return true;
		}
	}

	return false;
}

/* Clear diff addresses */
void
clear_diff_address(struct ipt_handle *h, list old, list new)
{
	ip_address_t *ipaddr;
	element e;
	char addr_str[INET6_ADDRSTRLEN];
	void *addr;

	/* No addresses in previous conf */
	if (LIST_ISEMPTY(old))
		return;

	/* All addresses removed */
	if (LIST_ISEMPTY(new)) {
		log_message(LOG_INFO, "Removing a complete VIP or e-VIP block");
		netlink_iplist(old, IPADDRESS_DEL, false);
		handle_iptable_rule_to_iplist(h, old, IPADDRESS_DEL, false);
		return;
	}

	LIST_FOREACH(old, ipaddr, e) {
		if (!address_exist(new, ipaddr) && ipaddr->set) {
			addr = (IP_IS6(ipaddr)) ? (void *) &ipaddr->u.sin6_addr :
						  (void *) &ipaddr->u.sin.sin_addr;
			inet_ntop(IP_FAMILY(ipaddr), addr, addr_str, INET6_ADDRSTRLEN);

			log_message(LOG_INFO, "ip address %s/%d dev %s, no longer exist"
					    , addr_str
					    , ipaddr->ifa.ifa_prefixlen
					    , ipaddr->ifp->ifname);
			netlink_ipaddress(ipaddr, IPADDRESS_DEL);
			if (ipaddr->iptable_rule_set)
				handle_iptable_rule_to_vip(ipaddr, IPADDRESS_DEL, h, false);
		}
	}
}

/* Clear static ip address */
void
clear_diff_saddresses(void)
{
	clear_diff_address(NULL, old_vrrp_data->static_addresses, vrrp_data->static_addresses);
}

static void
check_chains_exist(void)
{
#ifdef _HAVE_LIBIPTC_
#ifdef _LIBIPTC_DYNAMIC_
	if (using_libip4tc || using_libip6tc)
#endif
		check_chains_exist_lib();
#endif

#if !defined _HAVE_LIBIPTC_ || defined _LIBIPTC_DYNAMIC_
	char *argv[4];

	argv[1] = "-nL";
	argv[2] = global_data->vrrp_iptables_inchain;
	argv[3] = NULL;

	if (block_ipv4)
	{
#ifdef _LIBIPTC_DYNAMIC_
		if (!using_libip4tc)
#endif
		{
			argv[0] = "iptables";

			if (fork_exec(argv) < 0) {
				log_message(LOG_INFO, "iptables chain %s does not exist", global_data->vrrp_iptables_inchain);
				block_ipv4 = false;
			}
			else if (global_data->vrrp_iptables_outchain[0]) {
				argv[2] = global_data->vrrp_iptables_outchain;
				if (fork_exec(argv) < 0) {
					log_message(LOG_INFO, "iptables chain %s does not exist", global_data->vrrp_iptables_outchain);
					block_ipv4 = false;
				}
			}
		}
	}

	if (block_ipv6)
	{
#ifdef _LIBIPTC_DYNAMIC_
		if (!using_libip6tc)
#endif
		{
			argv[0] = "ip6tables";
			argv[2] = global_data->vrrp_iptables_inchain;

			if (fork_exec(argv) < 0) {
				log_message(LOG_INFO, "ip6tables chain %s does not exist", global_data->vrrp_iptables_inchain);
				block_ipv6 = false;
			}
			else if (global_data->vrrp_iptables_outchain[0]) {
				argv[2] = global_data->vrrp_iptables_outchain;
				if (fork_exec(argv) < 0) {
					log_message(LOG_INFO, "ip6tables chain %s does not exist", global_data->vrrp_iptables_outchain);
					block_ipv6 = false;
				}
			}
		}
	}
#endif
}

void
iptables_init(void)
{
	if (!block_ipv4 && !block_ipv6) {
#ifdef _HAVE_LIBIPSET_
		global_data->using_ipsets = false;
#endif
		return;
	}

#ifdef _HAVE_LIBIPTC_
	iptables_init_lib();
#endif

#if !defined _HAVE_LIBIPTC_ || defined _LIBIPTC_DYNAMIC_
	char *argv[3];

	/* If can't use libiptc, check iptables command available */
	argv[1] = "-V";
	argv[2] = NULL;

	if (block_ipv4
#ifdef _LIBIPTC_DYNAMIC_
		       && !using_libip4tc
#endif
				       )
	{
		argv[0] = "iptables";
		if (!(iptables_cmd_available = (fork_exec(argv) >= 0))) {
			log_message(LOG_INFO, "iptables command not available - can't filter IPv4 VIP address destinations");
			block_ipv4 = false;
		}
	}

	if (block_ipv6
#ifdef _LIBIPTC_DYNAMIC_
		       && !using_libip6tc
#endif
					 )
	{
		argv[0] = "ip6tables";
		if (!(ip6tables_cmd_available = (fork_exec(argv) >= 0))) {
			log_message(LOG_INFO, "ip6tables command not available - can't filter IPv6 VIP address destinations");
			block_ipv6 = false;
		}
	}
#endif

	if (block_ipv4 || block_ipv6)
		check_chains_exist();
#ifdef _HAVE_LIBIPSET_
	else
		global_data->using_ipsets = false;
#endif
}

void reinstate_static_address(ip_address_t *ipaddr)
{
	char buf[256];

	ipaddr->set = (netlink_ipaddress(ipaddr, IPADDRESS_ADD) > 0);
	format_ipaddress(ipaddr, buf, sizeof(buf));
	log_message(LOG_INFO, "Restoring deleted static address %s", buf);
}
