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
#include "vrrp.h"
#include "keepalived_netlink.h"
#include "vrrp_data.h"
#include "logger.h"
#include "utils.h"
#include "bitops.h"
#include "global_data.h"
#include "rttables.h"
#include "memory.h"
#include "parser.h"
#ifdef _WITH_FIREWALL_
#include "vrrp_firewall.h"
#endif


#define INFINITY_LIFE_TIME      0xFFFFFFFF

const char *
ipaddresstos(char *buf, const ip_address_t *ip_addr)
{
	static char addr_str[IPADDRESSTOS_BUF_LEN];
	char *end;

	if (!buf)
		buf = addr_str;

	if (IP_IS6(ip_addr))
		inet_ntop(AF_INET6, &ip_addr->u.sin6_addr, buf, INET6_ADDRSTRLEN);
	else
		inet_ntop(AF_INET, &ip_addr->u.sin.sin_addr, buf, INET_ADDRSTRLEN);
	if ((ip_addr->ifa.ifa_family == AF_INET && ip_addr->ifa.ifa_prefixlen != 32 ) ||
	    (ip_addr->ifa.ifa_family == AF_INET6 && ip_addr->ifa.ifa_prefixlen != 128 )) {
		end = buf + strlen(buf);
		snprintf(end, buf + IPADDRESSTOS_BUF_LEN - end, "/%u", ip_addr->ifa.ifa_prefixlen);
	}

	return buf;
}

bool
compare_ipaddress(const ip_address_t *X, const ip_address_t *Y)
{
	if (!X && !Y)
		return false;

	if (!X != !Y ||
	    X->ifa.ifa_family != Y->ifa.ifa_family)
		return true;

	if (X->ifa.ifa_prefixlen != Y->ifa.ifa_prefixlen ||
// We can't check ifp here and later. On a reload, has ifp been set up by now?
//	    !X->ifp != !Y->ifp ||
#ifdef _HAVE_VRRP_VMAC_
	    X->use_vmac != Y->use_vmac ||
#endif
	    X->ifa.ifa_scope != Y->ifa.ifa_scope)
		return true;

	if (X->ifp &&
#ifdef _HAVE_VRRP_VMAC_
	    X->ifp->base_ifp != Y->ifp->base_ifp
#else
	    X->ifp != Y->ifp
#endif
				)
		return true;

	if (!string_equal(X->label, Y->label))
		return true;

	if (X->ifa.ifa_family == AF_INET6)
		return X->u.sin6_addr.s6_addr32[0] != Y->u.sin6_addr.s6_addr32[0] ||
			X->u.sin6_addr.s6_addr32[1] != Y->u.sin6_addr.s6_addr32[1] ||
			X->u.sin6_addr.s6_addr32[2] != Y->u.sin6_addr.s6_addr32[2] ||
			X->u.sin6_addr.s6_addr32[3] != Y->u.sin6_addr.s6_addr32[3];

	return X->u.sin.sin_addr.s_addr != Y->u.sin.sin_addr.s_addr;
}

/* Add/Delete IP address to a specific interface_t */
int
netlink_ipaddress(ip_address_t *ip_addr, int cmd)
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
		if (!ip_addr->ifp->ifindex) {
			log_message(LOG_INFO, "Not adding address %s to %s since interface doesn't exist"
					    , ipaddresstos(NULL, ip_addr), ip_addr->ifp->ifname);
			return -1;
		}

		/* Make sure the ifindex for the address is current */
		ip_addr->ifa.ifa_index = ip_addr->ifp->ifindex;
	}
	else if (!ip_addr->ifp->ifindex) {
		/* The interface has been deleted, so there is no point deleting the address */
		return 0;
	}
	else if (!ip_addr->ifa.ifa_index)
		ip_addr->ifa.ifa_index = ip_addr->ifp->ifindex;

	memset(&req, 0, sizeof (req));

	req.n.nlmsg_len = NLMSG_LENGTH(sizeof (struct ifaddrmsg));
	req.n.nlmsg_flags = NLM_F_REQUEST;
	req.n.nlmsg_type = (cmd == IPADDRESS_DEL) ? RTM_DELADDR : RTM_NEWADDR;
	req.ifa = ip_addr->ifa;

	if (cmd == IPADDRESS_ADD)
		ifa_flags = ip_addr->flags;

	if (IP_IS6(ip_addr)) {
		if (cmd == IPADDRESS_ADD) {
			/* A preferred_lft of 0 marks an IPv6 address as deprecated (rfc3484)
			 * in order to prevent using VRRP VIP as source address in
			 * healthchecking use cases. */
			if (ip_addr->preferred_lft != INFINITY_LIFE_TIME) {
				memset(&cinfo, 0, sizeof(cinfo));
				cinfo.ifa_prefered = ip_addr->preferred_lft;
				cinfo.ifa_valid = INFINITY_LIFE_TIME;

				addattr_l(&req.n, sizeof(req), IFA_CACHEINFO, &cinfo, sizeof(cinfo));
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
			if (!(ip_addr->flagmask & IFA_F_NODAD))
				ifa_flags |= IFA_F_NODAD;
		}

		addattr_l(&req.n, sizeof(req), IFA_LOCAL,
			  &ip_addr->u.sin6_addr, sizeof(ip_addr->u.sin6_addr));
	} else {
		addattr_l(&req.n, sizeof(req), IFA_LOCAL,
			  &ip_addr->u.sin.sin_addr, sizeof(ip_addr->u.sin.sin_addr));

		if (cmd == IPADDRESS_ADD) {
			if (ip_addr->u.sin.sin_brd.s_addr)
				addattr_l(&req.n, sizeof(req), IFA_BROADCAST,
					  &ip_addr->u.sin.sin_brd, sizeof(ip_addr->u.sin.sin_brd));
		}
		else {
			/* IPADDRESS_DEL */
			addattr_l(&req.n, sizeof(req), IFA_ADDRESS,
				  &ip_addr->u.sin.sin_addr, sizeof(ip_addr->u.sin.sin_addr));
		}
	}

	if (cmd == IPADDRESS_ADD) {
#if HAVE_DECL_IFA_FLAGS
		if (ifa_flags)
			addattr32(&req.n, sizeof(req), IFA_FLAGS, ifa_flags);
#else
		req.ifa.ifa_flags = ifa_flags;
#endif
		if (ip_addr->label)
			addattr_l(&req.n, sizeof (req), IFA_LABEL,
				  ip_addr->label, strlen(ip_addr->label) + 1);

		if (ip_addr->have_peer)
			addattr_l(&req.n, sizeof(req), IFA_ADDRESS, &ip_addr->peer, req.ifa.ifa_family == AF_INET6 ? 16 : 4);
	}

	/* If the state of the interface or its parent is down, it might be because the interface
	 * has been deleted, but we get the link status change message before the RTM_DELLINK message */
	if (cmd == IPADDRESS_DEL &&
	    (((ip_addr->ifp->ifi_flags & (IFF_UP | IFF_RUNNING)) != (IFF_UP | IFF_RUNNING))
#ifdef _HAVE_VRRP_VMAC_
	     || ((IF_BASE_IFP(ip_addr->ifp)->ifi_flags & (IFF_UP | IFF_RUNNING)) != (IFF_UP | IFF_RUNNING))
#endif
													     ))
		netlink_error_ignore = ENODEV;
	if (netlink_talk(&nl_cmd, &req.n) < 0)
		status = -1;
	netlink_error_ignore = 0;

	return status;
}

/* Add/Delete a list of IP addresses */
bool
netlink_iplist(list_head_t *ip_list, int cmd, bool force)
{
	ip_address_t *ip_addr;
	bool changed_entries = false;

	/*
	 * If "--dont-release-vrrp" is set then try to release addresses
	 * that may be there, even if we didn't set them.
	 */
	list_for_each_entry(ip_addr, ip_list, e_list) {
		if ((cmd == IPADDRESS_ADD && !ip_addr->set) ||
		    (cmd == IPADDRESS_DEL &&
		     (force || ip_addr->set || __test_bit(DONT_RELEASE_VRRP_BIT, &debug)))) {
			/* If we are removing addresses left over from previous run
			 * and they don't exist, don't report an error */
			if (force)
				netlink_error_ignore = ENODEV;

			if (netlink_ipaddress(ip_addr, cmd) > 0) {
				ip_addr->set = (cmd == IPADDRESS_ADD);
				changed_entries = true;
			}
			else
				ip_addr->set = false;
		}
	}

	return changed_entries;
}

/* IP address dump/allocation */
void
free_ipaddress(ip_address_t *ip_addr)
{
	FREE_PTR(ip_addr->label);
	list_del_init(&ip_addr->e_list);
	FREE(ip_addr);
}

void
free_ipaddress_list(list_head_t *l)
{
	ip_address_t *ip_addr, *ip_addr_tmp;

	list_for_each_entry_safe(ip_addr, ip_addr_tmp, l, e_list)
		free_ipaddress(ip_addr);
}

void
format_ipaddress(const ip_address_t *ip_addr, char *buf, size_t buf_len)
{
	char peer[INET6_ADDRSTRLEN + 4];	/* allow for subnet */
	char *buf_p = buf;
	char *buf_end = buf + buf_len;

	buf_p += snprintf(buf_p, buf_end - buf_p, "%s", ipaddresstos(NULL, ip_addr));
	if (!IP_IS6(ip_addr) && ip_addr->u.sin.sin_brd.s_addr) {
		buf_p += snprintf(buf_p, buf_end - buf_p, " brd %s",
			 inet_ntop2(ip_addr->u.sin.sin_brd.s_addr));
	}
	buf_p += snprintf(buf_p, buf_end - buf_p, " dev %s", IF_NAME(ip_addr->ifp));
#ifdef _HAVE_VRRP_VMAC_
	if (ip_addr->ifp != ip_addr->ifp->base_ifp)
		buf_p += snprintf(buf_p, buf_end - buf_p, "@%s", ip_addr->ifp->base_ifp->ifname);
	if (ip_addr->use_vmac)
		buf_p += snprintf(buf_p, buf_end - buf_p, "%s" , " use_vmac");
#endif
	buf_p += snprintf(buf_p, buf_end - buf_p, " scope %s"
			       , get_rttables_scope(ip_addr->ifa.ifa_scope));
	if (ip_addr->label)
		buf_p += snprintf(buf_p, buf_end - buf_p, " label %s", ip_addr->label);
	if (ip_addr->have_peer) {
		inet_ntop(ip_addr->ifa.ifa_family, &ip_addr->peer, peer, sizeof(peer));
		buf_p += snprintf(buf_p, buf_end - buf_p, " peer %s/%d"
				       , peer, ip_addr->ifa.ifa_prefixlen);
	}
	if (ip_addr->flags & IFA_F_HOMEADDRESS)
		buf_p += snprintf(buf_p, buf_end - buf_p, " home");
	if (ip_addr->flagmask & IFA_F_NODAD)
		buf_p += snprintf(buf_p, buf_end - buf_p, " -nodad");
#ifdef IFA_F_MANAGETEMPADDR		/* Linux 3.14 */
	if (ip_addr->flags & IFA_F_MANAGETEMPADDR)
		buf_p += snprintf(buf_p, buf_end - buf_p, " mngtmpaddr");
#endif
#ifdef IFA_F_NOPREFIXROUTE		/* Linux 3.14 */
	if (ip_addr->flags & IFA_F_NOPREFIXROUTE)
		buf_p += snprintf(buf_p, buf_end - buf_p, " noprefixroute");
#endif
#ifdef IFA_F_MCAUTOJOIN			/* Linux 4.1 */
	if (ip_addr->flags & IFA_F_MCAUTOJOIN)
		buf_p += snprintf(buf_p, buf_end - buf_p, " autojoin");
#endif
	if (ip_addr->dont_track)
		buf_p += snprintf(buf_p, buf_end - buf_p, "%s", " no_track");

	if (ip_addr->track_group)
		buf_p += snprintf(buf_p, buf_end - buf_p, " track_group %s", ip_addr->track_group->gname);

	if (IP_IS6(ip_addr)) {
		if (ip_addr->preferred_lft == 0)
			buf_p += snprintf(buf_p, buf_end - buf_p, " deprecated");
		else if (ip_addr->preferred_lft == INFINITY_LIFE_TIME)
			buf_p += snprintf(buf_p, buf_end - buf_p, " preferred_lft forever");
		else
			buf_p += snprintf(buf_p, buf_end - buf_p, " preferred_lft %" PRIu32, ip_addr->preferred_lft);
	}

	if (ip_addr->set)
		buf_p += snprintf(buf_p, buf_end - buf_p, " set");
#ifdef _WITH_IPTABLES_
	if (ip_addr->iptable_rule_set)
		buf_p += snprintf(buf_p, buf_end - buf_p, " iptable_set");
#endif
#ifdef _WITH_NFTABLES_
	if (ip_addr->nftable_rule_set)
		buf_p += snprintf(buf_p, buf_end - buf_p, " nftable_set");
#endif
}

void
dump_ipaddress(FILE *fp, const ip_address_t *ip_addr)
{
	char buf[256];

	format_ipaddress(ip_addr, buf, sizeof(buf));

	conf_write(fp, "     %s", buf);
}

void
dump_ipaddress_list(FILE *fp, const list_head_t *l)
{
	ip_address_t *ip_addr;

	list_for_each_entry(ip_addr, l, e_list)
		dump_ipaddress(fp, ip_addr);
}

ip_address_t *
parse_ipaddress(ip_address_t *ip_addr, const char *str, bool allow_subnet_mask)
{
	ip_address_t *new = ip_addr;
	void *addr;
	const char *p;
	unsigned prefixlen;
	const char *str_dup = NULL;

	/* No ip address, allocate a brand new one */
	if (!new)
		PMALLOC(new);

	/* Parse ip address */
	new->ifa.ifa_family = (strchr(str, ':')) ? AF_INET6 : AF_INET;
	new->ifa.ifa_prefixlen = (IP_IS6(new)) ? 128 : 32;

	if (allow_subnet_mask)
		p = strchr(str, '/');
	else
		p = NULL;

	if (p) {
		if (!read_unsigned(p + 1, &prefixlen, 0, new->ifa.ifa_prefixlen, true))
			report_config_error(CONFIG_GENERAL_ERROR, "Invalid address prefix len %s for address %s - using %d", p + 1, str, new->ifa.ifa_prefixlen);
		else
			new->ifa.ifa_prefixlen = prefixlen;

		str_dup = STRNDUP(str, p - str);
	}

	addr = (IP_IS6(new)) ? (void *) &new->u.sin6_addr :
			       (void *) &new->u.sin.sin_addr;
	if (!inet_pton(IP_FAMILY(new), str_dup ? str_dup : str, addr)) {
		report_config_error(CONFIG_GENERAL_ERROR, "VRRP parsed invalid IP %s. skipping IP...", str);
		if (!ip_addr)
			FREE(new);
		new = NULL;
	}

	/* Release dup'd string */
	if (str_dup)
		FREE_CONST(str_dup);

	return new;
}

ip_address_t *
parse_route(const char *str)
{
	ip_address_t *new;

	PMALLOC(new);

	/* Handle the specials */
	if (!strcmp(str, "default") || !strcmp(str, "any") || !strcmp(str, "all")) {
		new->ifa.ifa_family = AF_UNSPEC;
		return new;
	}

	/* Maintained for backward compatibility v2.0.7 and earlier */
	if (!strcmp(str, "default6")) {
		log_message(LOG_INFO, "'default6' is deprecated - please replace with 'inet6 default'");
		new->ifa.ifa_family = AF_INET6;
		return new;
	}

	if (!parse_ipaddress(new, str, true)) {
		FREE(new);
		return NULL;
	}

	return new;
}

void
alloc_ipaddress(list_head_t *ip_list, const vector_t *strvec, bool static_addr)
{
/* The way this works is slightly strange.
 *
 * We don't set the interface for the address unless dev DEVNAME is specified,
 * in case a VMAC is added later. When the complete configuration is checked,
 * if the ifindex is 0, then it will be set to the interface of the
 * vrrp_instance (VMAC or physical interface).
 */
	ip_address_t *new;
	interface_t *ifp_local;
	const char *str;
	unsigned int i = 0, addr_idx = 0;
	uint8_t scope;
	bool param_avail;
	bool param_missing = false;
	const char *param;
	ip_address_t peer = { .ifa.ifa_family = AF_UNSPEC };
	int brd_len = 0;
	uint32_t mask;
	bool have_broadcast = false;
	unsigned preferred_lft;
	bool preferred_lft_set = false;

	PMALLOC(new);
	if (!new) {
		log_message(LOG_INFO, "Unable to allocate new ip_address");
		return;
	}
	INIT_LIST_HEAD(&new->e_list);

	/* We expect the address first */
	if (!parse_ipaddress(new, strvec_slot(strvec, 0), true)) {
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
				report_config_error(CONFIG_GENERAL_ERROR, "Cannot specify ipaddress device more than once for %s", strvec_slot(strvec, addr_idx));
				FREE(new);
				return;
			}
			if (!(ifp_local = if_get_by_ifname(strvec_slot(strvec, ++i), IF_CREATE_IF_DYNAMIC))) {
				report_config_error(CONFIG_GENERAL_ERROR, "WARNING - interface %s for ip address %s doesn't exist",
						strvec_slot(strvec, i), strvec_slot(strvec, addr_idx));
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
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid scope '%s' specified for %s - ignoring", strvec_slot(strvec,i), strvec_slot(strvec, addr_idx));
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
						    , strvec_slot(strvec, i), strvec_slot(strvec, addr_idx));
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
						      "skipping VIP...", strvec_slot(strvec, i));
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
				report_config_error(CONFIG_GENERAL_ERROR, "Peer %s - another peer has already been specified", strvec_slot(strvec, i));
				continue;
			}

			if (!parse_ipaddress(&peer, strvec_slot(strvec,i), false))
				report_config_error(CONFIG_GENERAL_ERROR, "Invalid peer address %s", strvec_slot(strvec, i));
			else if (peer.ifa.ifa_family != new->ifa.ifa_family)
				report_config_error(CONFIG_GENERAL_ERROR, "Peer address %s does not match address family", strvec_slot(strvec, i));
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
		} else if (!strcmp(str, "home")) {
			new->flags |= IFA_F_HOMEADDRESS;
			new->flagmask |= IFA_F_HOMEADDRESS;
		} else if (!strcmp(str, "-nodad")) {
			new->flagmask |= IFA_F_NODAD;
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
		} else if (!strcmp(str, "preferred_lft")) {
			if (!param_avail) {
				param_missing = true;
				break;
			}

			i++;
			if (!strcmp(strvec_slot(strvec, i), "forever")) {
				new->preferred_lft = INFINITY_LIFE_TIME;
				preferred_lft_set = true;
			} else if (read_unsigned_strvec(strvec, i, &preferred_lft, 0, UINT32_MAX, true)) {
				new->preferred_lft = (uint32_t)preferred_lft;
				preferred_lft_set = true;
			} else
				report_config_error(CONFIG_GENERAL_ERROR, "preferred_lft %s is invalid", strvec_slot(strvec, i));
		} else if (static_addr && !strcmp(str, "track_group")) {
			if (!param_avail) {
				param_missing = true;
				break;
			}
			i++;
			if (new->track_group) {
				report_config_error(CONFIG_GENERAL_ERROR, "track_group %s is a duplicate", strvec_slot(strvec, i));
				break;
			}
			if (!(new->track_group = static_track_group_find(strvec_slot(strvec, i))))
				report_config_error(CONFIG_GENERAL_ERROR, "track_group %s not found", strvec_slot(strvec, i));
		} else if (!static_addr && !strcmp(str, "use_vmac")) {
			new->use_vmac = true;
		} else
			report_config_error(CONFIG_GENERAL_ERROR, "Unknown configuration entry '%s' for ip address - ignoring", str);
		i++;
	}

	/* Check if there was a missing parameter for a keyword */
	if (param_missing) {
		report_config_error(CONFIG_GENERAL_ERROR, "No %s parameter specified for %s", str, strvec_slot(strvec, addr_idx));
		FREE(new);
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

	if (static_addr && !new->ifp) {
		new->ifp = get_default_if();
		if (!new->ifp) {
			report_config_error(CONFIG_FATAL, "Static address %s requires either an interface"
							  " or default interface must exist"
							, strvec_slot(strvec, addr_idx));
			FREE(new);
			return;
		}
	}

	if (new->ifa.ifa_family == AF_INET6) {
		if (new->ifa.ifa_scope) {
			report_config_error(CONFIG_GENERAL_ERROR, "Cannot specify scope for IPv6 addresses (%s) - ignoring scope", strvec_slot(strvec, addr_idx));
			new->ifa.ifa_scope = 0;
		}
		if (new->label) {
			report_config_error(CONFIG_GENERAL_ERROR, "Cannot specify label for IPv6 addresses (%s) - ignoring label", strvec_slot(strvec, addr_idx));
			FREE(new->label);
			new->label = NULL;
		}

		if (!preferred_lft_set) {
			/* Set the old defaults if preferred_lft not set */
			if (new->ifa.ifa_prefixlen == 128)
				new->preferred_lft = 0;
			else
				new->preferred_lft = INFINITY_LIFE_TIME;
		}
	}

	if (new->track_group && !new->ifp) {
		report_config_error(CONFIG_GENERAL_ERROR, "Static route cannot have track_group if interface not specified");
		new->track_group = NULL;
	}

#if 0
	if (!new->ifp && new->use_vmac) {
		report_config_error(CONFIG_GENERAL_ERROR, "use_vmac for a address requires an interface");
		new->use_vmac = false;
	}
#endif

	list_add_tail(&new->e_list, ip_list);
}

/* Find an address in a list */
static bool
address_exist(vrrp_t *vrrp, ip_address_t *ip_addr)
{
	ip_address_t *ipaddr;
	char addr_str[INET6_ADDRSTRLEN];
	void *addr;
	list_head_t *vip_list;

	/* If the following check isn't made, we get lots of compiler warnings */
	if (!ip_addr)
		return true;

	for (vip_list = &vrrp->vip; vip_list; vip_list = vip_list == &vrrp->vip ? &vrrp->evip : NULL ) {
		list_for_each_entry(ipaddr, vip_list, e_list) {
			if (!compare_ipaddress(ipaddr, ip_addr)) {
				ipaddr->set = ip_addr->set;
#ifdef _WITH_IPTABLES_
				ipaddr->iptable_rule_set = ip_addr->iptable_rule_set;
#endif
#ifdef _WITH_NFTABLES_
				ipaddr->nftable_rule_set = ip_addr->nftable_rule_set;
#endif
				ipaddr->ifa.ifa_index = ip_addr->ifa.ifa_index;
				return true;
			}
		}
	}

	addr = (IP_IS6(ip_addr)) ? (void *) &ip_addr->u.sin6_addr :
				  (void *) &ip_addr->u.sin.sin_addr;
	inet_ntop(IP_FAMILY(ip_addr), addr, addr_str, INET6_ADDRSTRLEN);

	log_message(LOG_INFO, "(%s) ip address %s/%d dev %s, no longer exist"
			    , vrrp->iname
			    , addr_str
			    , ip_addr->ifa.ifa_prefixlen
			    , ip_addr->ifp->ifname);

	return false;
}

/* Clear diff addresses */
void
get_diff_address(vrrp_t *old, vrrp_t *new, list_head_t *old_addr)
{
	ip_address_t *ip_addr, *ip_addr_tmp;
	list_head_t *vip_list;

	/* No addresses in previous conf */
	if (list_empty(&old->vip) && list_empty(&old->evip))
		return;

	for (vip_list = &old->vip; vip_list; vip_list = vip_list == &old->vip ? &old->evip : NULL ) {
		list_for_each_entry_safe(ip_addr, ip_addr_tmp, vip_list, e_list) {
			if (ip_addr->set && !address_exist(new, ip_addr)) {
				list_del_init(&ip_addr->e_list);
				list_add_tail(&ip_addr->e_list, old_addr);
			}
		}
	}
}

/* Clear diff addresses */
void
clear_address_list(list_head_t *delete_addr,
#ifndef _WITH_FIREWALL_
				     __attribute__((unused))
#endif
							     bool remove_from_firewall)
{
	/* No addresses to delete */
	if (list_empty(delete_addr))
		return;

	/* All addresses removed */
	netlink_iplist(delete_addr, IPADDRESS_DEL, false);
#ifdef _WITH_FIREWALL_
	if (remove_from_firewall)
		firewall_remove_rule_to_iplist(delete_addr);
#endif
}

/* Clear static ip address */
void
clear_diff_static_addresses(void)
{
	LIST_HEAD_INITIALIZE(remove_addr);
	vrrp_t old = {};
	vrrp_t new = {};

	list_copy(&old.vip, &old_vrrp_data->static_addresses);
	list_copy(&new.vip, &vrrp_data->static_addresses);
	INIT_LIST_HEAD(&old.evip);
	INIT_LIST_HEAD(&new.evip);

	get_diff_address(&old, &new, &remove_addr);

	list_copy(&old_vrrp_data->static_addresses, &old.vip);
	list_copy(&vrrp_data->static_addresses, &new.vip);

	clear_address_list(&remove_addr, false);
	free_ipaddress_list(&remove_addr);
}

void reinstate_static_address(ip_address_t *ip_addr)
{
	char buf[256];

	ip_addr->set = (netlink_ipaddress(ip_addr, IPADDRESS_ADD) > 0);
	format_ipaddress(ip_addr, buf, sizeof(buf));
	log_message(LOG_INFO, "Restoring deleted static address %s", buf);
}
