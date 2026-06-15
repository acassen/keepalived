# Release 2.3.0 `21th May 2024`

This release brings improvements and fix some minor issues reported. Yearly release.

## New

- **vrrp**: For use_vmac and use_ipvlan, copy the group from the base interface. It is useful in many instances to set up firewall rules based on interface groups so that sets of interfaces may be aggregated by group and matched with a single rule rather than by listing them all. Prior to this change, when use_vmac or use_ipvlan is used, new interfaces are created with the default group, which breaks this ability. Further complicating the issue is that nftables resolves interface names to ifindex at load time. This is problematic with keepalived's interface creation, which usually comes after the firewall loading, forcing the use of iifname, oifname instead (similar to iptables -i, -o). By copying the group value, such firewall rules can continue to work regardless of the use_vmac or use_ipvlan settings, since packets may now arrive on, or be routed out from, the new interfaces.

- **vrrp**: Addd name option for use_vmac and use_ipvlan. This is to allow an interface name of "bridge" etc.

- **vrrp**: Add interface group option for VMACs and ipvlans. Now that the interface group of a VMAC or ipvlan is set, by default, to match its parent interface, this option now allows the group of the VMAC or ipvlan to be explicitly configured and set.

- **ipvs**: Add snmp_rs_stats_update_interval. This compliments snmp_vs_stats_update_interval, and also real server stats are now only fetched from the kernel when there is an SNMP request for them; i.e. VS stats and RS stats are updated separately.

- **conf**: Add global keyword use_symlink_paths. By default keepalived resolves all symbolic links in path names of scripts to the real path. This commit adds the use_symlink_paths option to maintain the symlinks in paths, so that users can update symlinks in order to update the scripts being called.

- **doc**: Add documentation for MH and TWOS schedulers.

- **global**: Add per process gprof profiling.

- **systemd**: Add KEEPALIVED_OPTION for non-root service file.

- **systemd**: Add comment in non-root service file for old systemds.

## Improvements

- **vrrp**: Remove extraneous log message for netlink interface message.

- **vrrp**: Allow DBus to work with VRRP instances without configured interface. keepalived uses "none" for the interface in the DBus path if a VRRP instance has no configured interface. However, it was not checking explicitly for "none" when a query was received. This commit now adds a specific check.

- **vrrp**: Allow specification of string used by DBus for no interface.

- **vrrp**: check prefix length when checking if deleted address is a VIP. It is possible, for example, to configure both 10.1.0.3/32 and 10.1.0.3/24 on the same interface. When checking whether an address deleted from an interface is one of our VIPs, we need to also check the prefix length.

- **vrrp**: Set sysctl arp_ignore to 1 on IPv6 VMACs. Setting arp_ignore to 1 ensures that the VMAC interface does not respond to ARP requests for IPv4 addresses not configured on the VMAC.

- **vrrp**: Go to fault state if fail to add IPv6 link-local address to VMAC. If an IPv6 VRRP instance uses a VMAC, but adding a link-local address to the interface fails, then the vrrp instance now transitions to fault state, just as happens if the link-local address is removed after it has been added.

- **vrrp**: Don't send IPv6 advert from interface with no address. If an interface has no IPv6 address, no advert can be sent. Rather that logging an error when the send fails, simply don't send the advert.

- **vrrp**: Check interface for static routes if deleted. vrrp: Check interface for static routes if deleted route_is_ours() checked the outgoing interface for virtual routes but not for static routes. This commit now adds checking of the outgoing interface for static routes, and now moves the code to compare routes into a separate function used for both virtual and static routes.

- **vrrp**: remove logging on status output. A message is output to the log each time the status is queried. This is not necessary and can therefore be omitted.

- **vrrp**: Use addattr32() for setting link group. Set link group for ipvlan interfaces, just like for VMACs.

- **ipvs**: ping check extension. use consistent ICMP id and fix sequence number By keeping the sockets used for pings open, the ICMP id field now remains the same for each echo request. The sequence number is now per ping check, and is now sent in big endian order.

- **ipvs**: Reduce logging of activating health checkers. Don't log activating checkers after a reload if they are already active.

- **ipvs**: Remove checkers_queue. A configuration with 2277 virtual servers, with a total of 37205 real servers with each real server having one checker was taking 132 seconds to reload. This commit reduces the reload time to 0.24 seconds, a reduction of 99.8%! The problem was due to every real server iterating through all checkers, 37205 * 37205 = 1,384,212,025 iterations, not only once but several times. The code now maintains a list of checkers for each real server. The disadvantage of this is that to iterate through all checkers requires iterating through all virtual servers, and all their real servers and then for each real server the list of checkers. If there are relatively few checkers compared to real servers, this will take longer than using the checkers_queue, but using a queue per real server is still fast, and the only time the code iterates through all the checkers is at startup/reload, other than dumping the configuration.

- **ipvs**: don't call protocol_to_index() unless using auto fwmarks. protocol_to_index() must only be called when there is an index. This is when the virtual server uses a virtual server group that is using auto fwmarks.

- **ipvs**: add set and alive status for sorry servers in keepalived_check.data.

- **ipvs**: Reinstate non-failed real servers if remove sorry server. When there is no sorry server, the quorum is not used, and real servers are only removed if a checker fails. On the other hand if there is a sorry server, if the number of alive real servers falls below the quorum, all non-failed real servers are removed when the sorry server is added. If the sorry server is remomed from the configuration, non-failed real servers need to be reinstated.

- **ipvs**: don't remove sorry server if inhibit added but server is alive.

- **ipvs**: inhibit extensions: If inhibit is changed on a failed real server, add/remove it. If inhibit is added to inactive sorry server set weight 0. If inhibit cleared for inactive sorry server, clear s_svr->set.

- **ipvs**: Add snmp_vs_stats_update_interval for updating SNMP stats. The timer for updating VS and RS stats for SNMP was hard coded to 5 seconds. This commit still deffaults to 5 seconds but allows the timer to be configured.

- **ipvs**: Misc SNMP updates and extensions. Don't duplicate storage of 32 bit SNMP stats. Use correct variable for returning 64 bit stats for SNMP. Add counter64 options for 64 bit SNMP stats. Use SNMP variable3/4/7 instead of variable8 where appropriate. streamline SNMP real server code when no sorry server. Merge several SNMP functions that were doing nearly the same thing. Streamline finding VS group entry for SNMP. Streamline finding RS for SNMP. Streamline finding VS for SNMP. set var_len = 0 when returning an error to SNMP. fix building with SNMP support without using netlink interface.

- **systemd**: Change NotifyAccess to be main rather than all for non-root.

- **doc**: Clarify documentation for "weight" in track_process. The default value for weight should be 0, and not 1 as previously stated.

- **doc**: update description for v3_checksum_as_v2.

## Fixes

- **vrrp**: Stop link local VMAC address responging to neighbour solicit. When an IPv6 VRRP instance using  VMAC is in backup state, the link local address configured on the VMAC interface is the same as the link local address on the parent interface of the VMAC. This causes a problem with switches learning the MAC address of the VMAC is now on the backup. This causes packets meant to be sent to the master being sent to the backup. This commit uses nftables/iptables to stop neighbour advertisements for the link local address of the VMAC interface and its parent interface being sent from the VMAC interface.

- **vrrp**: fix global skip_check_adv_addr and strict_mode parsing. skip_check_adv_addr and strict_mode take an option parameter, but keepalived wasn't parsing it, and assumed it was set on/true/yes.

- **vrrp**: work around missing promiscuous netlink notifications. If the base interface does not implement IFF_UNICAST_FLT, for example it is a bridge interface, no netlink notification is sent by the kernel when promiscuity is set on the base interface. The promiscuous state of the base interface is correct in the kernel but it is in incorrect in daemons that listen to the interface netlink messages (eg. DPDK). The issue is still there in kernel 6.4.6. Force a notification by re-setting IFLA_GROUP for the base interface.

- **vrrp**: Fix specifying netlink_notify_msg for VMAC when name set. Trying to specify a VMAC name as well as netlink_notify_msg did not work for use_vmac.

- **ipvs**: fix issue in reload process when using virtual server groups. issue: when using virtual server groups, remove vs entry in configure file and then do reload, vs entry can not be removed. And add vs entry in configure file and the do reload, rs with 0 port will be set. fix: in reload process do the same action with ipvs_group_cmd. set rs port with vs port and update live state

- **ipvs**: add/remove sorry server of group server when reload. issue: when using virtual server groups, if all rs down and sorry server up, at this time remove/add vs entry in configure file and then do reload, vs entry can not be removed. fix: add/remove sorry server same as normal rs when reload server groups

- **check**: if lost misc check child register checker agagin. issue: misc check_child_thread timeout and remove child_pid form rb_data, timeout callback of check_child_thread is not be called, if at this time misc script done and exit, and child termination will do nothing because child_pid was remove form rb_data. in this case timeou callback will not register checker again, the checker will lost. fix: if lost misc check child register checker again

- **lib**: Stop setting MAGIC_PRESERVE_ATIME flag. On RedHat systems setting MAGIC_PRESERVE_ATIME caused SELinux errors.

- **core**: make startup/shutdown scripts work when not using --dont-fork. check_start_stop_script_secure() checks that the parent process has not changed while it is doing its checks, so we need to set the pid of the parent process (main_pid) before calling the function. There is a further complication that called getppid() too soon after a fork() with the parent process exiting after the fork means that we don't get the pid of the new parent, so we need to loop until getppid() returns a diffweent pid.

- **core**: initialise script structure in start_validate_reload_conf_child(). Due to the path field not being set to NULL, it was attempting to exec a random string when reload_check_config was configured.

- **systemd**: Fix snmp option in non-root service file.
