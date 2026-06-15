# Release 2.1.0 `13th June 2020`

The focus for this release has been put on making it even more robust. We are targetting carrier-grade software quality.

## New

- **core**: `scheduled reload` This allows several keepalived instances to all reload simultaneously which is useful if their configurations are changing in a way that is incompatible with their previous configuration - e.g. adding a VIP. The reload time can be specified as either local time or UTC.

- **core**: `dynamicallly incrementing process priority` If keepalived is delayed being scheduled after a timer expires, this could cause delays in adverts being sent, or other issues. This would, in practice, only occur on a very heavily loaded system. This feature makes keepalived compare the time when epoll_wait() returns to the time when it should have been scheduled due to the soonest expiring timer. If keepalived is more than 1 second late being scheduled to run, it will transition to realtime scheduling, if not already using that, or if it is will increase the realtime priority by 1 up to the system limit. This approach should ensure that keepalived elevates itself to sufficient priority so that it isn't delayed unduly in being scheduled. In order to protect the system from keepalived, keepalived sets RLIMIT_RTTIME to limits keepalived's overall CPU usage.

- **core**: `max_auto_priority` This option sets the maximum realtime priority that keepalived can elevate itself to. A value to 0 disables keepalived setting ifself to use realtime scheduling.

- **core**: `min_auto_priority_delay` This specifies the minimum rescheduling delay before the process priority will auto-increment.

- **core**: Add signal (RTMAX-1) to dump and clear stats

- **core**: `startup and shutdown scripts` This feature offers to run a script when keepalived starts up, and another script when keepalived shuts down. The original motivation for this was that keepalived can setup IPVS configuration that uses firewall marks, but it had no ability to add the iptables/nftables configuration to set the fwmarks. Running a script a startup allows the iptables/nftables configuration to be added, and the shutdown script can remove the configuration. This feature can also be used to setup the necessary iptables entries if using vrrp_iptables, or to set interface configuration settings. In fact, these can do anything that a script or program can do.

- **core**: Add configure option to disable macvlans/vmacs.

- **parser**: `~SEQx` This feature allow sequence option for hex formatting.

- **parser**: `~LST` This feature is similar to ~SEQ, except that the values to substitute into the variable (or variables) are listed in the ~LST specification.

- **vrrp**: Add sync group fault counts to keepalived.data

- **vrrp**: Add option to omit vrrp instance interface with unicast addresses. Not specifying the interface allows the system to decide the interface to send an advert on based on the destination address, and adverts can be received on any interface. This is needed for asymetric routing, and also dynamic routing.

- **vrrp**: Add option to specify TTL/hop_limit for unicast peers and to check it. This feature allows specifying the TTL/hop limit to use when sending to unicast peers, and allows a minimum and maximum TTL/hop limit to be specified against each unicast peer so that the TTL/hop limit can be checked to be within the specified range when an advert is received. This does not alter the TTL/hop limit used when multicasting, which remains at 255.

- **vrrp**: `notify_delete` If a VRRP instance is removed on a reload, keepalived used to send FAULT to all the notify mechanisms. This feature allows differentiation betwen fault state and deleted. Since previously FAULT was sent, that needs to remain the default, but we now have an option, notify_deleted, that causes DELETED notifies to be sent instead of FAULT when vrrp instances are deleted on a reload.

- **ipvs**: `UDP_CHECK` It performs an UDP bind_connect to remote service and handle ICMP response to add or remove service (Network Unreachable, Host Unreachable, Port Unreachable, ...). It supports IPv4 and IPv6.

- **ipvs**: `PING_CHECK` It performs an ICMP ECHO_REQUEST and handle ICMP ECHO_REPLY to add or remove service. It supports IPv4 and IPv6.

- **ipvs**: `FILE_CHECK` This new checker reads and monitors the contents of a file.

- **ipvs**: Allow mixed IPv4/6 virtual server groups where all RS are tunnelled. If all real and sorry servers of a virtual server are tunnelled, then the address family of the virtual server can be either IPv4 or IPv6. This means that it makes sense to have a virtual server group with both IPv4 and IPv6 addresses, provided that all the virtual servers using it meet the requirement of all real and sorry servers being tunnelled.

- **ipvs**: `net_namespace_ipvs` This feature allows the IPVS configuration to be in a separate network namespace from the rest of keepalived. When set, the ipvs socket is created in the targetted namespace. It allows to properly split traffic between healthchecks and ipvs (do the healthcheck traffic in one namespace and receive the VIP traffic in a given namespace).

- **ipvs**: On reload, if a new track file is down, make the checkers be failed.

## Improvements

- Remove old list library to use list_head_t instead. All Keepalived code has been revisited to port list to list_head_t. Motivation for this change was to increase code consistency and efficiency. It offers lower memory footprint since additional element allocation is no longer needed. Finally it makes the code more clean and more readable.

- **snmp**: Revisited the SNMP framework to make it more readable. Some code extensions and refactor.

- **vrrp**: `Remove iptables commands support` iptables by default uses library calls to setup the iptables configuration, so there is no point maintaining the option to call iptables commands, which is both very slow due to the way iptables works, and creates an overhead in maintaining the code.

- **vrrp**: Stop using libnftnl deprecated functions.

- **vrrp**: use nftables natively when possible.

- **vrrp**: Ensure GARP messages are sent for sync group members after receiving a lower prio advert.

- **vrrp**: VMAC name sanitize. The kernel does not allow certain characters in an interface name.

- **ipvs**: Set address family of virtual server from virtual server group. If all a virtual server's real servers are tunnelled, that gives no indication of which address family the virtual server is intended for. If the virtual server uses a virtual server group, and that vsg has IPv4 or IPv6 addresses, these can be used to set the address family of the virtual server. If the virtual server group only has fwmarks, and all the real servers are tunnelled, then default to IPv4.

- **ipvs**: Add more checker information to keepalived_check.data.

- **ipvs**: Allow both master and backup IPVS sync daemons to run simultaneously. With load balancing there could be two of more systems handling virtual servers, with either one able to take over from the other. In that case, both systems need to be able to synchronize their IPVS connections to the other, and this necessitates running both a master and a backup sync daemon in each system. Furthermore, there is no need to track a VRRP instance, since if all relevant VRRP instances are in backup mode, no connections will be received by that system and so the master sync daemon will not send and sync updates.

- **parser**: Allow parameters to ~SEQ to be definitions

- **parser**: Update parser to allow { and } on same line in value blocks

- **parser**: Enable ~SEQ to work in value blocks

- manpage updates.

## Fixes

- snap builds. In particular resolve building for s390x.

- Misc Coverity reported issues.

- Some fixes for rlimit_rtime configuration option

- Correctly handle unsupported attempts for changes at reload. The instance name, network namespace and nftables table name cannot be changed when reloading. The code was resetting the change twice, resulting in it not working.

- **vrrp**: Fix interfaces coming up during vrrp_script init phase. If a tracked interface transitioned from down to up while a vrrp_script was running for the first time, the tracking vrrp instances would never come up.

- **vrrp**: Assign correct link local IPv6 address to macvlan moved namespace. When keepalived is configured to use a macvlan on a macvlan that has been moved to a different namespace from its parent interface, it needs to get the IPv6 link local address from the interface that keepalived's macvlan is configured on. In the circumstance above, the created macvlan's base_ifp cannot be set, so the vrrp's configured_ifp must be used.

- **vrrp**: Don't set random fwd method if invalid lvs_method/lb_kind specified for VS.

- **vrrp**: Ensure default forwarding method set for sorry server if not specified.

- **vrrp**: Fix comparing existing macvlans when creating new ones.

- **vrrp**: Fix handling recreated interface when xmitbase is specified

- **vrrp**: Check for minimal conf requirements during vrrp_complete_init.

- **vrrp**: Fix use_vmac with no vmac name specified.

- **ipvs**: When removing a RS due to config error, also remove checkers. If a real server is misconfigured, for example the address family does not match the virtual server, then when the real server is removed from the configuration any checkers used by the real server must also stop referencing the real server.

- **ipvs**: Ensure virtual server persistence params updated after reload.

- **ipvs**: Fix checking of lvs_sync_daemon vrrp instance name.

- **ipvs**: Fix track file checker state when down after reload.

- **snmp**: Fix segfault when checker process terminates with SNMP.

- **snmp**: Fix retrieving SNMP stats now that the netlink socket is kept open.

- **snmp**: Fix malloc/realloc handling for IPVS SNMP.

- **snmp**: Make SNMP work after a reload.

- **snmp**: build: fix out-of-tree builds when SNMP is enabled.
