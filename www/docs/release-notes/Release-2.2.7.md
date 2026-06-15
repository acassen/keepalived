# Release 2.2.7 `16th January 2022`

This release brings lots of improvements and fix some minor issues reported. It add some new VRRP features as well. Stability has been even more extended.

## New

- **ipvs**: Add support to twos scheduler.

- **vrrp**: Add vrf option for unicast without specifying an interface.

- **vrrp**: Add option unicast_fault_no_peer. Previously if unicast_src_ip (or any other unicast option) was specified, but no unicast peers were configured, then the VRRP instance would operate in multicast mode. A user has identified that, due to automatic configuration generation, they could have a configuration that should operate in unicast mode, but that no unicast peers were configured. In this case, they did not want the VRRP instance to revert to multicast mode. In order to maintain backward compatibility, keepalived can't simply change to not allowing no unicast peers. Instead, this commit adds the configuration option "unicast_fault_no_peer", which if specified causes the VRRP instance to go to fault state if no unicast peers are configured.

- **vrrp**: Allow specification of multicast address to be used.

- **vrrp**: Add vrf option to static and vrrp routes.

- **vrrp**: Add option to resend vrrp states on fifos after reload. Since keepalived restarts FIFOs scripts it is managing when a reload occurs, it can be helpful to send the VRRP instance and group states after a reload. This commit adds option fifo_write_vrrp_states_on_reload to do that, and it means that what is written to the FIFOs with default configuration does not change.

- **vrrp**: Allow duplication of VRIDs on an interface with unicast peers. If two VRRP instances are using unicast peers and there is no overlap of unicast peers between the vrrp instances, then the vrrp instances can use the same VRIDs.

- **global**: Don't assume running as user root.

- **systemd**: Add keepalived-non-root.service systemd service file. keepalived-non-root.service allows keepalived to be run as a non root user, but with specific added capabilities to allow all the functionality that keepalived needs.

## Improvements

- **vrrp**: Stop receiving any data on garp and ndisc sockets. This is a send-only channel.

- **vrrp**: Open gratuitous ARP socket as an ARP socket rather than RARP. Now that the receiving of packets on the garp socket has been stopped, we can open the socket with the correct type of binding, and we won't have a queue of received messages build up.

- **vrrp**: Extend cBPF filtering code to support standard definition.

- **vrrp**: Optimise nftables configuration to limit some rules to macvlans. If we are moving messages that have been generated on a macvlan, we nftables rules can be optimised to restrict them to macvlan interfaces.

- **vrrp**: Drop ICMPV6 Router Solicitation messages from vmac interfaces. When we create a vmac interface, a short time afterwards the kernel sends a router solicition message with the source MAC address of the vmac interface. The problem is that this will upset snooping switches if the VRRP instance is in backup state. Furthermore, we can't simply move the packet onto the underlying interface since the ICMPV6 payload also contains the MAC address of the vmac interface. We can't just change the MAC address in the ICMPV6 message, since there is also a checksum which would need to be recalculated. The only solution at the moment is to drop the packet. This shouldn't be a problem since the underlying interface should have sent a Router solicitation message when it came up.

- **vrrp**: Add option to specify MAC address for VMACs.

- **vrrp**: Don't lose some configuration faults. The following errors were being detected in vrrp_complete_instance() and the VRRP instance was then supposed to be put into fault state since it couldn't operate. However, the need to go to fault state was subsequently being lost. The configuration errors that were being lost were: (a) Configuring use of a VMAC on a non Ethernet interface (b) Attempting to use multicast on an interface that doesn't support it (c) Using an ipvlan without a source IP address (d) ipvlan address family not matching VRRP isntance's (e) VRID conflicts on an interface which could be deleted an recreated on a different interface (f) An interface specified for a VIP is the same as the VRRP instance's VMAC or another VRRP instance's VMAC. This improvement ensures that the VRRP instance will be put into, and remain in, fault state, since it cannot successfully operate. As can be seen from the list of circumstances above, they were very unlikely to occur, but were possible.

- **vrrp**: Bind IPv6 socket to multicast address. Previously IPv6 sockets were being bound to the ::1 address, since trying to bind to the multicast address was failing. The reason for failing has now been discovered to be that the scope_id needed to be set (i.e. the interface index), since the multicast addresses that we use are link-local multicast addresses. This improvement now sets the scope_id, so the socket can successfully be bound to the multicast address.

- **vrrp**: Set IPV6_MULTICAST_ALL on IPv6 sockets if available.

- **vrrp**: Some SNMP extension and improvements: - Correct FastOpenNoCookie and L3Mdev variable types - Don't write multicast address to SNMP when using unicast. - Don't write unconfigured LVS sync daemon address to SNMP. - Define and use SNMP_TruthValue. - Define and use SNMP_InetAddressType. - Correct reporting accept mode for VRRPv3 SNMP.

- **vrrp**: Misc DBus improvements (Opening, logging, data_dir, policy, ...)

- **vrrp**: Handle VMAC's interface changing on reload properly.

- **vrrp**: If accept traffic for VIPs changes on reload, update firewall.

- **vrrp**: Stop going to backup if reload IPv6 and change vmac_xmit_base.

- **vrrp**: Add add/prepend/append options to static and virtual routes. The kernel by default prepends routes, whereas the ip (iproute2) utility be default adds routes (adding a route does not allow duplicates whereas appending or prepending does). keepalived previously has not set the flags relating to this, and so has always prepended routes. This means that duplicate routes could be created.

- **lib**: Update Red Black tree code to Linux 5.15-rc4.

- **script**: Extend sample_notify_fifo.sh.

- **doc**: Misc documentation updates.

- **docker**: Upate docker file.

- **init**: Init handling extensions. Make parent process exit with meaningful status on error. Ensure systemd is not notified of successful start if failed. fix building without systemd notify suport.

- **bfd**: handle unexpected closure of pipe to checker and vrrp processes. If the parent process abnormally terminates and then the BFD process terminates due to PDEATHSIG before the vrrp or checker processes terminate, the vrrp and checker processes can get a read error on the pipes used to communicate with the BFD process.

- **bfd**: make BFD work when IPv6 disabled on system.

## Fixes

- **lib**: Fix calculating CLOCK_REALTIME and CLOCK_MONOTONIC offsets.

- **lib**: scheduler: Handle cancelling timer thread on ready queue. The timer thread on the ready queue, if cancelled, was corrupting the read list_head, since it assumed it was on a red black tree.

- **snap**: Fix building snaps.

- **ipvs**: Fix building with glibc prior to v2.19 (released 2014).

- **bfd**: Handle interface down/address missing when keepalived starts. This resolves a segfault, and also makes bfd retry once per minute to create send socket if it cannot do so due to no address to bind to on an interface.

- **vrrp**: Fix unicast with interface in a VRF domain.

- **vrrp**: Fix moving excess VIPs to eVIPs, by properly handling vip_cnt.

- **vrrp**: Fix configured IPv6 multicast addresses with VMACs. Using different multicast addresses with IPv6 on the same interface without using VMACs is only supported if the kernel supports IPV6_MULTICAST_ALL (from Linux v4.20).

- **vrrp**: Fix checking for unicast with VMAC/ipvlan and no peers.

- **vrrp**: Fix checking if have unicast ppers if unicast_ttl specified.

- **vrrp**: Don't segfault if duplicate VMAC name, but ignore second name.

- **vrrp**: Don't delete and recreate VMAC on reload if only VRID has changed. There seems to be an issue deleting and then immediately recreating a VMAC on the same interface. This commit therefore simply changes the MAC address if the only change is the VRID.

- **vrrp**: Fix nftables config if VMAC interface changed on reload.

- **vrrp**: Don't segfault if don't have permission for ARP/NDISC socket.

- **vrrp**: Fix IPv6 with vmac_xmit_base.

- **vrrp**: fix disabling vmac-xmit-base with VRRPv3 IPv6 use_vmac.

- **vrrp**: Fix specifying user/group for vrrp_scripts.
