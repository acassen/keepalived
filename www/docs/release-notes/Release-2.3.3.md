# Release 2.3.3 `30th March 2025`

This release brings improvements and fix some minor issues reported. Keepalived VRRP implementation is now near full RFC compliant. This Realease extends and adds some security provisions for VRRP code. We would like to thank exchange and constructive work done with : **Orange Cyberdefense in Lyon/France** (Geoffrey, if you read these lines, thank you for your time and efforts) to address a VRRP RFC corner case on duplicate address owner handling. This work has done the rise and quickly approved by IETF of the foolowing errata on RFC9568: https://www.rfc-editor.org/errata/eid8298

## New

- **vrrp**: don't allow unicast instance without interface to have a VMAC. If the interface is not configured, we can't know what interface to add the VMAC to.

- **vrrp**: Add setting IP_FREEBIND/IPV6_FREEBIND socket option. This allows creating and configuring unicast sockets before the configured source address is added to the system.

- **core**: add O_CLOEXEC flag to pidfiles.

- **vrrp**: Support logging rate-limiting specified by RFC 9568

- **vrrp**: add option for address owner to drop received VRRP packets. RFC 9568 (and RFC 5798 and RFC 3768) state that an address owner must drop any received VRRP packets. The consequence of this is that if there is more than one VRRP instance configured with priority 255 then they will all be in master state simultaneously. It seems more sensible for such received packets to be processed normally, and all but the VRRP instance with the primary IP address will revert to backup state. RFC 9568 appears to allow more than one instance to have priority 255, since section 8.3.2 was changed from "No more than one router on the link is to be configured with priority 255, especially if preemption is set" (note the contradiction here) to "only a single VRRP Router on the link SHOULD be configured with priority 255" and then descibes the situation if there is more than one such router. keepalived defaults to processing received packets when the local priority is 255, but the option added by this patch allows working in accordance with the RFC, i.e. to drop any received packets.

## Improvements

- **core**: Allow building on very old systems with kernels < 3.15. Open file descriptor locks were introduced in Linux 3.15, so we cannot use that type of locking on systems with older kernels (e.g. CentOS 7, which of course is no longer supported). Since this problem only occurs on kernels no longer supported by keepalived this commit simply removes the file locking, rather than implementing a more comprehensive solution. It is expected that at some point, in order to simplify the code, support for kernels no longer supported by any of the main distros will be removed from keepalived.

- **doc**: add oldest distro versions with their EOL dates and kernel versions.

- **docker**: Install linux-headers pkg to build in Docker.

- **vrrp**: handle checking ip utility version properly with BusyBox.

- **snap**: Misc snap improvements.

- **build**: make default _FORTIFY_SOURCE setting 3. Various distros already use _FORTIFY_SOURCE=3 by default, so we should do so too.

- **vrrp**: check the iproute2 directories exist when read first file

- **vrrp**: create /etc/iproute2 directory if it doesn't exist.

- **vrrp**: Restore priority 255 if duplicate address owner detected. The VRRP RFCs assume that only one device is configured as the address owned for any VRID. keepalived has extended functionality which detects if two (or more) systems are configured as the address owner (this is completely invalid configuration). To avoid multiple systems acting as address owner, and hence all of them remaining in master mode, keepalived will reduce an address owner's priority to 254 if the other device configured as address owner does not go away. This commit restores the priority of a vrrp instance to 255 if it had reduced it to 254 to avoid multiple VRRP instances simultaneously advertising that they are the address owner.

- **vrrp**: Only reduce address owner priority if primary ip address lower. If a VRRP instance is configured as address owner and it detects another device also advertising it is the address owner, only initially reduce our priority if our primary IP address is lower than the other device's primary IP address.

- **vrrp**: if duplicate address owners, reduce priority if other won't. If a VRRP instance is configured as address owner and it detects another device also advertising it is the address owner, we don't reduce our priority if our primary IP address is higher than the other device's primary IP address. However, if the other system, with a lower primary IP address, won't reduce its priority (e.g. it is not a keepalived implementation), then we will reduce our priority after a suitable time.

- **vrrp**: add more helpful log messages if duplicate address owner.

- **vrrp**: log rate-limited message if advert has no VIPs.

- **vrrp**: log rate-limited warning if VRRPv3 advert interval mismatch.

- **vrrp**: it is not an error if VIPs in advert do not match configured. We should accept a VRRP advert if the VIPs in an advert do not match our configuration, but just log a rate-limited warning.

- **vrrp**: update saved master address when receive high priority advert. If we are in master state and receive a higher priority advert, saving the new master address saves checking VIPs twice.

- **vrrp**: include source address in log after receiving a bad advert.

- **vrrp**: check that VIPs are not duplicated.

- **vrrp**: check TTL/HL and unicast source ip even when not checking VIPs. The checking of TTL/HL and unicast source ip was only being done if the VIPs were being checked, whereas they should be checked even if the VIPs are not being checked.

- **vrrp**: change rx_ttl_hop_limit to rx_ttl_hl. The name was confusing since it suggested the value was a limit.

- **vrrp**: identify unicast peer in unicast_peer block configuration errors.

- **vrrp**: detect and reject duplicate unicast_peers in configuration.

- **vrrp**: add logging a change of master when detailed logging enabled.

- **vrrp**: handle a reload with no more startup_delay. During the vrrp_startup_delay time, if keepalived is reloaded with no more startup_delay, the startup_delay is never timed out and all received adverts is discarded. The commit causes the startup_delay timer to be reinstated after a reload with no more startup_delay if the timer has not yet expired.

- **vrrp**: Skip running not idle vrrp scripts. When a vrrp script is to be run (initially or after specified interval), first it is checked if it's in IDLE state. If not a log message is printed informing about skipping run due to script being either running or timed out. However despite not being idle the code continues to run new script process. In heavily loaded systems this caused running multiple instances of vrrp script at the same time. This patch brings back missing return, which was lost during refactoring.

- **codeQL**: update codeQL.yml

- **vrrp**: add checks that interface fault flags not inconsistent. When a fault is added in down_instance() or cleared in try_up_instance() check that the flag that is being modified is not already set or cleared, as appropriate. This check is enabled by configure option --enable-fault-flags-check.

- **vrrp**: use a fault flag if num_track_faults is non zero. It simplifies the code to set a fault flag is num_track_faults is non-zero and clear the flag if num_track_faults is zero.

- **vrrp**: don't attempt to send advert if socket is closed. This avoids an unnecessary log message.

- **vrrp**: don't have multiple tracking objects for a VRRP instance. The code did have separate tracking objects for dynamic and non dynamic tracking objects for a VRRP instance. It also would add an addition dynamic tracking object every time a tracked interface was created, causing down_instance() to be called multiple times when an interface was deleted and previous creations of the interface. Prior to the patch to add fault flag bits this resulted in the vrrp instance not coming back up after the interface was recreated. Ths issue of vrrp instances remaining in fault state after after deletion and re-creation of interfaces is now resolved.

- **vrrp**: delay deleting VMACs are parent interface is deleted. The interface structure needs to have the ifindex set for the first pass through the VRRP instances, but it must be unset when the VMACs are cleaned up.

- **vrrp**: don't change link local IPv6 address when extra added to base if. If an additional link local address was added to the base interface of a VMAC, keepalived was changing the source address of adverts to be the new address. The commit makes keepalived change the source address if the one it is using is deleted.

- **track**: don't overwrite track file at startup unless configured to.

- **vrrp**: allow interface up debounce timer to exceed 2 * advert interval. There was no need to limit the up debounce timer in the same way that the down debounce timer has to be limited, so this commit removes the 2 * advert interval upper limit.

- **vrrp**: update delayed start time on reload if vrrp_startup_delay changed.

- **vrrp**: ignore IPv6 tentative addresses. We can't do anything with them, and they are not usable, so we now wait until we are notified that the address is no longer tentative before we consider using it.

## Fixes

- **parser**: Fix error handling for HEX_STR parsing in UDP_CHECK. Fixes an issue where HEX_STR values with a trailing 0xff were incorrectly treated as errors. This HEX_STR is used in UDP_CHECK configuration, particularly in the payload and require_reply fields.

- **ipvs**: Fix segfault when using track_file checker.

- **ipvs**: Fix delay_loop for TCP_CHECK.

- **scheduler**: Fix segfault caused double erase from child_pid rbtree. In a situation when a child was timed out, but not yet processed, the thread is THREAD_CHILD_TIMEOUT type and remains on ready queue. If it gets terminated in this state, it needs to be removed from rb tree child_pid and transitioned to THREAD_CHILD_TERMINATED, but without additional moving it to ready queue as it is already there. The erase from child_pid tree is required to clean up pid from not terminated childs tree, but it needs to be done exactly once as rb tree implementation is not guarded against double removal. Erasing or adding same element multiple times, leads to malformed red-black tree and segmentation faults. This patch removes double erase in described scenario.

- **build**: fix compilation failure if building without VMACs.

- **vrrp**: fix reading of iproute2 conf files when directories don't exist.

- **vrrp**: fix segfault when instance has no interface configured. If a vrrp instance has no interface configured (so it is unicast), processing SIGUSR1 resulted ina  segfault.

- **vrrp**: Don't segfault if open_sockpool_socket() fails to open sockets. If a unicast VRRP instance is configured and the unicast_src_ip does not exist on the system, then the bind() fails and the sockets are not opened. This commit ensures that in that case vrrp->sockets is not dereferenced. This is not a real fix to the problem. We need to track the addition and removal of unicast_src_ip addresses, and enter fault state if the address in not configured, or when it is removed.

- **vrrp**: interface add should call setup_interface(). When an interface is (re-)added, setup_interface() should be called even if vrrp->flags is set (eg VRRP_FLAG_NOPREEMPT).

- **vrrp**: fix recreating a VMAC interface with IPv6. The sin6_scope_id was not being updated if a VMACs underlying interface were deleted and recreated, causing the `bind()` call to fail. This commit now correctly updates the sin6_scope_id field in mcast_daddr.

- **vrrp**: fix persistent FAULT state with use_vmac when interfaces renamed. If an existing base interface of a VMAC is renamed, delete the VMAC since the configure base interface no longer exists. When an existing interface is renamed to match the base interface for a VMAC for a VRRP instance, for IPv6 when the VMAC interface is created a link local address is added, so clear the NO_ADDRESS fault flag by calling try_up_instance(). For IPv4 we do not add an address to the VMAC when it is created, so will wait for notlink notifications of addresses on the base interface, which can then be added to be VMAC.

- **vrrp**: fix keepalived warning of ipsets specified without iptables. keepalived was warning that using ipsets had been specified but iptables had not been specified, even if ipsets had not been specified.
