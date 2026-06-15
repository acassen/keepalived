# Release 2.2.0 `09th January 2021`

This release bring a bunch of new features and extensions. This release targetted corner cases and resilient handling. This release is a major milestone for us ! please consider upgrading, this is the fruit of hard stabilization and non-regression effort.

## New

- **vrrp**: Add recvmsg-debug configure option. This debug option allows logging of all received VRRP packets.

- **vrrp**: Implement notify_priority_changes on sync groups.

- **vrrp**: Check all VRIDs for conflicts even after error found.

- **vrrp**: Add option for VMACs for IPs not on VRRP instance's interface.

- **vrrp**: If delete a VMAC when reloading, don't try to recreate it.

- **vrrp**: Add global option disable_local_igmp to stop IGMP on VMACs. As an alternative to using nftables to move IGMP messages from VMACs to their parent interfaces, disable_local_igmp stops all IGMP messages for addresses in 224.0.0.0/24, since they are unnecessary. It achieves this by clearing /proc/sys/net/ipv4/igmp_link_local_mcast_reports.

- **bfd**: Add support for configuring timers to micro-second resolution. Previously, min_rx, min_tx and idle_tx could only be specified in whole milli-seconds. RFC7419 states: "Common Interval values to be: 3.3 msec, 10 msec, 20 msec, 50 msec, 100 msec, and 1 sec". In order to support 3.3 msec, we need to be able to specify fractions of msec, so this commit adds support for specifying the timers to 3 decimal places of msecs, in other words allowing the resolution down to single micro-seconds, which is the resolution of the timers in the BFD protocol. In order to support this change, all logged values of the timers are now logged in micro-seconds, instead of the previous milli-seconds.

- **core**: Add reload_check_config global_defs option. This option makes keepalived check the new configuration to ensure that there are no errors before it initiates the reload. It does this by running another instance of keepalived with the --config-test option.

- **core**: Add timeout handling for reload check_config process.

- **core**: Only read config files once when starting or reloading. Some users who have automatically updated configurations and frequent reloads can experience a problem when using the reload config_check if a config file changes between when the config check runs and is successful, and then the main keepalived processes read the config files. This feature makes keepalived write the config to a memory based file when the config is first read, and then all the other processes read the memory based file, rather than re-reading the config files.

- **core**: Add reload_file config option. The feature makes keepalived create the specified reload_file before it starts reading the configuration files during a config reload and deletes the file after it has finished reading the configuration files. If the reload_file is created by the user (or a user process) before signalling keepalived to reload, the user (or user processs) can monitor the existance of the file, and when it is removed can start modifying the config files again.

- **core**: Add configuration option to cache config on disk. By default a copy of the configuration is written to a memory based file while keepalived is loading/reloading. The new config_directory global_defs option allows specifying a directory on whose filesystem the config will be written instead. This feature also adds support for systems that do not support memfd_create() by using an anonymous file created on the /tmp filesystem.

- **core**: Add distro name to output of keepalived -v.

- **check**: Add UDP_CHECK payload data for sending and checking reply. Pedro Viton of Nokia, Madrid requested the ability to be able to specify a payload for the UDP messages sent for a UDP_CHECK, in order to avoid having to use a MISC_CHECK, with the associated overhead that causes. This commit extends that idea by allowing the maximum and minimum required payload lengths for the returned payload to be specified, and also allows parts of the returned payload to be checked to match configured values.

- **ipvs**: Allow multiple MISC_CHECKs and use with FILE_CHECKs. Previously a MISC_CHECK set the weight of the real server based on it's exit code. This meant that a real server could not have more than one MISC_CHECK (not really a problem because a script could combine all the MISC_CHECK scripts), but also MISC_CHECKs and FILE_CHECKs could not be combined.

- **ipvs**: Send omega notifies when using lvs_flush_onstop.

- **parser**: Check glob_strict to include_check and add more options. Add includer, includem, includew, includeb and includea include types. Change glob_strict to include_check to be more meaningful. Add options to include_check for different include checks Add -e command line option so that keepalived will exit if there are include errors.

- **systemd**: Add systemd service notification. If keepalived is run by systemd and the service file has type=notify, then keepalived will notify systemd that it has started, that it is reloading, that a reload has completed, and that it is stopping. systemctl status keepalived shows the current status of keepalived. The main benefit of this is that "systemd reload keepalived" will not initiate another reload until the previous reload has completed, and it is also possible for scripts to check the systemd status of keepalived to ensure that the previous reload has completed before modifying configuration files again.

- **conf**: Use --with-default-config-file for installing default config file.

- **debug**: add option to disable malloc() checking if it is enabled. This was produced due to the reload_check_config option, to stop unnecessary errors being reported, so adding a command line option to turn the checking off was simple to add as well.

- **debug**: Add using gstack to dump a stack backtrace. gstack uses gdb and the bt command, so provides more information than using backtrace_symbols().

## Improvements

- **vrrp**: Ensure the kernel supports network namespaces before using. Previously configure just checked that the libraries supported setting the network namespace, which would normally be fine. However is using old kernel headers with a newer glibc this would cause a build failure.

- **vrrp**: ensure virtual routes are not lost during a reload. If a virtual route depended on a VIP and a reload changes the VIP, the kernel would delete the route when the VIP is deleted, but not reinstate the route if a new VIP allowed the route to work again.

- **vrrp**: IPv4 iptables entries don't use ICMP so remove code handling it.

- **vrrp**: Cosmetics improvement to use definitions for iptables ICMPv6 types.

- **vrrp**: Use IGMP/MLD protocol rather than multicast address in iptables and nftables. Rather than checking the multicast destination address to identify IGMP/MLD packets, use either IPPROTO_IGMP or IPPROTO_ICMPV6 with type ICMPV6_MLD2_REPORT.

- **vrrp**: Make vmac_xmit_base work for IPv6 with base i/f in another netns. If vmac_xmit_base is specified for an interface that is a macvlan or an ipvlan and the base interface of that macvlan/ipvlan is in another network namespace, we cannot access the base interface, and so the macvlan/ipvlan interface must be used.

- **vrrp**: Ensure first advert sent before GARPs on transition to master. If we are transitioning to master and we are using a VMAC, for IPv4 we must ensure that any existing (lower priority) master removes its VIPs before we send the gratuitous ARPs. The only way to make the old master remove the VIPs is to send a higher priority advert, so we need to do so before sending the GARPs. The problem with sending GARPs before the VIPs have been removed, when using a VMAC, is that we send a GARP request, but the old master, since it has the VIP configured on the same MAC address, then sends a GARP reply, which will cause any MAC caches in switches to be updated again to point to the old master for the VMAC MAC address. This solution isn't perfect because it depends on the old master removing the VIPs before it receives the GARP request that we will send, but it is certainly better than sending GARPs first, which will guarantee that the old master will send GARP replies. We probably need to use a firewall, or eBPF filter, to properly stop the GARP replies being sent.

- **vrrp**: Make track_process work on sync groups.

- **vrrp**: ensure memory used for entries in /etc/iproute2 is freed.

- **vrrp**: Correct logging of master advert interval changes.

- **vrrp**: Stop code duplication when iterating though VIPs and eVIPs.

- **vrrp**: Don't treat for IPv6 VIP non link local as error unless vrrp_strict set. While it is an error based on RFC5798 not to have the first IPv6 VIP being link local, keepalived can run successfully even if the first VIP is not link local. Since we have the vrrp_strict option, only treat it as a hard configuration error if vrrp_strict is set, otherwise just log it.

- **vrrp**: Ensure the same VMAC name is not used by more than 1 VRRP instance.

- **vrrp**: When creating VMAC names, check name doesn't match configured name.

- **vrrp**: handle interfaces being created while VMAC interfaces are created.

- **vrrp**: Don't send sync group notifies at reload if state hasn't changed.

- **vrrp**: Handle tacked interface having master interface removed.

- **vrrp**: Ensure a new IPv6 interface address is copied to vrrp instance. When a VMAC is being used with IPv6 if the parent interface transitions from down to up, copy the new IPv6 link local address to the vrrp instance.

- **vrrp**: if VMAC name changes on reload, delete the old VMAC.

- **vrrp**: Don't delete VMAC after reload if still used. If a vrrp instance using a VMAC is deleted during a reload, but another VRRP instance starts using the same VMAC, don't delete the VMAC.

- **track**: Extended track_process framework to log if kernel doesn't support proc events.

- **parser**: Improve debugging output of parser.

- **smtp**: Optimise MALLOC calls when sending SMTP messages. This extension changes the code to use a single MALLOC that includes the buffers, and sets pointers accordingly; it is also more efficient.

- **check**: Change lvs_process_name/ipvs_process_name to checker_process_name.

- **scheduler**: If process terminated by SIGKILL, suggest rlimit_rttime. If a keepalived child process is terminated by SIGKILL, in the log message from the parent process add a suggestion that it may have been caused by rlimit_rttime being exceeded.

- **core**: Don't change process names if reload fails. On reload, if the new configuration specifies new process names for the child processes, don't change the process names until it has been determined that the reload can proceed.

- **core**: Implement PTR_CAST. Using PTR_CAST with default configuration should make no difference to the code generated, but can suppress unnecessary compiler warnings. On architectures which require aligned access, e.g. 32 bit ARM (an example being the Raspberry Pi), the compiler produces a very large number of "cast increases required alignment of target type" warnings. PTR_CAST will now, by default, cast via a void pointer, which suppresses the warning.

- **core**: Don't explicitly close signal_fd prior to exec. The signal_fd is opened with the CLOEXEC flag, so there is not need to explicitly close the fd prior to an exec.

- **core**: ensure directories created for PID files have correct permissions.

- **core**: If epoll_wait() returns un unrecoverable error, exit and reload.

- **core**: Allow location of temporary directory to be specified.

- **script**: Merge notify_exec() into system_call_script(). Merge notify_fifo_exec() into system_call_script(). Move system_call() code into system_call_script(). Move local_fork() code into system_call_script().

- **ipvs**: Allow real servers to be specified with a weight of 0. This currently only really makes sense when also having a FILE_CHECK with non-zero weight configured, or a MISC_CHECK with "misc_dynamic", since otherwise there is no way that the weight of the real server can be changed to be non-zero.

- **ipvs**: Remove rs->weight and use rs->effective_weight.

- **ipvs**: handle effective_weight overflowing 32 bits. Since FILE_CHECKs can return values up to 2^31 - 1, adding two FILE_CHECK return values can overflow a signed 32 bit integer. This commit forces effective_weight calculations to be done as 64 bit, to stop any overflow.

- **ipvs**: Improve migrating checkers when reloading.

- **ipvs**: Add dumping of current weight of checkers.

- **ipvs**: Sort out reloading with FILE_CHECK and dynamic MISC_CHECK.

- **ipvs**: sort out IPVS_WEIGHT_* definitions.

- **ipvs**: Allow FILE_CHECK to set weight 2147483647 with multiplier 1. 2147483648 (or -2147483648 if weight reverse) now triggers fault state.

- **ipvs**: Simplify converting effective_weight to actual weight.

- **ipvs** **vrrp**: Ensure inotify established before read a track file. Previously at initialisation a track file was read before the inotify was established on the file. This left a small window when the file could be updated after it was read and notification was received that the file would not be changed.

- **man**: bring keepalived.8 man page up to date.

- **man**: Generate the date for man pages from the lastest commit of the page.

- **man**: Misc manpage content updates.

- **systemd**: Set systemd service type based on whether built with systemd support.

- **build**: improve generation of git-commit.h and ensure dates are UTC.

## Fixes

- **vrrp**: Fix building without VMAC support.

- **vrrp**: Don't remove unweighted track scripts from sync group members. While switching to new list_head_t design code cleared the track_script list for any vrrp instance that was in a sync group. This was due to the old list structure allocating memory which had to be freed if the list was empty, but that is no longer the case with list_head.

- **vrrp**: Fix IPv6 neighbour advert unaligned access. Due to struct eth_header being 14 bytes long, attempting to follow that in a single buffer with a struct ip6hdr, which requires 4 byte alignment, causes unaligned access unless the struct eth_header is forced to be 2 byte aligned but not 4 byte aligned. Solution used here, instead of forcing an unnatural alignment, uses a gather write (sendmsg()) so that each header structure is constructed independently.

- **vrrp**: Fix unaligned access for data from process events connector.

- **vrrp**: Be consistent about whether an IPv6 address is set or not. It has been identified that keepalived was setting an invalid IPv6 address after a reload if the address had previously been configured and then removed from an interface. The cause of this was that sometimes only the first 32 bits were checked or cleared, and sometimes all 128 bits were checked or cleared.

- **vrrp**: fix nftables vmac_set entries when don't have dup statement. The if_index values were being incorrectly set in nftables when the nftables dup statement is not supported. The problem was that the if_index was being treated as big endian, whereas it should be host endian.

- **vrrp**: Fix binding to unicast link local IPv6 address.

- **vrrp**: Fix using VMACs with unicast peers.

- **vrrp**: fix list head handling for nftables when removing VIPs on reload.

- **vrrp**: fix list head handling for iptables when removing VIPs on reload.

- **vrrp**: fix checking if kernel netlink socket is open.

- **vrrp**: correct calculation of vip count if some entries invalid.

- **vrrp**: Don't segfault when a VRID is changed on a VMAC when reloading.

- **vrrp**: Don't segfault if interface changes state during delayed startup.

- **bfd**: Fix BFD process PID file name.

- **doc**: Fixes some documentation and manpages related.

- **ipvs**: Fix building with libnl1. When using a separate namespace for IPVS configuration was introduced (in v2.1.0) building with libnl1 was broken. This commit now restores building with libnl1. Is anyone really still using it?

- **ipvs**: Fix lvs_flush_instop VS with virtual server groups. The code was not removing the virtual server and real servers for virtual server groups when config option lvs_flush_on_stop VS was specified.

- **ipvs**: Fix parsing content length for HTTP_GET and SSL_GET.

- **ipvs**: fix adding FILE_CHECKs at a reload. When FILE_CHECKs are added during a reload, if the file check is in a failed state, the real server must be failed.

- **ipvs**: Fix SNMP stats when using virtual server groups. The stats for virtual server using a virtual server group did not include the IPv6 stats when the virtual server group had both IPv4 and IPv6 members (which is allowable if all the real servers are tunnelled), and the real server stats were not being collected.

- **core**: Fix detecting setsid() error in xdaemon().

- **core**: Fix a file descriptor leak in scheduler when reloading

- **check**: fix a file descriptor leak with SSL_GET.

- **check**: Fix handling of timeouts for SSL_GET.

- **snmp**: Fix checking file descriptors used for snmp_epoll. If only the most significant bit was set, so bit == 64, bits >>= bit was effectively a no-op. The code now explicitly checks for this case. Also, the do { ... } while (); loops should be while () { ... }; This wasn't a problem in snmp_epoll_info() but it was in snmp_epoll_update().
