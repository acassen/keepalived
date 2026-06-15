# Release 2.2.8 `31th May 2023`

This release brings improvements and fix some minor issues reported. It add some new VRRP and BFD features as well.

## New

- **vrrp**: Add support for Infiniband over IPv6. Github issue #2100 reported that attempting to use IPv6 over Infinband was causing keepalived to segfault. It turned out that vrrp_ndisc.c had a comment that it still needed to be implemented, which we have now been able to do with someone in a position to test it. With many thanks for Itel Levy of NVIDIA, Israel for reporting the issue and and testing the patch to confirm that it works.

- **vrrp**: Add no_virtual_ipaddress keyword. This keyword suppresses warnings for no virtual ipaddresses configured and allows none to be configured when using VRRPv3.

- **vrrp**: Add --enable-nm configure option. --enable-nm adds support for Keepalived telling NetworkManager not to manage VMAC interfaces the keepalived creates. Early versions of NM (i.e. at least up to v1.12, but resolved at the latest by v1.18) would set the VMAC inerfaces as managed by NetworkManager, and then if the underlying interface went down, NM would down the VMAC interface and the VRRP instance would never recover from fault state.

- **vrrp**: add v3_checksum_as_v2 configuration option. RFC 5798 (the VRRPv3 RFC) states regarging the checksum:

    ..

    5.2.8.  Checksum The checksum field is used to detect data corruption in the VRRP message. The checksum is the 16-bit one's complement of the one's complement sum of the entire VRRP message starting with the version field and a "pseudo-header" as defined in Section 8.1 of [RFC2460].  The next header field in the "pseudo-header" should be set to 112 (decimal) for VRRP.  For computing the checksum, the checksum field is set to zero.  See RFC1071 for more detail [RFC1071].

    Some manufacturers (e.g. Cisco) interpret this to mean that the pseudo- header is not included in the checksum calculation, since RFC2460 only defines a pseudo-header for IPv6. RFC3768 (the last VRRPv2 RFC) did not include a pseudo-header in the checksum. However, keepalived has always included a pseudo-header in the VRRPv3 IPv4 checksum, which is also consistent with the default setting in Wireshark. In order to allow interoperation with Cisco routers, and possibly other manufacturers, the "v3_checksum_as_v2" keyword, when configured in global_defs to set the default for all vrrp_instances, or in individual vrrp_instances, causes those vrrp_instances to exclude the pseudo- header from the checksum. The default action of including the pseudo- header in the checksum remains unchanged.

- **vrrp**: Add option to revert to backup if thread timer expires. If the VRRP process is not scheduled for sufficiently long, another VRRP instance may have taken over as master. For some users, minimising the number of master switches is desired, and so if nopreempt is configured (if it is not configured the highest priority instance will take over as master again), and if it is too long after a thread timer expires before keepalived is scheduled to run so that another instance will probably have taken over as master, we will just revert to backup state rather than sending further adverts. The keyword that configures this is thread_timer_expired.

- **vrrp**: Add optional new JSON format including track_process details. The original JSON format did not allow for adding additional object types other than the original vrrp instances. This commit adds a json_version 2, which puts the vrrp instances in a named array and adds an array of the track_processes.

- **core**: add option to check for malloc's etc returning NULL. Configure option --enable-malloc-check will cause the returned value of malloc/realloc/strdup/strndup to be checked to ensure that they do not return NULL. If any such call does return NULL a message will be logged and the process will terminate. Unless sysctl vm.overcommit_memory == 2 (default is usually 0), or the malloc would cause the process virtual address space to exceed the limit, malloc etc will not return NULL. It is only once there is a write into the memory block that the memory is actually allocated, and if there is insufficient memory (including swap space), then the OOM killer will step in to either kill keepalived, or kill another process. Consequently checking for NULL being returned is generally a waste of time and program size.

- **ipvs**: Add option to check OpenSSL mallocs/frees for validity.

- **ipvs**: Add option to let SSL_GET shutdown comply with TLS spec.

- **bfd**: Add multihop option to conform with RFC5883. RFCs 5881 and 5883 state that port 3784 is used for single hop BFD and port 4784 is used for multihop. The commit adds configuration option "multihop" to use port 4784 rather than port 3784.

## Improvements

- **vrrp**: Don't adjust vrrp receive timeout during delayed start. The timeout for a vrrp instance to become master should not be changed if an advert is received during the delayed start - the timeout is set to include the delayed start and the (3 to 4) * advert int delay to take over as master.

- **vrrp**: Remove redundant checks of snmp_option.

- **vrrp**: deley freeing vrrp instances until all references are freed. Trackers etc have lists for vrrp instances that are tracking them. Therefore the trackers, and their references, must be freed before the vrrp instances are freed.

- **vrrp**: restore the vmac ipv6 link-local after flapping. The user is not supposed to shutdown a vmac interface created by keepalived. However, it can mistakenly happen. When the link is re-established, the link-local has disappear (the kernel removes all IPv6 addresses on link down except if keep_addr_on_down sysctl is on) and sending VRRP packet is no nore possible. Restore the IPv6 Link-Local after a VMAC interface flapping. A Link-Local is not set when the VRRP packets are sent from the base interface (vmac-xmit-base). Note that the IPv6 Virtual Addresses are also removed on link down which is the desired behavior. Enabling keep_addr_on_down sysctl would keep the link-local without this patch but would break this behavior.

- **doc**: Man pages and documentation updates. Add explanation of why unicast VRRPv3 checksum changed.

- **configure**: Add systemd auto option. fix default config file with ${prefix} use. use back-ticks rather than $(...) for commmands. Improve checking for ${prefix}.

- **ipvs**: Don't report HTTP_CHECK when it is an SSL_CHECK.

- **ipvs**: Work around OpenSSL memory leak in versions 3.0.0 to 3.0.4. The memory leak was observed with OpenSSL 3.0.1, and it is resolved by version 3.0.5. Also the leak is not observed in v1.1.1n.

- **ipvs**: Simplify SSL_GET handling code.

## Fixes

- **rpm**: Fix RPM spec file to use kmod-lib and kmod-devel rather than libkmod.

- **vrrp**: Fix NFT support to properly handle build with L4PROTO support.

- **vrrp**: Resolve segfault when enable_snmp_vrrp is added at a reload.

- **vrrp**: workaround GCC LTO bug causing incorrect VRRPv3 checksum. The problem was observed with GCC versions 11.2, 11.3.1 and 12.1.1, on Ubuntu 22.04, Fedora 34, Fedora 36 and Fedora 37 (Rawhide). The problem did not occur when not using LTO, nor when using clang, even with LTO.

- **vrrp**: fix ipv6 vrrp in fault state because no ipv4 address. Setting an IPv6 VRRP virtual address on an interface that has no IPv4 address results in a persistent FAULT state.

- **core**: Fix segfault when receive netlink message for static default route added.

- **build**: Fix order of -lssl -lcrypto. This needs to be correct in order to be able to use static library linking on Alpine Linux.

- **build**: Fix build with libressl. SSL_set0_rbio is provided by libressl since version 3.4.0 and libressl/openbsd@c99939f but SSL_set0_wbio is not provided resulting in build failure.

- **build**: Fix out of tree builds. Fix build error with --disable-track-process.

- **build**: Fix building with --disable-vmac.

- **build**: Fix compiler warning when building without VRRP authentication.

- **parser**: Fix segfault caused by extra '}' and other parser fixes. If there was a configuration error in a block, e.g. a vrrp_instance, keepalived would apply the configuration in the rest of the block to the previous object of that type, e.g. the previous vrrp instance. If there had been no previous instance, keepalived would probably segfault. This commit changes the way the parser works. A new instance of an object, e.g. a VRRP instance or a virtual server, is only added to the list of those objects once the configuration of that object is complete. In particular it no longer applies the configuration to the last entry on the list of the relevant object type, but keeps a point to the object currently being configured.

- **parser**: Optimise fixing recalculating updated line length.

- **ipvs**: Fix memory leaks when configuration is repeated. Use last entry if duplicate definition.

- **lib**: Fix malloc check code for CPUs without unaligned memory access.
