# Release 2.1.3 `23rd June 2020`

This release fix 2 uninitialized list which can lead to a SEGV when using track_process or track_bfd. There are some minor fixes, IPVS configurations improvements and some cosmetics.

## Improvements

- **snap**: Multiple extensions of snapcraft.yaml. Stop snap builds always appending '+' to version. Correct install hook script. Remove duplication of organize, stage and prime entries.

- **check**: Change persistence_timeout rage. Maximum timeout value is set to LVS_MAX_TIMEOUT = 31 days.

- **check**: Change TTL min value for syncd datagram. If lvs_sync_daemon ttl is set to 0, IPVS kernel code reset it to be 1, which may be make misconception.

- **check**: Change lvs sync port range. If lvs_sync_daemon port is set 0, IPVS kernel code reset it to be 8848, which may be make misconception. Force range to start at 1.

- **check**: Change lvs_sync_daemon maxlen range. If maxlen is set 0, keepalived judges it is legal value. but now maxlen is set mtu - hlen. Force range to start at 1.

- **check**: Make check_http/check_ssl functions void if return val not used.

- **vrrp**: Remove all reference to previous libjson-c.

## Fixes

- **snap**: Fix using different kernel header files in build process.

- **snap**: Fix use of libmagic. The magic file used by libmagic must be the one that matches libmagic, which is the one in the snap. Set environment variable MAGIC to point to the snap's magic file.

- **check**: check_ping/fix handling ping_group_range on 32 bit systems.

- **check**: check_dns/Don't call htons() with a value returned by random(). Since keepalived doesn't store the value returned by random() for later comparison, there is no point potentially swapping the bytes.

- **check**: check_dns/Fix checker timeout. The sands timeout for dns_send() was incorrectly calculated as the sands timeout of the timer thread which had already expired when the dns_connect_thread() was called. Once time_now was subtracted from the expired sands, the timeout had underflowed and was a value close to ULONG_MAX, effectively resulting in no timeout. dns_connect_thread() now adds the checker connection timeout to time_now so that the actual timeout is in the near future. dns_send() now also ensures that when calculating the next timeout there is no underflow.

- **vrrp**: Fix setting of vrrp_ipset_igmp/mld ipset names. A warning when compiling on a 32 bit system identified that the setting of the default names for vrrp_ipset_igmp and vrrp_ipset_mld was very wrong.

- **vrrp**: Initialise vrrp_tracked_process_t tracking_vrrp list_head.

- **vrrp**: Initialise vrrp_tracked_bfd_t tracking_vrrp list_head.

- **core**: Fix checking delay after timer expires before running. If the delay after a timer expires is too long, keepalived sets itself to use real time scheduling and then steadily increases its priority. On 32 bit systems there was a signed/unsigned mismatch between types used in the comparison.

- **doc**: Fix keepalived.conf.5 manpage format.

- **core**: Scheduler/Fix epoll_count is reversed.
