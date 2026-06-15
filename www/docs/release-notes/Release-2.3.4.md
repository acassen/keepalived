# Release 2.3.4 `10th June 2025`

This release brings improvements and fix some snap build issue.

## Improvements

- **core**: properly restore process priorities after a reload.

- **core**: allow specifying iproute_usr_dir even if no iproute2 support.

- **core**: include network namespace name when error opening namespace fds.

- **core**: resolve lang warning when comparing ordering of function addresses. The only reason function addresses are compared is with a red-black tree to quickly convert a function address into its name. It clearlt isn't a sandard thing to do to compare ordering of function addresses, but it this case it is quite valid.

- **core**: stop repeatedly calling getpid(). We only need to call getpid() once per process, and can then save the value. A PID of a given process is never going to change!

- **core**: add code to calculate maximum stack usage and use it for no_swap. When a process has no_Swap specified, if we want to ensure that the stack is resident in memory we need to know the maximum size that it is likely to grow to. This commit adds diagnostic code (usually disabled) to report maximum usage, so that the code can be updated to know, in advance, the maximum likely stack usage.

- **core**: set CLOEXEC flag on all file descriptors except stdin/stdout/stderr.

- **core**: set CLOEXEC flag on streams (fopen/popen).

- **snmp**: set CLOEXEC on file descriptors opened by snmp.

- **snmp**: use close_range() if available for closing snmp file descriptors.

- **core**: call close_range() if available before exec'ing scripts.

## Fixes

- **build**: fix snap build process.

- **vrrp**: fix segfault at reload when DBus re-enabled. If dbus as enabled, then a reload disabled it, and another reload re-enabled it, then keepalived would often segfault. This is resolved by clearing dbus_startup_completed when dbus is stopped.

- **vrrp**: fix track_process warn identified by -Wflex-array-member-not-at-end.

- **notify**: fix resolving group name to gid for scripts. If a group had a large number of members, the memory allocated for getgrnam_r() could be insufficient and the call fail. This commit now allocates as much memory as the size of the group file, which should be sufficient.

- **ipvs**: resolve infinity loop when SMTP_CHECKers have 'host' config.

- **core**: fix keepalived not coredumping after a reload. This made it very difficult to resolve segfaults occurring due to a reload.

- **vrrp**: document and fix specifying iproute_etc_dir and iproute_usr_dir.

- **build**: fix some RHEL 7 and friends compilation problems.

- **core**: fix memory leak in track_file.
