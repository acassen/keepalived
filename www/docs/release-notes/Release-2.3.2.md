# Release 2.3.2 `3rd November 2024`

This release brings improvements and fix some minor issues reported.

## New

- **all**: add --ignore-sigint option. This is needed for running keepalived under GDB (see https://bugzilla.kernel.org/show_bug.cgi?id=9039#c8).

- **vrrp**: allow specifing interval amd timeout to milli-second resolution. Although running track_scripts too rapidly can have use cause heavy system load, there are use cases for being able to run scripts more frequently than 1 second, and also at intervals not in whole seconds. This commit adds the option to be able to specify the interval and timeout timers to a resolution in milli-seconds.

## Improvements

- **vrrp**: remove need for route to have configured interface to track it. If a virtual route did not have an interface configured, keepalived would log a warning saying that it could not track the route, and then would disable tracking of that route. It appears that it is not necessary to know the interface in order to track the route, and in any event the netlink message received after adding the route identifies the interface for the route if it is appropriate. So this commit removes the requirement to specify an interface in order to track a route.

- **intall**: Update INSTALL instructions - add openSUSE.

- **ipvs**: Retry ipvs_nl_send_message() in ipvs_getinfo(). If we have to call keepalived_modprobe() for the ip_vs module, on some distros (e.g. RHEL based ones but not Fedora) we need to call ipvs_nl_send_message() twice in ipvs_getinfo(), since the first call fails. On most distros keepalived_modprobe() does not need to be called, since calling genl_ctrl_resolve(sock, IPVS_GENL_NAME) loads the ip_vs module.

- **core**: improve error message for process event listen.

- **all**: Properly handle an include file name ending with '\'.

- **vrrp**: Allow for Ethernet frame padding for short packets. Some network interface cards do not strip Ethernet frame padding before passing a packet to userspace (recvmesg()). keepalived checks the received packet length but wasn't allowing for extra bytes to be received that were added as frame padding. This commit allows for frame padding to be received and not report an incorrect packet length.

- **vrrp**: Remove duplicate dumping of master advert interval. Don't write master advert interval in keepalived.data twice when using VRRPv3 and the VRRP instance is in backup state.

- **vrrp**: Handle empty ipset names with vrrp_ipsets keyword. We now handle empty ipset names and return a config error.

- **vrrp**: handle empty iptables chain names - vrrp_iptables keyword. We now return an error if a chain name is empty.

- **vrrp-ipvs**: handle empty nftables chain names. We now return an error if a chain name is empty.

- **vrrp**: use configured vrrp ipset names rather than ignore them.

- **vrrp**: check configured vrrp ipset names are all different. If a pair of configured ipset names are the same, there will be an error when using the ipsets. This commits checks and logs an error if two ipset names are the same.

- **core**: remove some duplicate include files.

- **core**: ensure only one instance of keepalived can run per config_id. There was a window when keepalived starts up when if two (or more) instances were starting at the same time, they might not detect the other instance is running. This commit add advisort file locking on the PID files to ensure that only one instance can run at a time.

- **vrrp**: Duplicate/drop MLDv1 listener reports on VMACs. MLDv2 listener reports were being handled, but not MLDv1. This commit now adds handling of MLDv1 listener reports as well.

- **all**: Ensure pid file exists when respawning child process. If a child process is respawned, the old pidfile may or may not still exist. If it doesn't exist, we need to recreate it. If it still exists we need to reset our file offset and truncate the file before re-wrighting it.

- **all**: better pidfile handling after reload.

- **vrrp**: add thread_timer_expired keyword as a synonym of timer_expired_backup. The release notes referred to thread_timer_expired, so it is added for completeness but logs a message to change the keyword to timer_expired_backup.

- **bfd**: use time_t to avoid implicit ptr type casting. This fixes an incompatible pointer type [-Wincompatible-pointer-types] issue when compiling keepalived with GCC 14 [1] in 32-bit architectures where time_t size is 64 bits.

- **vrrp-ipvs**: Stop setting SO_LINGER on TCP sockets. Setting SO_LINGER causes the close() call to block until the first of: 1. the ACK of the FIN is received 2. the SO_LINGER timeout expires Since the SO_LINGER timeout was set to 5 seconds, if the FIN or the subsequent ACK were lost, then keepalived would block for 5 seconds, which must not be allowed to happen. The only TCP sockets that keepalived opens are for TCP_CHECK, HTTP_GET, SSL_GET, SMTP_CHECK and sending notify emails. For all of these, for any data that keepalived sends it receives data in response, and so there is no purpose in using SO_LINGER. Removing setting SO_LINGER will stop the occasional 'A thread timer expired 5.1nnnnn seconds ago', as reported in issue #2271.

- **all**: use correct format specifier for time fields. 32 bit Debian uses a 32 bit TIMESIZE, whereas 32 bit Ubuntu uses a 64 bit TIMESIZE. This means that on 32 bit Ubuntu some time types need to be printed using "%lld", whereas on 32 bit Debian, and on 64 bit systems "%ld" is what is needed. Using the wrong format specifier was causing compilation warnings on 32 bit Debian. The issue impacts printing time_t, struct timeval tv_sec and tv_usec and struct timespec tv_sec fields. Peversely, on a 32 bit system when TIMESIZE is 64, struct timeval tv_usec is 64 bits, whereas struct timesec tv_nsec is 32 bits. The commit adds configure time checking of the right format specifiers to use, and adds definitions PRI_time_t, PRI_tv_sec, PRI_ts_sec etc.

- **core**: update addattr_l to match current iproute2 code - almost. The alignment calculations were not coerect, so this commit updates addattr_l to match the iproute2 version, EXCEPT there appears to be 1 issue in the iproute2 code when NLMSG_ALIGN is used when RTA_ALIGN should be used. The difference is entirely cosmetic (at the moment) since the functionality of the 2 macros is currently identical.

- **lib**: add micro-second timers to memory allocation debugging. Previously the time was logged for memory allocation/freeing operations in seconds. When comparing when memory was allocated/freed to debugging logging via a log file, it was helpful, in terms of being able to identify the sequence of events, to have the time of memory allocations etc logged in micro-seconds.

- **vrrp**: on reload only configured track_script name was checked. On a reload, only the configured name of a track_script was being checked to see if the new config track_script matched the old config track_script. If the script to be executed were changed, but the configured named of the script were kept the same, then the status of the old script would be transferred to the new script, despite the scripts being completely different. This commit now checks that the script really is the same, in terms of the path, parameters and user executing the script.

- **vrrp**: On reload with addresses added to VRRP instance send 2nd GARPs. If garp_master_delay is non zero, then after a reload when VIPs are added to a VRRP instance in master state, as well as the initial block of GARP messages that are sent, the messages need to be repeated after garp_master_delay seconds. This commit adds sending the second block.

- **vrrp**: merge vrrp instance garp_pending and gna_pending flags. Combine garp_pending and gna_pending flags into a single flags; that is all that is necessary and simplifies the code.

- **vrrp**: Use timer threads for delayed sending of GARPs/GNAs. Previously whenever a VRRP instance send an advert, it checked to see if any more GARPs/GNAs were due to be sent, either for garp_master_delay or garp_master_refresh. Using timer threads removes the checking every time an advert is sent, and the relevant code is only triggered when a timer expires.

- **vrrp**: stop using alloc_strvec() for parsing rttables files. It was a good idea at the time, but is not really appropriate. The parsing can be done just as simply without using alloc_strvec().

- **all**: stop "unmatched quotes" warning for quoted strings. If a line with a quoted string has unbalanced quote characters when parsed as a standard (not quoted) string, an innapropriate warning was issued for unmatches quotes. This commit now stops the warning. This commit is not elegant, and it would be appreciated if a neater solution could be found. If anyone has a better solution, please submit a pull request or raise an issue explaining the solution.

- **all**: change checking process name at reload to include not NULL checks. The code was using the reload variable as an indicator that prev_global_data was not NULL, and this was causing some static code analysers to to flag up NULL pointer dereferences. The patch explicitly checks whether prev_global_data is NULL or not, since this is synonymous with testing the reload variable.

- **all**: clear pointers to old data structures freed after reload. This means that if that if there is a subsequent reference to the old data via thoe old_global_data, or old{bfd,check,vrrp} pointers, it should cause a segfault rather than undefined behaviour. It will also make it more straightford to debug any problem should it occur.

- **vrrp**: update location of iproute config files. Since iproute2 version 3.3 the location of the config files has been configurable, with the default being /etc/iproute2. Since version 4.4 there has been an rt_tables.d sub-directory. Version 4.10 added an rt_protos.d sub-directory, and version 6.5 added a second directory (/usr/lib/iproute2 or /usr/lib64/iproute) which 6.7 changed to /usr/share/iproute2 as the default. No major distro appears to change the default locations, and the only distro that used verion 6.5 or 6.6 was Fedora 40, but that has now upgraded to 6.7 so we are not bothered with the /usr/lib* options. The two directories have configure options, and if they are not specified, configure attempts to get the locations from the ip-route man page or the ip executable.

- **vrrp**: Specify protocol for IP addresses that keepalived adds. This is similar to being able to specify a protocol of ip routes and rules.

- **vrrp**: Add configure option to update /etc/rt_addrprotos. If there is no keepalived entry in rt_addrprotos create an entry which is removed when keepalived terminates. This will allow ip address show to display the protocol of an address as "keepalived" rather than 0x12.

- **vrrp**: always add a keepalived entry to rt_addrprotos is none exists.

- **doc**: Some updates.

## Fixes

- **vrrp**: Handle a reload before vrrp_delayed_start has expired. If keepalived reloaded its configuration before a specified vrrp_startup_delay had expired, the startup_delay was never being timed out, and so all received adverts would be discarded. The commit caused the startup_delay timer to be reinstated after a reload if the timer has not yet expired.

- **ipvs**: Update status code of misc checker if changes while in fault state. The exit code of a misc checker can be read via SNMP. The misc check code was not updating the last exit code if the checker was not dynamic, the checker was already down (i.e. returned a non 0 exit code), and the exit code changed from the previous exit code. This meant that the exit code reported via SNMP was not the latest exit code, but the exit code that caused the status of the checker to change. This commit now updates the last exit code, even if the checker is already down.

- **vrrp**: Ensure VRRPv3 advert interval strictly <= 40.95 seconds. If an advert interval of 40.958 seconds was configured, it was being round up to 40.96 after the check that the advert interval was less than 40.96. The consequence of this was that adverts were being sent at 40.96 second intervals, but worse, the advert interval in the VRRP packet was set to 0. This commit now ensures that after the rounding the advert interval is <= 40.95 seconds.

- **vrrp**: fix track process reinitialize fork delay timer. Github user Bbulatov identified that terminate_delay was being used when fork_delay should have been used. While investigating, it was also found, albeit in a debug message that fork_delay was used where terminate_delay should have been used. Further, the process state was being updated immediately even if the fork_delay was being invoked.

- **vrrp**: fix memory leak if error in vrrp_ipsets configuration.

- **vrrp**: stop memory leak when error in configuring vrrp_iptables.

- **bfd**: make alloc_bfd() return NULL rather than false on error. alloc_bfd() returns a bfd_t \*, but in the case of errors it was returning false, which clearly should have been NULL. This issues was identified by compiling with -std=c23.

- **vrrp**: fix corruption of master-child_pid red black tree. Child process thread_t structures use two red-black trees, one for the timeout, and the other for pids. It is important to ensure that threads are removed from the child_pid RB tree at the correct time. This was not happening when reloads were occurring and there was a THREAD_CHILD_TIMEOUT thread on the ready list. A few other instances of the thread not being removed from the child_pid RB tree correctly, which are also resolved by this commit.

- **all**: Fix parsing of \xNN in quoted strings. Following \x keepalived processed all following hex digits, but only returned one byte. For example \x20file would result in a byte 0x0f followed by the string "ile". This commit limits the number of hex digits consumed to 2.

- **all**: fix parsing of escaped characters in quoted strings.

- **core**: fix error report in json version parser.
