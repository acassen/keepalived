# Release 2.2.3 `14th August 2021`

This release add some new features and fix some minor bugs. genhash utility is now part of the mainline daemon.

## New

- **genhash**: Rewrite genhash utility to be part of mainline daemon. There is no good reasons for it to be a dedicated standalone tool. This extension create a new keepalived command line option --genhash with all commands and options from previous utility. Our goal is to use the same code path in order to generate MD5SUM by submitting exactly the same code as the one used for HTTP_GET and/or SSL_GET.

- **vrrp**: Add interface up/down debounce timers. There are  some users who experience very rapid interface up/down/up state transitions, and would like the VRRP instance on the master not to transition to backup state as soon as the interface goes down. This commit adds interface down and up debounce timers so that a master instance can remain in master state if its interface very briefly transitions to down state and then reverts to up state.

- **vrrp**: Add down_timer_adverts configuration option The VRRP RFCs state that the master down timer is 3 advert intervals plus a skew timer. There are some users who, due to network problems, would like to have more advert intervals, and there are others who would like to have fewer advert intervals in order to achieve a faster take over time by a backup instance. Using this feature is absolutely non-conformant with the RFCs, but it does add some flexibility for certain users.

- **vrrp**: Define and use VRRP_MS_DOWN_TIMER etc for master down timer. The vrrp code had the same calculation in may places for calculating the master down timer. Introducing VRRP_MS_DOWN_TIMER means that there is only one place where the calculation is specified. This is also in preparation for the commit to introduce down_timer_adverts.

- **vrrp**: Allow sync groups with only one member again. It appears that there are some use cases where users want a sync group with only one member - issue 1912 identifies dynamic configuration adding and removing VRRP instances.

- **core**: Add option to save config details before and after reload. There have been occasions when strange behaviour occurs when there are frequent reloads. This commit adds global_defs option config_save_dir that makes keepalived save each configuration and also the internal state data dumps before and after each reload. The feature is intended for debugging purposes only.

- **core**: Report correct memory allocation after reload. When using the mem-check debug option, report the malloc'd memory size after freeing the old configuration, so that if reloading the same configuration the same size is reported after the reload as was reported initially.

- **build**: add Link Time Optimisation configure option.

- **dump**: Add data_use_instance global def. The filenames of the data dump files keepalived writes to after receiving SIGUSR1 were always the same, and this caused problems if multiple keepalived instances were running on a system. This commit adds the data_use_instance global def which makes keepalived include the instance name and network namespace name in the dump file names.

- **ipvs**: Add snmp_name virtual and real server options. The snmp_name options allow a text string to be included in the SNMP data for each virtual and real server. This can make it easier for scripts etc which parse SNMP output.

## Improvements

- **build**: Add support for clang compiler and resolve bug and warnings identified.

- **core**: Stop using floating point for most config options with decimals.

- **ipvs**: check kernel supports NFT_SET_CONCAT for using ranges in concatenations.

- **ipvs**: log VS and RS info when logging IPVS cmd error.

- **ipvs**: Stop using deprecated inet_aton(). It would have been simpler to use inet_pton() rather than getaddrinto(), but that does not support IPv4 numbers-and-dots notation, whereas inet_aton() does. We probably don't want to support numbers-and-dots notation, but someone may be using it, and ipvsadm, since it uses inet_aton(), does support numbers-and-dots notation for granularity mask.

- **vrrp**: Make VMAC IPv6 link local address mirror parent interface. If the link local address on the parent interface of a VMAC is changed, keepalived will now change the link local address of the VMAC so that it is the same as the parent interface's. There was also an inconsistency in keepalived's behaviour. If the parent interface's link local address was deleted, keepalived generated a link local address for the VMAC based on the MAC address of the parent interface. However, if when keepalived started the parent interface didn't have a link local address, then one was not assigned to the VMAC. keepalived will now generate a link local address on startup if the parent interface does not have a link local address.

- **vrrp**: Make duplicate track_file on VRRP instance and sync group consistent. The log message for having a track_file configured on both a VRRP instance and its sync group was not consistent with the equivalent messages for track_bfd, track_process, track_script and track_interface. This commit now makes the messages all the same.

- **vrrp**: Only log 0 pri messages and SNMP traps if --log-detail specified.

- **vrrp**: Add further comparisons when comparing routes when reloading. Since keepalived does not set the NLM_F_EXCL flag when adding routes, the scope, type and nexthops also have to be compared.

- **vrrp/bfd/ipvs**: If log detail, log CPU time used by children if any when exit.

- **doc**: Some documentation updates.

- **conf**: Ensure reload doesn't overwrite config if reload in progress. The main process reads the configuration files and writes them to an anonymous file which is then read by the child processes. This commit ensures that the parent process doesn't start overwriting the anonymous file before the child processes have completed reading it, so that if two reloads are signalled in quick succession the child processes don't read corrupted configurations.

- **scheduler**: handle THREAD_READ/WRITE_ERROR in thread_cancel().

- **core**: only process startup/shutdown scripts in parent process. This commit also doesn't check the security of a startup script after a reload, since the script will not be run.

- **bfd**: handle checker/bfd interface same after reload as before. The global variable specified_event_processes is now cleared during a reload, so that it will be set based on the new configuration rather than the old configuration.

- **smtp**: Enhance smtp code. Extend FSM, remove code duplication, fix receive buffer overflowchecking.

- **scheduler**: Add FREE_ARG_ON_RELOAD option to thread_add_read()/thread_add_write(). When sending an SMTP message, there is an smtp_t object allocated, and the pointer to it is saved in the thread arg variable. If the thread is deleted when keepalived reloads, the smtp_t object needs to be freed. Previously it wasn't being freed resulting in a memory leak during reloads. This commit adds a THREAD_FREE_ARG_ON_RELOAD flag to thread_add_read() and thread_add_write(), so that when any such threads are freed, the smtp_t object pointed to by the arg can be freed. An alternative implementation would have been to add a cleanup function pointer to thread_add_...() calls, and that could be an option in future. This could handle both closing fds and freeing any allocated memory. It is possible that in the future other thread_add_...() functions may also need to support THREAD_FREE_ARG_ON_RELOAD.

## Fixes

- **ipvs**: Correct printf width and precision sepcifiers to be ints

- **ipvs**: Fix double free in MISC_CHECK if problems setting script user.

- **ipvs**: Fix freeing NULL in MISC_CHECK if no misc_path specied.

- **ipvs**: Fix segfault when unable to set default user for MISC_CHECK script.

- **ipvs**: free null pointer in check_udp.

- **vrrp**: Check address label length < IFNAMSIZ. Issue #1951 identified that in certain circumstances address labels did not work. While investigating that issue it was noticed that keepalived did not notice address labels that were too long, and also if the label was too long, it didn't terminate it with a NUL byte. With this commit keepalvied now checks that the address label is not too long, and it is is logs a config error and ignores the address. Previously the address would not be added by the kernel due to the label being too long, so the overall runtime functionality effectively remains the same.

- **vrrp**: Remove O0 optimisation from memcmp_constant_time and add noinline, noclone. Issue #1948 reported that setting the optimisation to O0 for function memcmp_constant_time() caused problems when using annocheck. It suggested that removing the optimize("O0") and adding noinline,noclone function attributes should produce the desired effect when using LTO. A check of the conde generated, when using GCC, confirmed that this is the case

- **vrrp**: Fix segfault when terminating due to config fault in checker/bfd process.

- **vrrp**: Fix weight initialisation of track_bfd entries in sync group.

- **vrrp**: Fix segfault when unicast_src_ip omitted.

- **lib**: Handle EINTR returned by epoll_wait(). Even though keepalived does not use asynchronous signal handlers, SIGSTOP causes epoll_wait() to return EINTR. Although we don't expect to be sent SIGSTOP it could happen, so we need to check for it.

- **lib**: Supress -Wstringop-truncation warnings for strcpy_safe().

- **lib**: Fix flags to mlockall for setting no_swap options.

- **build**: fix compiling with --disable-vrrp-auth or --disable-vrrp options.

- **build**: Stop spurious -Wstringop-overflow when using LTO. GCC, at least up to v11.1.1 produces spurious -Wstringop-truncation warnings when using Link Time Optimisation relating to function addattr_l(). Explicitly setting the noinline attribute stops those warnings, so this commit does so if LTO is in use.

- **build**: fix detecting if build is in keepalived git tree.

- **build**: Fix compilation if ipvlans not supported.

- **core**: Fix compiling on RHEL 9.
