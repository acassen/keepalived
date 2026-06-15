# Release 2.1.4 `10th July 2020`

This release extend some documentation elements. Some fix for the building process. DNS_CHECK fix and extensions. Properly handle ipvs_sync_daemon.

## New

- **conf**: Add support to ${_HASH} and ${_BANG} configuration options. This feature adds ${_HASH} and ${_BANG} which are replaced with # and ! respectively, without a comment being started. This makes it easy to create configuration files with a large number of optional elements that can be enabled or disabled by simple definition changes. For example, one could have

    ```
    $TEST=${_HASH}
    $TEST test config
    ```

    which would disable "test config" since it would be commented out.

    Changing the definition of $TEST to be

    ```
    $TEST=
      or even
    $TEST=#${_HASH}
    ```

    would enable "test config".

- **conf**: Allow 'include' statement to be on any line in config files. Using an include statement was used in the middle of a virtual_ipaddress block didn't work. It turned out that 'include' could not be used in any block that was a list of multiple entries, e.g. routes, rules, email addresses. This extension restructures the way handling to opening and closing of config files is handled, so that include statements can appear on any line of the config files.

## Improvements

- **script**: Extend mk_if script for setting up test environment much more flexible.

- **manpage**: Some more detailed explanations and corrections.

- **doc**: Update build package requirements for Debian based distributions.

- **doc**: Remove garp_interval and gna_interval from vrrp_instance.

- **memory**: Add log_mem_chk_message() to help --enable-mem-check debugging. log_mem_chk_message() allows the application to write entries to the mem_check log to assist with identifying the location in the code where a malloc/free problem is occurring.

- **debug**: Add nanosecond timestamping when logging to a file.

- **vrrp**: Update local definition of RTPROTO_KEEPALIVED. Linux 5.8 adds RTPROTO_KEEPALIVED, the value the kernel has assigned to RTPROTO_KEEPALIVED is 18.

## Fixes

- **vrrp**: Fix maintaining list of processes we are interested in. While tracking processes, after adding a new process to the list of active processes, it was being deleted immediately.

- **vrrp**: Fix building on Linux 3.15 with nftables support.

- **configure**: Fix --with-kernel-dir option

- **build**: Fix build with kernel v4.15 headers prior to 4.15.7.

- **build**: Fix building with libc's that return NULL for malloc(0).

- **check**: Fix DNS_CHECK to correctly handle request when using the default dns name.

- **check**: Fix DNS_CHECK malloc errors re name. If the name wasn't specified, on exit or reload keepalived to attempt to free memory that hadn't been obtained from malloc. If name was specified more than once, the mallocs for the earlier names were not freed.

- **check**: Fix DNS_CHECK names to not allow empty labels.

- **check**: Fix UDP_CHECK failure causing fd leak.

- **core**: Fix a couple of free()s which should have been FREE()s.

- **parser**: fix handling ~SEQ in multiline definition.

- **parser**: fix multiple command line substitutions/conditions.

- **bfd**: Fix using IPv6 (bind was failing).

- **build**: Fix building RPM with json enabled.

- **ipvs**: Fix configuring of sync daemon. The sync daemon used to be either master or backup, but an option was added to allow it to run in both master and backup mode, although this was still all handled in the vrrp process. There was a race condition when using both master and backup because the checker process was stopping the IPVS sync at startup, and the VRRP process was starting it. This fix changes the way it works, so that the VRRP process only handles the sync daemon if it is set to track a VRRP instance, and if the daemon runs in both master and backup mode, it is handled by the checker process. This fix also resolves issues when reloading the config if the sync daemon configuration is changed. Finally, lvs_timeouts are moved from being handled by the VRRP process to the checker process, values are updated after a reload, and the original values are read before any values are changed, and those values are restored on exit, or when no longer configured after a reload.
