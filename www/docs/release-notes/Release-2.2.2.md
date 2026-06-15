# Release 2.2.2 `05th March 2021`

This release fix some minor issues and migrate from Travis-Ci to GitHub Actions. Add support to LGTM Continuous security analysis.

## New

- **core**: Handle SELinux denying access to memfd files. If running in an SELinux controlled environment, permission needs to be granted to a confined process to be able to create, read and write memfd files. This commit detects access being denied to a memfd file, and if so uses an unnamed temporary file in the run filesystem instead. In particular, the following SELinux permissions are needed:

    ```
    allow keepalived_t tmpfs_t:file { getattr open read write };
    ```

- **systemd**: Use an eventfd to notify parent of reload completion. keepalived was using 3 different signals (one for each child process) to notify the parent parent process that they had completed reloading. This commit changes that to use a single eventfd for all child processes to notify the parent of completion.

- **build**: Remove RHEL6 RPM creation support.

- **build**: Remove Support to Travis-CI. Travis's offering of free credits is a hollow offer. Those guys are no longer good for OpenSource !

- **build**: Add support to GitHub Actions to takeover previous Travis-CI jobs.

- **build**: Add support to LGTM Continuous security analysis.

## Improvements

- **core**: Set default log facility to LOG_DAEMON.

- **core**: Add nftables_ipvs for optimised virtual_server_group handling.

- **core**: Remove support to old kernel. This makes code more readable and we keep aligned to all major LTS distros. It reduces ifdef use.

- **core**: Fix all coverity identified issues.

- **core**: add --with-default-runtime-options option. --with-default-runtime-options configure option sets KEEPALIVED_OPTIONS in /etc/sysconfig/keepalived

- **core**: misc cosmetics.

- **doc**: Add note to man page re moving VIP between VRRP instances.

- **doc**: Tidy up and update manpage.

- **build**: Set file timestamps in tar files based on their git commit times.

- **build**: Remove code supporting TRUNCATE_FILE_AFTER_READ. The TRUNCATE_FILE_AFTER_READ conditional compilation option cannot be used since the configuration is needed to be available in case a keepalived child process abnormally terminates (e.g. due to a segfault) and is restarted by the parent process.

- **build**: Improve RPM file generation.

## Fixes

- **core**: If using systemd with notify support, don't fork. Add the --dont-fork command line option to ExecStart in the keepalived.service file if using systemd with Type=notify.

- **core**: Fix and standardize include guards for header files.

- **build**: Resolve compiler warnings in 32 bit systems (Raspberry Pi).

- **core**: Fix handling systemd notify. The handling of the child processes signalling the parent process that they had completed reading the config file copy was not working reliably. The problem was that all child processes were using the same signal number to notify the parent, and so if more than one child process signalled the parent before the parent had read the first signal, one of the signals was lost. As a temporary measure make the child processes use different signal numbers. This may be changed in future to avoid the use of signals, such as using an eventfd, but any change will be internal to keepalived.

- **build**: Correct some conditional compilation checks.

- **debug**: Fix building with --enable-one-process-debug.

- **ipvs**: Fix updating real server weights changed on reload.

- **vrrp**: Fix issue when reload after vip is moved from one vrrp instance to another.

- **vrrp**: Don't remove unweighted track_file/if/bfd from sync group members.
