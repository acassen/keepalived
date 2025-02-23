==========
KEEPALIVED
==========

:Date: 2024-06-13

NAME
====

keepalived - load-balancing and high-availability service

SYNOPSIS
========

**keepalived** [**-f**\ \|\ **--use-file**\ =FILE]
[**-P**\ \|\ **--vrrp**] [**-C**\ \|\ **--check**]
[**-B**\ \|\ **--no_bfd**] [**--all**] [**-l**\ \|\ **--log-console**]
[**-D**\ \|\ **--log-detail**]
[**-S**\ \|\ **--log-facility**\ ={0-7|local{0-7}|user|daemon}]
[**-g**\ \|\ **--log-file**\ =FILE] [**--flush-log-file**]
[**-G**\ \|\ **--no-syslog**] [**-X**\ \|\ **--release-vips**]
[**-V**\ \|\ **--dont-release-vrrp**]
[**-I**\ \|\ **--dont-release-ipvs**] [**-R**\ \|\ **--dont-respawn**]
[**-n**\ \|\ **--dont-fork**] [**-d**\ \|\ **--dump-conf**]
[**-p**\ \|\ **--pid**\ =FILE] [**-r**\ \|\ **--vrrp_pid**\ =FILE]
[**-T**\ \|\ **--genhash**] [**-c**\ \|\ **--checkers_pid**\ =FILE]
[**-a**\ \|\ **--address-monitoring**]
[**-b**\ \|\ **--bfd_pid**\ =FILE] [**-s**\ \|\ **--namespace**\ =NAME]
[**-e**\ \|\ **--all-config**] [**-i**\ \|\ **--config-id** id]
[**-x**\ \|\ **--snmp**] [**-A**\ \|\ **--snmp-agent-socket**\ =FILE]
[**-u**\ \|\ **--umask**\ =NUMBER] [**-m**\ \|\ **--core-dump**]
[**-M**\ \|\ **--core-dump-pattern**\ [=PATTERN]]
[**--signum**\ =SIGFUNC] [**-t**\ \|\ **--config-test**\ [=FILE]]
[**--perf**\ [={all|run|end}]] [**--debug**\ [=debug-options]]
[**--no-mem-check**] [**--ignore-sigint**] [**-v**\ \|\ **--version**]
[**-h**\ \|\ **--help**]

DESCRIPTION
===========

Keepalived provides simple and robust facilities for load-balancing and
high-availability. The load-balancing framework relies on the well-known
and widely used Linux Virtual Server (IPVS) kernel module providing
Layer4 load-balancing. Keepalived implements a set of checkers to
dynamically and adaptively maintain and manage a load-balanced server
pool according to their health. Keepalived also implements the VRRPv2
and VRRPv3 protocols to achieve high-availability with director
failover.

OPTIONS
=======

 **-f, --use-file**\ =FILE
   Use the specified configuration file. The default configuration file
   is "/etc/keepalived/keepalived.conf".

 **-P, --vrrp**
   Only run the VRRP subsystem. This is useful for configurations that
   do not use the IPVS load balancer.

 **-C, --check**
   Only run the healthcheck subsystem. This is useful for configurations
   that use the IPVS load balancer with a single director with no
   failover.

 **-B, --no_bfd**
   Don't run the BFD subsystem.

 **--all**
   Run all subsystems, even if they have no configuration.

 **-l, --log-console**
   Log messages to the local console. The default behavior is to log
   messages to syslog.

 **-D, --log-detail**
   Detailed log messages.

 **-S, --log-facility**\ ={0-7|local{0-7}|user|daemon}
   Set syslog facility to LOG_LOCAL[0-7], LOG_USER or LOG_DAEMON. The
   default syslog facility is LOG_DAEMON.

 **-g, --log-file**\ =FILE
   Write log entries to FILE. FILE will have \_vrrp, \_healthcheckers,
   and \_bfd inserted before the last '.' in FILE for the log output for
   those processes.

 **--flush-log-file**
   If using the -g option, the log file stream will be flushed after
   each write.

 **-G, --no-syslog**
   Do not write log entries to syslog. This can be useful if the rate of
   writing log entries is sufficiently high that syslog will rate limit
   them, and the -g option is used instead.

 **-X, --release-vips**
   Drop VIP on transition from signal.

 **-V, --dont-release-vrrp**
   Don't remove VRRP VIPs and VROUTEs on daemon stop. The default
   behavior is to remove all VIPs and VROUTEs when keepalived exits.

 **-I, --dont-release-ipvs**
   Don't remove IPVS topology on daemon stop. The default behavior it to
   remove all entries from the IPVS virtual server table when keepalived
   exits.

 **-R, --dont-respawn**
   Don't respawn child processes. The default behavior is to restart the
   VRRP and checker processes if either process exits.

 **-n, --dont-fork**
   Don't fork the daemon process. This option will cause keepalived to
   run in the foreground.

 **-d, --dump-conf**
   Dump the configuration data.

 **-p, --pid**\ =FILE
   Use the specified pidfile for the parent keepalived process. The
   default pidfile for keepalived is "/run/keepalived.pid", unless a
   network namespace is being used. See **NAMESPACES** below for more
   details.

 **-r, --vrrp_pid**\ =FILE
   Use the specified pidfile for the VRRP child process. The default
   pidfile for the VRRP child process is "/run/keepalived_vrrp.pid",
   unless a network namespace is being used.

 **-T, --genhash**
   Enter genhash utility mode. Previous versions of keepalived were
   shipped with a dedicated genhash utility. genhash is now part of the
   mainline code. We keep compatibility with previous genhash utility
   command line option. For more information please refer to the
   genhash(1) manpage.

 **-c, --checkers_pid**\ =FILE
   Use the specified pidfile for checkers child process. The default
   pidfile for the checker child process is
   "/run/keepalived_checkers.pid" unless a network namespace is being
   used.

 **-a, --address-monitoring**
   Log all address additions/deletions reported by netlink.

 **-b, --bfd_pid**\ =FILE
   Use the specified pidfile for the BFD child process. The default
   pidfile for the BFD child process is "/run/keepalived_bfd.pid" unless
   a network namespace is being used.

 **-s, --namespace**\ =NAME
   Run keepalived in network namespace NAME. See **NAMESPACES** below
   for more details.

 **-e, --all-config**
   Don't load if any configuration file is missing or cannot be read.

 **-i, --config-id ID**
   Use configuration id ID, for conditional configuration (defaults to
   hostname without the domain name).

 **-x, --snmp**
   Enable the SNMP subsystem.

 **-A, --snmp-agent-socket=FILE**
   Use the specified socket for connection to SNMP master agent.

 **-u, --umask=NUMBER**
   The umask specified in the usual numeric way - see man umask(2)

 **-m, --core-dump**
   Override the RLIMIT_CORE hard and soft limits to enable keepalived to
   produce a coredump in the event of a segfault or other failure. This
   is most useful if keepalived has been built with 'make debug'. Core
   dumps will be created in /, unless keepalived is run with the
   --dont-fork option, in which case they will be created in the
   directory from which keepalived was run, or they will be created in
   the directory of a configuraton file if the fault occurs while
   reading the file.

 **-M, --core-dump-pattern[=PATTERN]**
   Sets option --core-dump, and also updates
   /proc/sys/kernel/core_pattern to the pattern specified, or 'core' if
   none specified. Provided the parent process doesn't terminate
   abnormally, it will restore /proc/sys/kernel/core_pattern to its
   original value on exit.

**Note: This will also affect any other process producing a core dump
while keepalived is running.**

 **--signum=PATTERN**
   Returns the signal number to use for STOP, RELOAD, DATA, STATS,
   STATS_CLEAR, JSON and TDATA. For example, to stop keepalived running,
   execute:

   ::

      kill -s $(keepalived --signum=STOP) $(cat /run/keepalived.pid)

 **-t, --config-test[=FILE]**
   Keepalived will check the configuration file and exit with non-zero
   exit status if there are errors in the configuration, otherwise it
   exits with exit status 0 (see **Exit status below for details).**

Rather that writing to syslog, it will write diagnostic messages to
stderr unless file is specified, in which case it will write to the
file.

 **--perf[={all|run|end}]**
   Record perf data for vrrp process. Data will be written to
   /perf_vrrp.data. The data recorded is for use with the perf tool.

 **--no-mem-check**
   Disable malloc() etc mem-checks if they have been compiled into
   keepalived.

 **--ignore-sigint**
   Disable SIGINT handling (defaults to terminating keepalived). This is
   needed for running keepalived under GDB.

 **--debug[=debug-options]]**
   | Enables debug options if they have been compiled into keepalived.
     *debug-options* **is made up of a sequence of strings of the form
     Ulll.**
   | The upper case letter specifies the debug option, and the lower
     case letters specify for which processes the option is to be
     enabled.
   | If a debug option is not followed by any lower case letters, the
     debug option is enabled for all processes.

..

   The characters to identify the processes are:

   === ===============
   Chr Process
   === ===============
   p   Parent process
   b   BFD process
   c   Checker process
   v   VRRP process
   === ===============

   The characters used to identify the debug options are:

   === =====================================
   Chr Debug option
   === =====================================
   D   Epoll thread dump
   E   Epoll debug
   F   VRRP fd debug
   N   Netlink timers
   P   Network timestamp
   X   Regex timers
   M   Email alert debug
   T   Timer debug
   S   TSM debug
   R   Regex debug
   B   Smtp connect debug
   U   Checksum diagnostics
   O   Track process debug
   A   Track process debug with extra detail
   C   Parser (config) debug
   H   Checker debug
   Z   Memory alloc/free error debug
   G   VRRP recvmsg() debug
   J   VRRP recvmsg() log rx data
   V   Script debugging
   K   Dump keywords
   === =====================================

   **Example: --debug=DvEcvNR**

 **-v, --version**
   Display the version and exit.

 **-h, --help**
   Display this help message and exit.

Exit status:
------------

0
   if OK

1
   if unable to malloc memory

2
   if cannot initialise subsystems

3
   if running with --config-test and configuration cannot be run

4
   if running with --config-test and there are configuration errors but
   keepalived will run after modifying the configuration

5
   if running with --config-test and script security hasn't been enabled
   but scripts are configured.

NAMESPACES
==========

**keepalived** can be run in a network namespace (see
**keepalived.conf(5) for configuration details). When** run in a network
namespace, a local mount namespace is also created, and
/run/keepalived/keepalived_NamespaceName is mounted on /run/keepalived.
By default, pid files with the usual default names are then created in
/run/keepalived from the perspective of a process in the mount
namespace, and they will be visible in
/run/keepalived/keepalived_NamespaceName for a process running in the
default mount namespace.

SIGNALS
=======

**keepalived** reacts to a set of signals. You can send a signal to the
parent **keepalived** process using the following:

::

   kill -SIGNAL $(cat /run/keepalived.pid)

or better:

::

   kill -s $(keepalived --signum=SIGFUNC) $(cat /run/keepalived.pid)

Note that if the first option is used, -SIGNAL must be replaced with the
actual signal you are trying to send, e.g. with HUP. So it then becomes:

::

   kill -HUP $(cat /run/keepalived.pid)

Signals other than for STOP, RELOAD, DATA and STATS may change depending
on the kernel, and also what functionality is included in the version of
the keepalived depending on the build options used.

**HUP or SIGFUNC=RELOAD**
   This causes **keepalived** to close down all interfaces, reload its
   configuration, and start up with the new configuration.

   **Note:** If a virtual_ipaddress, virtual_route or virtual_rule is
   being moved from one VRRP instance to another one, two reloads will
   be necessary, the first to remove the virtual ipaddress/route/rule,
   and the second reload to add it to the VRRP instance it is now to be
   configured on. Failing to do this can result in the
   ipaddress/route/rule not being configured on the new instance if both
   the old and new instances are in master state. It will usually work
   with a single reload, however, if either of the VRRP instances is not
   in MASTER state or if the VRRP instance the ipaddress/route/rule the
   VRRP instance is being **added to** is later in the original
   configuration file than the instance it is being removed from.

**TERM\ , INT or SIGFUNC=STOP**
   **keepalived** will shut down.

**USR1 or SIGFUNC=DATA**
   Write configuration data to **/tmp/keepalived.data**

**USR2 or SIGFUNC=STATS**
   Write statistics info to **/tmp/keepalived.stats**

**SIGFUNC=STATS_CLEAR**
   Write statistics info to **/tmp/keepalived.stats** and clear the
   statistics counters

**SIGFUNC=JSON**
   Write configuration data in JSON format to **/tmp/keepalived.json**

**SIGFUNC=TDATA**
   This causes **keepalived** to write the current state of its internal
   threads to the log

USING KEEPALIVED WITH FIREWALLD
===============================

If you are running a firewall (see **firewalld**\ (8)\ **)** you must
allow VRRP protocol traffic through the firewall. For example if this
instance of **keepalived(8)** has a peer node on IPv4 address
192.168.0.1:

::

   # firewall-cmd \
       --add-rich-rule="rule family='ipv4' \
                        source address='192.168.0.1' \
                        protocol value='vrrp' accept" --permanent
   # firewall-cmd --reload

SEE ALSO
========

**keepalived.conf(5), ipvsadm(8)**

AUTHOR
======

This man page was written by Ryan O'Hara <rohara@redhat.com>
