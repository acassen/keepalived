############################
Keepalived programs synopsis
############################

Keepalived package comes with 2 programs.

keepalived daemon
*****************

The keepalived command line arguments are:

.. glossary::

    -f, --use-file=FILE
        Use the specified configuration file. The default configuration file is "/etc/keepalived/keepalived.conf".

    -P, --vrrp
        Only run the VRRP subsystem. This is useful for configurations that do not use IPVS load balancer.

    -C, --check
        Only run the healthcheck subsystem. This is useful for configurations that use the IPVS load balancer with a single director with no failover.

    -l, --log-console
        Log messages to the local console. The default behavior is to log messages to syslog.

    -D, --log-detail
        Detailed log messages.

    -S, --log-facility=[0-7]
        Set syslog facility to LOG_LOCAL[0-7]. The default syslog facility is LOG_DAEMON.

    -V, --dont-release-vrrp
        Don’t remove VRRP VIPs and VROUTEs on daemon stop. The default behavior is to remove all VIPs and VROUTEs when keepalived exits

    -I, --dont-release-ipvs
        Don’t remove IPVS topology on daemon stop. The default behavior is to remove all entries from the IPVS virtual server table on when keepalived exits.

    -R, --dont-respawn
        Don’t respawn child processes. The default behavior is to restart the VRRP and checker processes if either process exits.

    -n, --dont-fork
        Don’t fork the daemon process. This option will cause keepalived to run in the foreground.

    -d, --dump-conf
        Dump the configuration data.

    -p, --pid=FILE
        Use specified pidfile for parent keepalived process. The default pidfile for keepalived is "/var/run/keepalived.pid".

    -r, --vrrp_pid=FILE
        Use specified pidfile for VRRP child process. The default pidfile for the VRRP child process is "/var/run/keepalived_vrrp.pid".

    -c, --checkers_pid=FILE
        Use specified pidfile for checkers child process. The default pidfile for the checker child process is "/var/run/keepalived_checkers.pid".

    -x, --snmp
        Enable SNMP subsystem.

    -v, --version
        Display the version and exit.

    -h, --help
        Display this help message and exit.

genhash utility
***************

The ``genhash`` binary is used to generate digest strings. The genhash command
line arguments are:

.. glossary::

    --use-ssl, -S
          Use SSL to connect to the server.

    --server <host>, -s
          Specify the ip address to connect to.

    --port <port>, -p
          Specify the port to connect to.

    --url <url>, -u
          Specify the path to the file you want to generate the hash of.

    --use-virtualhost <host>, -V
          Specify the virtual host to send along with the HTTP headers.

    --hash <alg>, -H
          Specify the hash algorithm to make a digest of the target page.   Consult  the
          help screen for list of available ones with a mark of the default one.

    --verbose, -v
          Be verbose with the output.

    --help, -h
          Display the program help screen and exit.

    --release, -r
          Display the release number (version) and exit.

Running Keepalived daemon
*************************

To run Keepalived simply type::

    [root@lvs tmp]# /etc/rc.d/init.d/keepalived.init start
    Starting Keepalived for LVS:                            [ OK ]

All daemon messages are logged through the Linux syslog. If you start Keepalived with the “dump configuration data” option, you should see in your /var/log/messages (on Debian this may be */var/log/daemon.log* depending on your syslog configuration) something like this::

    Jun 7 18:17:03 lvs1 Keepalived: Starting Keepalived v0.6.1 (06/13, 2002)
    Jun 7 18:17:03 lvs1 Keepalived: Configuration is using : 92013 Bytes
    Jun 7 18:17:03 lvs1 Keepalived: ------< Global definitions >------
    Jun 7 18:17:03 lvs1 Keepalived: LVS ID = LVS_PROD
    Jun 7 18:17:03 lvs1 Keepalived: Smtp server = 192.168.200.1
    Jun 7 18:17:03 lvs1 Keepalived: Smtp server connection timeout = 30
    Jun 7 18:17:03 lvs1 Keepalived: Email notification from = keepalived@domain.com
    Jun 7 18:17:03 lvs1 Keepalived: Email notification = alert@domain.com
    Jun 7 18:17:03 lvs1 Keepalived: Email notification = 0633556699@domain.com
    Jun 7 18:17:03 lvs1 Keepalived: ------< SSL definitions >------
    Jun 7 18:17:03 lvs1 Keepalived: Using autogen SSL context
    Jun 7 18:17:03 lvs1 Keepalived: ------< LVS Topology >------
    Jun 7 18:17:03 lvs1 Keepalived: System is compiled with LVS v0.9.8
    Jun 7 18:17:03 lvs1 Keepalived: VIP = 10.10.10.2, VPORT = 80
    Jun 7 18:17:03 lvs1 Keepalived: VirtualHost = www.domain1.com
    Jun 7 18:17:03 lvs1 Keepalived: delay_loop = 6, lb_algo = rr
    Jun 7 18:17:03 lvs1 Keepalived: persistence timeout = 50
    Jun 7 18:17:04 lvs1 Keepalived: persistence granularity = 255.255.240.0
    Jun 7 18:17:04 lvs1 Keepalived: protocol = TCP
    Jun 7 18:17:04 lvs1 Keepalived: lb_kind = NAT
    Jun 7 18:17:04 lvs1 Keepalived: sorry server = 192.168.200.200:80
    Jun 7 18:17:04 lvs1 Keepalived: RIP = 192.168.200.2, RPORT = 80, WEIGHT = 1
    Jun 7 18:17:04 lvs1 Keepalived: RIP = 192.168.200.3, RPORT = 80, WEIGHT = 2
    Jun 7 18:17:04 lvs1 Keepalived: VIP = 10.10.10.3, VPORT = 443
    Jun 7 18:17:04 lvs1 Keepalived: VirtualHost = www.domain2.com
    Jun 7 18:17:04 lvs1 Keepalived: delay_loop = 3, lb_algo = rr
    Jun 7 18:17:04 lvs1 Keepalived: persistence timeout = 50
    Jun 7 18:17:04 lvs1 Keepalived: protocol = TCP
    Jun 7 18:17:04 lvs1 Keepalived: lb_kind = NAT
    Jun 7 18:17:04 lvs1 Keepalived: RIP = 192.168.200.4, RPORT = 443, WEIGHT = 1
    Jun 7 18:17:04 lvs1 Keepalived: RIP = 192.168.200.5, RPORT = 1358, WEIGHT = 1
    Jun 7 18:17:05 lvs1 Keepalived: ------< Health checkers >------
    Jun 7 18:17:05 lvs1 Keepalived: 192.168.200.2:80
    Jun 7 18:17:05 lvs1 Keepalived: Keepalive method = HTTP_GET
    Jun 7 18:17:05 lvs1 Keepalived: Connection timeout = 3
    Jun 7 18:17:05 lvs1 Keepalived: Nb get retry = 3
    Jun 7 18:17:05 lvs1 Keepalived: Delay before retry = 3
    Jun 7 18:17:05 lvs1 Keepalived: Checked url = /testurl/test.jsp,
    Jun 7 18:17:05 lvs1 Keepalived: digest = 640205b7b0fc66c1ea91c463fac6334d
    Jun 7 18:17:05 lvs1 Keepalived: 192.168.200.3:80
    Jun 7 18:17:05 lvs1 Keepalived: Keepalive method = HTTP_GET
    Jun 7 18:17:05 lvs1 Keepalived: Connection timeout = 3
    Jun 7 18:17:05 lvs1 Keepalived: Nb get retry = 3
    Jun 7 18:17:05 lvs1 Keepalived: Delay before retry = 3
    Jun 7 18:17:05 lvs1 Keepalived: Checked url = /testurl/test.jsp,
    Jun 7 18:17:05 lvs1 Keepalived: digest = 640205b7b0fc66c1ea91c463fac6334c
    Jun 7 18:17:05 lvs1 Keepalived: Checked url = /testurl2/test.jsp,
    Jun 7 18:17:05 lvs1 Keepalived: digest = 640205b7b0fc66c1ea91c463fac6334c
    Jun 7 18:17:06 lvs1 Keepalived: 192.168.200.4:443
    Jun 7 18:17:06 lvs1 Keepalived: Keepalive method = SSL_GET
    Jun 7 18:17:06 lvs1 Keepalived: Connection timeout = 3
    Jun 7 18:17:06 lvs1 Keepalived: Nb get retry = 3
    Jun 7 18:17:06 lvs1 Keepalived: Delay before retry = 3
    Jun 7 18:17:06 lvs1 Keepalived: Checked url = /testurl/test.jsp,
    Jun 7 18:17:05 lvs1 Keepalived: digest = 640205b7b0fc66c1ea91c463fac6334d
    Jun 7 18:17:06 lvs1 Keepalived: Checked url = /testurl2/test.jsp,
    Jun 7 18:17:05 lvs1 Keepalived: digest = 640205b7b0fc66c1ea91c463fac6334d
    Jun 7 18:17:06 lvs1 Keepalived: 192.168.200.5:1358
    Jun 7 18:17:06 lvs1 Keepalived: Keepalive method = TCP_CHECK
    Jun 7 18:17:06 lvs1 Keepalived: Connection timeout = 3
    Jun 7 18:17:06 lvs1 Keepalived: Registering Kernel netlink reflector

