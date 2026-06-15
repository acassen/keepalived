# Keepalived Configuration Synopsis

The Keepalived configuration file, by default `/etc/keepalived/keepalived.conf`,
is organised as a hierarchy of blocks and sub-blocks. Each block is delimited by a
`{` ... `}` pair, and comments start with `#` or `!` and run to the end of the
line.

The configuration is split into four families of blocks:

- **Global definitions** for daemon wide settings and notifications.
- **VRRP** for high availability, the `vrrp_instance` and `vrrp_sync_group` blocks.
- **LVS** for load balancing, the `virtual_server` and `real_server` blocks.
- **BFD** for the bidirectional forwarding detection sessions.

!!! note
    This page is a quick orientation that shows the skeleton of the main blocks
    and their most common keywords. The complete and authoritative list of every
    keyword, with its arguments and defaults, lives in the
    [keepalived.conf(5)](../keepalived-conf.md) reference, which the core team
    maintains with each release.

## Global definitions

```
global_defs {
    notification_email {
        admin@example.com
    }
    notification_email_from keepalived@example.com
    smtp_server 127.0.0.1
    smtp_connect_timeout 30
    router_id LVS_MAIN
    # send an email on every state transition
    smtp_alert
    # multicast group used for VRRP adverts (default is RFC assigned)
    vrrp_mcast_group4 224.0.0.18
    # bind the IPVS synchronisation daemon to an interface and an instance
    lvs_sync_daemon eth0 VI_1
}
```

router_id
:   Name identifying the director in notifications. The legacy `lvs_id` spelling is gone, use `router_id`.

notification_email / notification_email_from
:   Recipients and sender used for the SMTP alerts.

smtp_server / smtp_connect_timeout
:   SMTP relay and its connection timeout in seconds.

smtp_alert
:   Default state of the SMTP alerts for both VRRP and the checkers.

lvs_sync_daemon
:   Bind the IPVS connection synchronisation daemon to an interface and, optionally, a VRRP instance.

!!! info "Full reference"
    These are the keywords you reach for first. For every `global_defs` option,
    see [keepalived.conf(5) → Global definitions](../keepalived-conf.md#global-definitions).

## VRRP instances and sync groups

A `vrrp_instance` owns a set of virtual addresses and runs the VRRP election on an
interface. A `vrrp_sync_group` keeps several instances in the same state, so a
takeover moves a whole routing path at once.

```
vrrp_sync_group VG1 {
    group {
        VI_1
        VI_2
    }
    notify_master "/etc/keepalived/master.sh"
}

vrrp_instance VI_1 {
    state MASTER
    interface eth0
    virtual_router_id 51
    priority 150
    advert_int 1
    # VRRP protocol version, 2 (RFC3768) or 3 (RFC5798)
    version 2
    authentication {
        auth_type PASS
        auth_pass secret
    }
    virtual_ipaddress {
        192.168.200.10/24
        192.168.200.11/24
    }
    # unicast adverts instead of multicast
    # unicast_src_ip 10.0.0.1
    # unicast_peer {
    #     10.0.0.2
    # }
    track_interface {
        eth1
    }
    track_script {
        chk_haproxy
    }
    notify_master "/etc/keepalived/master.sh"
    notify_backup "/etc/keepalived/backup.sh"
    notify_fault  "/etc/keepalived/fault.sh"
}
```

state
:   Initial role, MASTER or BACKUP.

interface
:   Interface the instance runs on.

virtual_router_id
:   VRRP router id shared by the master and its backups, 1 to 255.

priority
:   Election priority, the highest wins, 1 to 255.

advert_int
:   Advertisement interval in seconds.

authentication
:   Legacy authentication block, `auth_type` PASS or AH. RFC5798 (version 3) does not use it.

virtual_ipaddress
:   The addresses carried by the instance and moved on takeover.

track_interface / track_script
:   Drop the instance to fault state when an interface goes down or a tracked script fails.

notify_master / notify_backup / notify_fault
:   Scripts run on each state transition.

!!! info "Full reference"
    The keywords above cover the common path. For every VRRP option, such as
    unicast peers, VMAC, tracking, GARP timing and native IPv6, see
    [keepalived.conf(5) → VRRP instance(s)](../keepalived-conf.md#vrrp-instances).

## Virtual servers and real servers

A `virtual_server` describes one LVS service, and each `real_server` is a backend
in its pool with a health checker attached.

```
virtual_server 192.168.200.15 80 {
    delay_loop 15
    # scheduler: rr wrr lc wlc lblc sh mh dh fo ovf lblcr sed nq twos
    lvs_sched wrr
    # forwarding method: NAT, DR or TUN
    lvs_method NAT
    persistence_timeout 50
    protocol TCP

    sorry_server 192.168.100.100 80

    real_server 192.168.100.2 80 {
        weight 2
        inhibit_on_failure
        HTTP_GET {
            url {
                path /index.html
                digest <md5-of-the-page>
            }
            connect_timeout 3
            retry 3
            delay_before_retry 2
        }
    }
}
```

delay_loop
:   Interval, in seconds, between two checks.

lvs_sched
:   Scheduler, classic alias `lb_algo`. See [IPVS Scheduling Algorithms](scheduling-algorithms.md).

lvs_method
:   Forwarding method NAT, DR or TUN, classic alias `lb_kind`.

persistence_timeout
:   Keep a client pinned to the same real server for this many seconds.

protocol
:   Service protocol, TCP, UDP or SCTP.

sorry_server
:   Server added to the pool when every real server is down.

real_server
:   A backend, with its weight and a health checker block.

weight
:   Relative capacity used by the weighted schedulers.

inhibit_on_failure
:   Set the weight to zero on failure instead of removing the server from the pool.

### Health checkers

A real server can carry one of the following checker blocks. They are described in
full in [keepalived.conf(5)](../keepalived-conf.md).

HTTP_GET / SSL_GET
:   Fetch one or more URLs and compare an MD5 digest of the response.

TCP_CHECK
:   Open a TCP connection to the service.

SMTP_CHECK
:   Connect to an SMTP server and complete the initial handshake.

DNS_CHECK
:   Query a DNS server for a record of a given type.

UDP_CHECK
:   Send a UDP packet, optionally requiring a specific reply.

PING_CHECK
:   Send an ICMP echo request.

FILE_CHECK
:   Read a value from a file watched with inotify.

BFD_CHECK
:   Track a BFD session run by the BFD process.

MISC_CHECK
:   Run an arbitrary script whose exit status drives the decision.

!!! info "Full reference"
    This is the common subset. For every `virtual_server` and `real_server`
    option, each checker's parameters and the LVS scheduler flags, see
    [keepalived.conf(5) → Virtual server(s)](../keepalived-conf.md#virtual-servers).

## Going further

This synopsis only scratches the surface. For BFD configuration, static addresses,
routes and rules, track files and processes, conditional configuration, parameter
substitution and every keyword of the blocks above, read the complete
[keepalived.conf(5)](../keepalived-conf.md) reference.
