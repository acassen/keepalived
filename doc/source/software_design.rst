###############
Software Design
###############


Keepalived is written in pure ANSI/ISO C. The software is articulated around a
central I/O multiplexer that provides realtime networking design. The main
design focus is to provide a homogenous modularity between all elements. This
is why a core library was created to remove code duplication. The goal is to
produce a safe and secure code, ensuring production robustness and stability.

To ensure robustness and stability, daemon is split into 4 distinct processes:

* A minimalistic parent process in charge with forked children process monitoring.
* Up to three child processes, one responsible for VRRP framework, one for
  healthchecking and IPVS configuration, and one for BFD.

Each child process has its own scheduling I/O multiplexer, that way VRRP
scheduling jitter is optimized since VRRP and BFD scheduling are more sensitive/critical
than healthcheckers. This split design minimalizes for healthchecking the usage
of foreign libraries and minimalizes its own action down to an idle mainloop in
order to avoid malfunctions caused by itself. 

The parent process monitoring framework is called watchdog. If the parent process
detects that a child has terminated it simply restarts child process::

    PID         111     Keepalived  <-- Parent process monitoring children
                112     \_ Keepalived   <-- VRRP child
                113     \_ Keepalived   <-- Healthchecking child
                114     \_ Keepalived   <-- BFD child

Kernel Components
*****************

Keepalived uses four Linux kernel components:

1. LVS Framework: Uses the getsockopt and setsockopt calls to get and set options on sockets.
#. Netfilter Framework: IPVS code that supports NAT and Masquerading.
#. Netlink Interface: Sets and removes VRRP virtual IPs on network interfaces.
#. Multicast:  VRRP advertisements are sent to the reserved VRRP MULTICAST group (224.0.0.18).


Atomic Elements
***************

.. image:: images/software_design.png
   :align: center
   :scale: 80%
   :alt: keepalived software design

Control Plane
=============

Keepalived configuration is done through the file keepalived.conf. A compiler
design is used for parsing. Parser work with a keyword tree hierarchy for
mapping each configuration keyword with specifics handler. A central
multi-level recursive function reads the configuration file and traverses the
keyword tree. During parsing, configuration file is translated into an internal
memory representation.

Scheduler - I/O Multiplexer
===========================

For each process, all the events are scheduled into the same process.
Keepalived is network routing software, it is so close to I/O. The design used
here is a central epoll_wait(...) that is in charge of scheduling all internal
tasks. POSIX thread libs are NOT used. This framework provides its own thread
abstraction optimized for networking purpose.

Memory Management
=================

This framework provides access to some generic memory management functions like
allocation, reallocation, release,... This framework can be used in two modes:
normal_mode & debug_mode. When using debug_mode it provides a strong way to
eradicate and track memory leaks. This low-level env provides buffer under-run
protection by tracking allocation and release of memory. All the buffers used are
length fixed to prevent against eventual buffer-overflow.

Core Components
===============

This framework defines some common and global libraries that are used in all the
code. Those libraries are html parsing, link-list, timer, vector, string
formating, buffer dump, networking utils, daemon management, pid handling, 
low-level TCP layer4. The goal here is to factorize code to the max to limit as
much as possible code duplication to increase modularity.

Checkers
========

This is one of the main Keepalived functionality. Checkers are in charge of
adding, removing and changing the weight of realservers. There are several types
of checkers, most of which relate to realserver healthchecking. A checker tests
if realserver is alive, this test either ends on a binary decision: remove or
add realserver from/into the LVS topology, or changing the weight of the realserver.
The internal checker design is realtime networking software, it uses a fully
multi-threaded FSM design (Finite State Machine). This checker stack provides
LVS topology manipulation according to layer4 to layer5/7 test results. It's run
in an independent process monitored by the parent process.

VRRP Stack
==========

The other most important Keepalived functionality. VRRP (Virtual Router
Redundancy Protocol: RFC2338/RFC3768/RFC5798) is focused on director takeover,
it provides low-level design for router backup. It implements full IETF RFC5798
standard with some provisions and extensions for LVS and Firewall design (with
legacy support for RFC2338, i.e. authentication). It implements
the vrrp_sync_group extension that guarantees persistence routing path after
protocol takeover. It implements IPSEC-AH using MD5-96bit crypto provision for
securing protocol adverts exchange. For more information on VRRP please read
the RFC. Important things: VRRP code can be used without the LVS support, it
has been designed for independent use. It's run in an independent process
monitored by parent process.

BFD Stack
==========

An implementation of BFD (Bidirectional Forwarding and Detection: RFC5880). This
can be used by both the VRRP process as a tracker for VRRP instance(s) and by the
checker process as a checker for realserver.
It's run in an independent process monitored by parent process.

System Call
===========

This framework offers the ability to launch extra system script. It is mainly
used in the MISC checker. In VRRP framework it provides the ability to launch
extra script during protocol state transition. The system call is done into a
forked process to not pertube the global scheduling timer.

Netlink Reflector
=================

Same as IPVS wrapper. Keepalived works with its own network interface
representation. IP address and interface flags are set and monitored through
kernel Netlink channel. The Netlink messaging sub-system is used for setting
VRRP VIPs. On the other hand, the Netlink kernel messaging broadcast capability
is used to reflect into our userspace Keepalived internal data representation
any events related to interfaces. So any other userspace (others program)
netlink manipulation is reflected our Keepalived data representation via
Netlink Kernel broadcast (RTMGRP_LINK & RTMGRP_IPV4_IFADDR).

SMTP
====

The SMTP protocol is used for administration notification. It implements the
IETF RFC821 using a multi-threaded FSM design. Administration notifications are
sent for healthcheckers activities and VRRP protocol state transition. SMTP is
commonly used and can be interfaced with any other notification sub-system such
as GSM-SMS, pagers, etc.

IPVS Wrapper
============

This framework is used for sending rules to the Kernel IPVS code. It provides
translation between Keepalived internal data representation and IPVS rule_user
representation. It uses the IPVS libipvs to keep generic integration with IPVS
code.

IPVS
====

The Linux Kernel code provided by Wensong from LinuxVirtualServer.org
OpenSource Project. IPVS (IP Virtual Server) implements transport-layer load
balancing inside the Linux kernel, also referred to as Layer-4 switching.

NETLINK
=======

The Linux Kernel code provided by Alexey Kuznetov with its very nice advanced
routing framework and sub-system capabilities. Netlink is used to transfer
information between kernel and user-space processes.  It consists of a standard
sockets-based interface for userspace processes and an internal kernel API for
kernel modules.

Syslog
======

All keepalived daemon notification messages are logged using the syslog service.


Healthcheck Framework
*********************

Each health check is registered to the global scheduling framework.  These
health check worker threads implement the following types of health checks:

.. glossary::

    TCP_CHECK
        Working at layer4. To ensure this check, we use a TCP Vanilla check using nonblocking/timed-out TCP connections. If the remote server does not reply to this request (timed-out), then the test is wrong and the server is removed from the server pool.

    HTTP_GET
        Working at layer5. Performs a HTTP GET to a specified URL. The HTTP GET result is then summed using the MD5 algorithm. If this sum does not match with the expected value, the test is wrong and the server is removed from the server pool. This module implements a multi-URL get check on the same service. This functionality is useful if you are using a server hosting more than one application servers. This functionality gives you the ability to check if an application server is working properly. The MD5 digests are generated using the genhash utility (included in the keepalived package).

    SSL_GET
        Same as HTTP_GET but uses a SSL connection to the remote webservers.

    MISC_CHECK
        This check allows a user-defined script to be run as the health checker. The result must be 0 or 1. The script is run on the director box and this is an ideal way to test in-house applications. Scripts that can be run without arguments can be called using the full path (i.e. /path_to_script/script.sh). Those requiring arguments need to be enclosed in double quotes (i.e. “/path_to_script/script.sh arg 1 ... arg n ”)

    SMTP_CHECK
        This check ensures that an SMTP server can be connected to and the initial SMTP handshake completed.

    DNS_CHECK
        This check queries a DNS server for the configured name of the specified type (e.g. A, AAAA, MX record).

    BFD_CHECK
        This is updated by the BFD process, and allows a realserver to be removed if the BFD session goes down.

    UDP_CHECK
        This check sends a UDP packet to the specified remote host/port. It can be configured to require a specific response, or to fail if an ICMP error is returned.

    PING_CHECK
        This check sends and ICMP echo request and will fail if an appropriate ICMP echo response is not received.

    FILE_CHECK
        This check monitors a file using inotify(). If the file is modified or created, its contents are read and interpreted as a numeric value. This can either indicate the realserver should be removed, or its weight changed, depending on the configuration.

The goal for Keepalived is to define a generic framework easily extensible for adding new checkers modules. If you are interested in the development of existing or new checkers, have a look at the *keepalived/check* and *keepalived/trackers* directories in the source:

https://github.com/acassen/keepalived/tree/master/keepalived/check

Failover (VRRP) Framework
*************************

Keepalived implements the VRRP protocol for director failover. Within the
implemented VRRP stack, the VRRP Packet dispatcher is responsible for
demultiplexing specific I/O for each VRRP instance.

From RFC5798, VRRP is defined as::

    “VRRP specifies an election protocol that dynamically assigns
    responsibility for a virtual router to one of the VRRP routers on a LAN.
    The VRRP router controlling the IPv4 or IPv6 address(es) associated with
    a virtual router is called the Master, and it forwards packets sent to
    these IPv4 or IPv6 addresses.  VRRP Master routers are configured with
    virtual IPv4 or IPv6 addresses, and VRRP Backup routers infer the
    address family of the virtual addresses being carried based on the
    transport protocol.  Within a VRRP router, the virtual routers in
    each of the IPv4 and IPv6 address families are a domain unto
    themselves and do not overlap.  The election process provides dynamic
    failover in the forwarding responsibility should the Master become
    unavailable.  For IPv4, the advantage gained from using VRRP is a
    higher-availability default path without requiring configuration of
    dynamic routing or router discovery protocols on every end-host.  For
    IPv6, the advantage gained from using VRRP for IPv6 is a quicker
    switchover to Backup routers than can be obtained with standard IPv6
    Neighbor Discovery mechanisms.” [rfc5798]

.. note::
    This framework is LVS independent, so you can use it for LVS director
    failover, even for other Linux routers needing a Hot-Standby protocol.
    This framework has been completely integrated in the Keepalived daemon for
    design & robustness reasons.

The main functionalities provided by this framework are:

* Failover: The native VRRP protocol purpose, based on a roaming set of VRRP VIPs.
* VRRP Instance synchronization: We can specify a state monitoring between 2 or more VRRP Instances, also known as a *VRRP sync group*. It guarantees that the VRRP Instances remain in the same state. The synchronized instances monitor each other.
* Nice Fallback
* Advert Packet integrity: Using IPSEC-AH ICV.
* System call: During a VRRP state transition, an external script/program may be called.


Note on Using VRRP with Virtual MAC Address
===========================================

To reduce takeover impact, some networking environment would require using
VRRP with VMAC address. To reach that goal Keepalived VRRP framework implements
VMAC support by the invocation of 'use_vmac' keyword in configuration file.

Internally, Keepalived code will bring up virtual interfaces, each interface
dedicated to a specific virtual_router. Keepalived uses Linux kernel macvlan
driver to defines these interfaces. It is then mandatory to use kernel
compiled with macvlan support.

By default MACVLAN interface are in VEPA mode which filters out received
packets whose MAC source address matches that of the MACVLAN interface. Setting
MACVLAN interface in private mode will not filter based on source MAC address.

Alternatively, you can specify 'vmac_xmit_base' which will cause the VRRP
messages to be transmitted and received on the underlying interface whilst ARP
will happen from the VMAC interface.

You may also need to tweak your physical interfaces to play around with well
known ARP issues. Keepalived sets the following configuration when using VMACs:

1) Global configuration::

    net.ipv4.conf.all.arp_ignore = 1
    net.ipv4.conf.all.arp_announce = 1
    net.ipv4.conf.all.arp_filter = 0

2) Physical interface configuration

For the physical ethernet interface running VRRP instance use::

    net.ipv4.conf.eth0.arp_filter = 1

3) VMAC interface

consider the following VRRP configuration::

    vrrp_instance instance1 {
        state BACKUP
        interface eth0
        virtual_router_id 250
        use_vmac
            vmac_xmit_base         # Transmit VRRP adverts over physical interface
        priority 150
        advert_int 1
        virtual_ipaddress {
            10.0.0.254
        }
    }

The ``use_vmac`` keyword will drive keepalived code to create a macvlan interface
named *vrrp.250* (default internal paradigm is vrrp.{virtual_router_id}, you can
override this naming by giving an argument to 'use_vmac' keyword, eg: use_vmac
vrrp250).
