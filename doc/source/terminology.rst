###########
Terminology
###########

.. todo:: put image here

LVS stands for “Linux Virtual Server“. LVS is a patched Linux kernel that adds a load balancing facility. For more information on LVS, please refer to the project homepage: http://www.linux-vs.org. LVS acts as a network bridge (using NAT) to load balance TCP/UDP stream. The LVS router components are:

* WAN Interface: Ethernet Network Interface Controller that will be accessed by all the clients.
* LAN Interface: Ethernet Network Interface Controller to manage all the load balanced servers.
* Linux kernel: The kernel is patched with the latest LVS and is used as a router OS.

In this document, we will use the following keywords:

LVS Component
*************

.. glossary::

    VIP
        The Virtual IP is the IP address that will be accessed by all the
        clients. The clients only access this IP address.

    Real server
        A real server hosts the application accessed by client requests.
        WEB SERVER 1 & WEB SERVER 2 in our synopsis.

    Server pool
        A farm of real servers.

    Virtual server
        The access point to a Server pool.

    Virtual Service
        A TCP/UDP service associated with the VIP.

VRRP Component
**************

.. glossary::

    VRRP
        The protocol implemented for the directors’ failover/virtualization.

    IP Address owner
        The VRRP Instance that has the IP address(es) as real interface
        address(es). This is the VRRP Instance that, when up, will respond to
        packets addressed to one of these IP address(es) for ICMP, TCP
        connections, ...

    MASTER state
        VRRP Instance state when it is assuming the responsibility of forwarding
        packets sent to the IP address(es) associated with the VRRP Instance.
        This state is illustrated on “Case study: Failover” by a red line.

    BACKUP state
        VRRP Instance state when it is capable of forwarding packets in the
        event that the current VRRP Instance MASTER fails.

    Real Load Balancer
        An LVS director running one or many VRRP Instances.

    Virtual Load balancer
        A set of Real Load balancers.

    Synchronized Instance
        VRRP Instance with which we want to be synchronized. This provides
        VRRP Instance monitoring.

    Advertisement
        The name of a simple VRRPv2 packet sent to a set of VRRP Instances
        while in the MASTER state.

.. todo::
   Define RIP, DIP, Director, IPVS
