###############################
Case Study: Failover using VRRP
###############################

As an example we can introduce the following LVS topology:

Architecture Specification
**************************

To create a virtual LVS director using the VRRPv2 protocol, we define the following architecture:

* 2 LVS directors in active-active configuration.
* 4 VRRP Instances per LVS director: 2 VRRP Instance in the MASTER state and 2 in BACKUP state. We use a symmetric state on each LVS directors.
* 2 VRRP Instances in the same state are to be synchronized to define a persistent virtual routing path.
* Strong authentication: IPSEC-AH is used to protect our VRRP advertisements from spoofed and reply attacks.

The VRRP Instances are compounded with the following IP addresses:

* VRRP Instance VI_1: owning VRRIP VIPs VIP1 & VIP2. This instance defaults to the MASTER state on LVS director 1. It stays synchronized with VI_2.
* VRRP Instance VI_2: owning DIP1. This instance is by default in MASTER state on LVS director 1. It stays synchronized with VI_1.
* VRRP Instance VI_3: owning VRRIP VIPs VIP3 & VIP4. This instance is in default MASTER state on LVS director 2. It stays synchronized with VI_4.
* VRRP Instance VI_4: owning DIP2. This instance is in default MASTER state on LVS director 2. It stays synchronized with VI_3.

Keepalived Configuration
************************

The whole configuration is done in the /etc/keepalived/keepalived.conf file. In our case study this file on LVS director 1 looks like::

    vrrp_sync_group VG1 {
        group {
            VI_1
            VI_2
        }
    }
    vrrp_sync_group VG2 {
        group {
            VI_3
            VI_4
        }
    }
    vrrp_instance VI_1 {
        state MASTER
        interface eth0
        virtual_router_id 51
        priority 150
        advert_int 1
        authentication {
            auth_type AH
            auth_pass k@l!ve1
        }
        virtual_ipaddress {
            192.168.200.10
            192.168.200.11
        }
    }
    vrrp_instance VI_2 {
        state MASTER
        interface eth1
        virtual_router_id 52
        priority 150
        advert_int 1
        authentication {
            auth_type AH
            auth_pass k@l!ve2
        }
        virtual_ipaddress {
            192.168.100.10
        }
    }


::

    vrrp_instance VI_3 {
        state BACKUP
        interface eth0
        virtual_router_id 53
        priority 100
        advert_int 1
        authentication {
            auth_type AH
            auth_pass k@l!ve3
        }
        virtual_ipaddress {
            192.168.200.12
            192.168.200.13
        }
    }
    vrrp_instance VI_4 {
        state BACKUP
        interface eth1
        virtual_router_id 54
        priority 100
        advert_int 1
        authentication {
            auth_type AH
            auth_pass k@l!ve4
        }
        virtual_ipaddress {
            192.168.100.11
        }
    }

Then we define the symmetric configuration file on LVS director 2. This means that VI_3 & VI_4 on LVS director 2 are in MASTER state with a higher priority 150 to start with a stable state.  Symmetrically VI_1 & VI_2 on LVS director 2 are in default BACKUP state with lower priority of 100.
|
This configuration file specifies 2 VRRP Instances per physical NIC. When you run Keepalived on LVS director 1 without running it on LVS director 2, LVS director 1 will own all the VRRP VIP. So if you use the ip utility you may see something like: (On Debian the ip utility is part of iproute)::

    [root@lvs1 tmp]# ip address list
    1: lo: <LOOPBACK,UP> mtu 3924 qdisc noqueue
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 brd 127.255.255.255 scope host lo
    2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc pfifo_fast qlen 100
        link/ether 00:00:5e:00:01:10 brd ff:ff:ff:ff:ff:ff
        inet 192.168.200.5/24 brd 192.168.200.255 scope global eth0
        inet 192.168.200.10/32 scope global eth0
        inet 192.168.200.11/32 scope global eth0
        inet 192.168.200.12/32 scope global eth0
        inet 192.168.200.13/32 scope global eth0
    3: eth1: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc pfifo_fast qlen 100
        link/ether 00:00:5e:00:01:32 brd ff:ff:ff:ff:ff:ff
        inet 192.168.100.5/24 brd 192.168.201.255 scope global eth1
        inet 192.168.100.10/32 scope global eth1
        inet 192.168.100.11/32 scope global eth1

Then simply start Keepalived on the LVS director 2 and you will see::

    [root@lvs1 tmp]# ip address list
    1: lo: <LOOPBACK,UP> mtu 3924 qdisc noqueue
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 brd 127.255.255.255 scope host lo
    2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc pfifo_fast qlen 100
        link/ether 00:00:5e:00:01:10 brd ff:ff:ff:ff:ff:ff
        inet 192.168.200.5/24 brd 192.168.200.255 scope global eth0
        inet 192.168.200.10/32 scope global eth0
        inet 192.168.200.11/32 scope global eth0
    3: eth1: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc pfifo_fast qlen 100
        link/ether 00:00:5e:00:01:32 brd ff:ff:ff:ff:ff:ff
        inet 192.168.100.5/24 brd 192.168.201.255 scope global eth1
        inet 192.168.100.10/32 scope global eth1

Symmetrically on LVS director 2 you will see::

    [root@lvs2 tmp]# ip address list
    1: lo: <LOOPBACK,UP> mtu 3924 qdisc noqueue
        link/loopback 00:00:00:00:00:00 brd 00:00:00:00:00:00
        inet 127.0.0.1/8 brd 127.255.255.255 scope host lo
    2: eth0: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc pfifo_fast qlen 100
        link/ether 00:00:5e:00:01:10 brd ff:ff:ff:ff:ff:ff
        inet 192.168.200.5/24 brd 192.168.200.255 scope global eth0
        inet 192.168.200.12/32 scope global eth0
        inet 192.168.200.13/32 scope global eth0
    3: eth1: <BROADCAST,MULTICAST,UP> mtu 1500 qdisc pfifo_fast qlen 100
        link/ether 00:00:5e:00:01:32 brd ff:ff:ff:ff:ff:ff
        inet 192.168.100.5/24 brd 192.168.201.255 scope global eth1
        inet 192.168.100.11/32 scope global eth1

The VRRP VIPs are:

* VIP1 = 192.168.200.10
* VIP2 = 192.168.200.11
* VIP3 = 192.168.200.12
* VIP4 = 192.168.200.13
* DIP1 = 192.168.100.10
* DIP2 = 192.168.100.11

The use of VRRP keyword “sync_instance” imply that we have defined a pair of MASTER VRRP Instance per LVS directors ó (VI_1,VI_2) & (VI_3,VI_4). This means that if eth0 on LVS director 1 fails then VI_1 enters the MASTER state on LVS director 2 so the MASTER Instance distribution on both directors will be: (VI_2) on director 1 & (VI_1,VI_3,VI_4) on director 2. We use “sync_instance”
so VI_2 is forced to BACKUP the state on LVS director 1. The final VRRP MASTER instance distribution will be: (none) on LVS director 1 & (VI_1,VI_2,VI_3,VI_4) on LVS director 2. If eth0 on LVS director 1 became available the distribution will transition back to the initial state.

For more details on this state transition please refer to the “Linux Virtual Server High Availability using VRRPv2” paper (available at http://www.linux-vs.org/~acassen/), which explains the implementation of this functionality.

Using this configuration both LVS directors are active at a time, thus sharing LVS directors for a global director. That way we introduce a virtual LVS director.

.. note::
   This VRRP configuration sample is an illustration for a high availability router (not LVS specific). It can be used for many more common/simple needs.
