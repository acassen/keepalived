#########################################
Case Study: Mixing Healthcheck & Failover
#########################################

For this example, we use the same topology used in the Failover part. The idea here is to use VRRP VIPs as LVS VIPs. That way we will introduce a High Available LVS director performing LVS real server pool monitoring.

Keepalived Configuration
************************

The whole configuration is done in the /etc/keepalived/keepalived.conf file. In
our case study this file on LVS director 1 looks like::

    # Configuration File for keepalived
    global_defs {
        notification_email {
            admin@domain.com
            0633225522@domain.com
        }
        notification_email_from keepalived@domain.com
        smtp_server 192.168.200.20
        smtp_connect_timeout 30
        lvs_id LVS_MAIN
    }
    # VRRP Instances definitions
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
            auth_type PASS
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
            auth_type PASS
            auth_pass k@l!ve2
        }
        virtual_ipaddress {
            192.168.100.10
        }
    }
    vrrp_instance VI_3 {
        state BACKUP
        interface eth0
        virtual_router_id 53
        priority 100
        advert_int 1
        authentication {
            auth_type PASS
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
            auth_type PASS
            auth_pass k@l!ve4
        }
        virtual_ipaddress {
            192.168.100.11
        }
    }
    # Virtual Servers definitions
    virtual_server 192.168.200.10 80 {
        delay_loop 30
        lb_algo wrr
        lb_kind NAT
        persistence_timeout 50
        protocol TCP
        sorry_server 192.168.100.100 80
        real_server 192.168.100.2 80 {
            weight 2
            HTTP_GET {
                url {
                    path /testurl/test.jsp
                    digest ec90a42b99ea9a2f5ecbe213ac9eba03
                }
                url {
                    path /testurl2/test.jsp
                    digest 640205b7b0fc66c1ea91c463fac6334c
                }
                connect_timeout 3
                retry 3
                delay_before_retry 2
            }
        }
        real_server 192.168.100.3 80 {
            weight 1
            HTTP_GET {
                url {
                    path /testurl/test.jsp
                    digest 640205b7b0fc66c1ea91c463fac6334c
                }
                connect_timeout 3
                retry 3
                delay_before_retry 2
            }
        }
    }
    virtual_server 192.168.200.12 443 {
        delay_loop 20
        lb_algo rr
        lb_kind NAT
        persistence_timeout 360
        protocol TCP
        real_server 192.168.100.2 443 {
            weight 1
            TCP_CHECK {
                connect_timeout 3
            }
        }
        real_server 192.168.100.3 443 {
            weight 1
            TCP_CHECK {
                connect_timeout 3
            }
        }
    }

We define the symmetric VRRP configuration file on LVS director 2. That way both directors are active at a time, director 1 handling HTTP stream and director 2 SSL stream.
