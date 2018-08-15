#######################
Case Study: Healthcheck
#######################

As an example we can introduce the following LVS topology:

First of all, you need a well-configured LVS topology. In the rest of this document, we will assume that all system configurations have been done. This kind of topology is generally implemented in a DMZ architecture. For more information on LVS NAT topology and system configuration please read the nice Joseph Mack LVS HOWTO.

Main architecture components
****************************

* LVS Router: Owning the load balanced IP Class routed (192.168.100.0/24).
* Network Router: The default router for the entire internal network. All the LAN workstations are handled through this IP address.
* Network DNS Server: Referencing the internal network IP topology.
* SMTP Server: SMTP server receiving the mail alerts.
* SERVER POOL: Set of servers hosting load balanced services.

Server pool specifications
**************************

In this sample configuration we have 2 server pools:

* Server pool 1: Hosting the HTTP & SSL services. Each server owns two application servers (IBM WEBSPHERE & BEA WEBLOGIC)
* Server pool 2: Hosting the SMTP service.

Keepalived configuration
************************

You are now ready to configure the Keepalived daemon according to your LVS topology. The whole configuration is done in the /etc/keepalived/keepalived.conf file. In our case study this file looks like::

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
    virtual_server 192.168.200.15 80 {
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
    virtual_server 192.168.200.15 443 {
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
    virtual_server 192.168.200.15 25 {
        delay_loop 15
        lb_algo wlc
        lb_kind NAT
        persistence_timeout 50
        protocol TCP
        real_server 192.168.100.4 25 {
            weight 1
            TCP_CHECK {
                connect_timeout 3
            }
        }
        real_server 192.168.100.5 25 {
            weight 2
            TCP_CHECK {
                connect_timeout 3
            }
        }
    }

According to this configuration example, the Keepalived daemon will drive the kernel using the following information:

* The LVS server will own the name: LVS_MAIN
* Notification:

    * SMTP server will be: 192.168.200.20
    * SMTP connection timeout is set to: 30 seconded
    * Notification emails will be: admin@domain.com & 0633225522@domain.com

* Load balanced services:

    * HTTP: VIP 192.168.200.15 port 80

        * Load balancing: Using Weighted Round Robin scheduler with NAT forwarding. Connection persistence is set to 50 seconds on each TCP service. If you are using Linux kernel 2.2 you need to specify the NAT netmask to define the IPFW masquerade granularity (nat_mask keyword). The delay loop is set to 30 seconds
        * Sorry Server: If all real servers are removed from the VS’s server pools, we add the sorry_server 192.168.100.100 port 80 to serve clients requests.
        * Real server 192.168.100.2 port 80 will be weighted to 2. Failure detection will be based on HTTP_GET over 2 URLS. The service connection timeout will be set to 3 seconds. The real server will be considered down after 3 retries. The daemon will wait for 2 seconds before retrying.
        * Real server 192.168.100.3 port 80 will be weighted to 1. Failure detection will be based on HTTP_GET over 1 URL. The service connection timeout will be set to 3 seconds. The real server will be considered down after 3 retries. The daemon will wait for 2 seconds before retrying.

    * SSL: VIP 192.168.200.15 port 443

        * Load balancing: Using Round Robin scheduler with NAT forwarding.  Connection persistence is set to 360 seconds on each TCP service.  The delay loop is set to 20 seconds
        * Real server 192.168.100.2 port 443 will be weighted to 2. Failure detection will be based on TCP_CHECK. The real server will be considered down after a 3-second connection timeout.
        * Real server 192.168.100.3 port 443 will be weighted to 2. Failure detection will be based on TCP_CHECK. The real server will be considered down after a 3-second connection timeout.

    * SMTP: VIP 192.168.200.15 port 25

        * Load balancing: Using Weighted Least Connection scheduling algorithm in a NAT topology with connection persistence set to 50 seconds. The delay loop is set to 15 seconds
        * Real server 192.168.100.4 port 25 will be weighted to 1. Failure detection will be based on TCP_CHECK. The real server will be considered down after a 3-second connection timeout.
        * Real server 192.168.100.5 port 25 will be weighted to 2. Failure detection will be based on TCP_CHECK. The real server will be considered down after a 3-second connection timeout.

For SSL server health check, we can use SSL_GET checkers. The configuration block for a corresponding real server will look like::

    virtual_server 192.168.200.15 443 {
        delay_loop 20
        lb_algo rr
        lb_kind NAT
        persistence_timeout 360
        protocol TCP
        real_server 192.168.100.2 443 {
            weight 1
            SSL_GET
            {
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
        real_server 192.168.100.3 443 {
            weight 1
            SSL_GET
            {
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

To generate a sum over an URL simply proceed as follows::

    [root@lvs /root]# genhash –s 192.168.100.2 –p 80 –u /testurl/test.jsp
    --------------------------[ HTTP Header Buffer ]--------------------------
    0000 48 54 54 50 2f 31 2e 31 - 20 34 30 31 20 55 6e 61 HTTP/1.1 401 Una
    0010 75 74 68 6f 72 69 7a 65 - 64 0d 0a 44 61 74 65 3a uthorized..Date:
    0020 20 4d 6f 6e 2c 20 32 33 - 20 41 70 72 20 32 30 30 Mon, 23 Apr 200
    0030 31 20 31 35 3a 34 31 3a - 35 34 20 47 4d 54 0d 0a 1 15:41:54 GMT..
    0040 41 6c 6c 6f 77 3a 20 47 - 45 54 2c 20 48 45 41 44 Allow: GET, HEAD
    0050 0d 0a 53 65 72 76 65 72 - 3a 20 4f 72 61 63 6c 65 ..Server: Oracle
    0060 5f 57 65 62 5f 4c 69 73 - 74 65 6e 65 72 2f 34 2e _Web_Listener/4.
    0070 30 2e 38 2e 31 2e 30 45 - 6e 74 65 72 70 72 69 73 0.8.1.0Enterpris
    0080 65 45 64 69 74 69 6f 6e - 0d 0a 43 6f 6e 74 65 6e eEdition..Conten
    0090 74 2d 54 79 70 65 3a 20 - 74 65 78 74 2f 68 74 6d t-Type: text/htm
    00a0 6c 0d 0a 43 6f 6e 74 65 - 6e 74 2d 4c 65 6e 67 74 l..Content-Lengt
    00b0 68 3a 20 31 36 34 0d 0a - 57 57 57 2d 41 75 74 68 h: 164..WWW-Auth
    00c0 65 6e 74 69 63 61 74 65 - 3a 20 42 61 73 69 63 20 enticate: Basic
    00d0 72 65 61 6c 6d 3d 22 41 - 43 43 45 53 20 20 20 20 realm="ACCES
    00e0 22 0d 0a 43 61 63 68 65 - 2d 43 6f 6e 74 72 6f 6c "..Cache-Control
    00f0 3a 20 70 75 62 6c 69 63 - 0d 0a 0d 0a : public....
    ------------------------------[ HTML Buffer ]-----------------------------
    0000 3c 48 54 4d 4c 3e 3c 48 - 45 41 44 3e 3c 54 49 54 <HTML><HEAD><TIT
    0010 4c 45 3e 55 6e 61 75 74 - 68 6f 72 69 7a 65 64 3c LE>Unauthorized<
    0020 2f 54 49 54 4c 45 3e 3c - 2f 48 45 41 44 3e 0d 0a /TITLE></HEAD>..
    0030 3c 42 4f 44 59 3e 54 68 - 69 73 20 64 6f 63 75 6d <BODY>This docum
    0040 65 6e 74 20 69 73 20 70 - 72 6f 74 65 63 74 65 64 ent is protected
    0050 2e 20 20 59 6f 75 20 6d - 75 73 74 20 73 65 6e 64 . You must send
    0060 0d 0a 74 68 65 20 70 72 - 6f 70 65 72 20 61 75 74 ..the proper aut
    0070 68 6f 72 69 7a 61 74 69 - 6f 6e 20 69 6e 66 6f 72 horization infor
    0080 6d 61 74 69 6f 6e 20 74 - 6f 20 61 63 63 65 73 73 mation to access
    0090 20 69 74 2e 3c 2f 42 4f - 44 59 3e 3c 2f 48 54 4d it.</BODY></HTM
    00a0 4c 3e 0d 0a - L>..
    -----------------------[ HTML MD5 final resulting ]-----------------------
    MD5 Digest : ec90a42b99ea9a2f5ecbe213ac9eba03

The only thing to do is to copy the generated MD5 Digest value generated and paste it into your Keepalived configuration file as a digest value keyword.

