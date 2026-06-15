# Quick Start

This guide takes you from a fresh install to a working setup in a few minutes,
first a floating IP that fails over between two nodes, then a load balanced
service behind that IP. Adjust the interface names and addresses to match your
own network as you go.

## Prerequisites

You need Keepalived installed on each host, which the
[Installing Keepalived](installing.md) page covers, and root access to edit the
configuration and start the service. The whole configuration lives in a single
file, `/etc/keepalived/keepalived.conf`.

For the high availability example you need two Linux hosts on the same LAN. For
the load balancing example you also need a couple of backend servers.

## Step 1: A floating IP with VRRP

The goal is a virtual IP that one node owns at a time and that moves to the other
node on failure. On the first host, write this to `/etc/keepalived/keepalived.conf`:

```
vrrp_instance VI_1 {
    state MASTER
    interface eth0
    virtual_router_id 51
    priority 150
    advert_int 1
    authentication {
        auth_type PASS
        auth_pass changeme
    }
    virtual_ipaddress {
        192.168.1.100/24
    }
}
```

On the second host use the same file, but set `state BACKUP` and a lower
`priority`, for example `100`. The node with the highest priority becomes master
and carries the address.

!!! note
    The `virtual_router_id` must be identical on both nodes and unique among the
    VRRP routers on the LAN. Change `auth_pass` to your own value, and remember it
    is sent in clear text, so VRRP authentication only guards against
    misconfiguration, not against an attacker on the wire.

Start the service on both hosts:

```
# systemctl enable --now keepalived
```

Check that the master carries the address, and watch it move when you stop
Keepalived on the master:

```
# ip address show eth0
# systemctl stop keepalived        # on the master, the backup takes the VIP
```

## Step 2: Load balance a service behind the VIP

Now spread TCP traffic for the floating address across two backends. Add a
`virtual_server` block to the same file, alongside the `vrrp_instance`:

```
virtual_server 192.168.1.100 80 {
    delay_loop 10
    lvs_sched rr
    lvs_method NAT
    protocol TCP

    real_server 192.168.10.10 80 {
        weight 1
        TCP_CHECK {
            connect_timeout 3
        }
    }
    real_server 192.168.10.11 80 {
        weight 1
        TCP_CHECK {
            connect_timeout 3
        }
    }
}
```

Keepalived now health checks each backend with a TCP connection and keeps only
the live ones in the pool. Reload to apply the change:

```
# systemctl reload keepalived
```

Then confirm the virtual service and its real servers are programmed into the
kernel:

```
# ipvsadm -Ln
```

!!! warning
    NAT forwarding needs the director to route packets, so enable IP forwarding
    with `sysctl -w net.ipv4.ip_forward=1`, and make sure the backends send their
    return traffic back through the director. Direct Routing and Tunneling avoid
    that constraint, as the
    [Load Balancing Techniques](load-balancing-techniques.md) page explains.

## Next steps

You now have a failover address and a load balanced service. From here:

- The [Configuration Synopsis](configuration-synopsis.md) walks through the main
  blocks and their common keywords.
- The [keepalived.conf(5)](../keepalived-conf.md) reference lists every keyword in
  full.
- The [case studies](case-study-healthcheck.md) show complete, real world
  topologies.
