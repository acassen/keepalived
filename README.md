<div align="center">

<a href="https://www.keepalived.org"><img src="www/docs/images/Keepalived-Banner-Github.png" alt="Keepalived" width="100%"></a>

### Load balancing & high availability for Linux

[![Keepalived CI](https://github.com/acassen/keepalived/actions/workflows/build.yml/badge.svg)](https://github.com/acassen/keepalived/actions/workflows/build.yml)
[![CodeQL](https://github.com/acassen/keepalived/actions/workflows/codeql.yml/badge.svg)](https://github.com/acassen/keepalived/actions/workflows/codeql.yml)
[![Snap Status](https://snapcraft.io/keepalived/badge.svg)](https://snapcraft.io/keepalived)
[![License: GPL v2+](https://img.shields.io/badge/License-GPLv2+-blue.svg)](COPYING)
[![GitHub Sponsor](https://img.shields.io/static/v1?label=Sponsor&message=%E2%9D%A4&logo=GitHub&color=%23fe8e86)](https://github.com/sponsors/acassen)
[![Follow on X](https://img.shields.io/badge/Follow-%40keepalived-000000?logo=x&logoColor=white)](https://twitter.com/keepalived)

[Website](https://www.keepalived.org) ·
[Documentation](https://www.keepalived.org/documentation/) ·
[Download](https://www.keepalived.org/download/) ·
[Quick Start](https://www.keepalived.org/documentation/user-guide/quick-start/) ·
[Community](https://www.keepalived.org/community/)

</div>

Keepalived is a routing software written in C. It brings simple and robust load
balancing and high availability to Linux systems and Linux based
infrastructures, and it runs in production across data centers, ISPs and
hardware vendors worldwide.

## What is Keepalived?

Keepalived builds load balancing on top of the well known
[Linux Virtual Server (IPVS)](https://www.linuxvirtualserver.org/) kernel
module, which delivers Layer 4 load balancing. On top of IPVS, Keepalived runs a
set of health checkers that watch each server pool and decide, in real time,
whether a real server stays in the topology or drops out according to its
health.

High availability comes from the [VRRP](https://datatracker.ietf.org/wg/vrrp/)
protocol, the fundamental brick for router failover. Keepalived adds a set of
hooks to the VRRP finite state machine so it can react with low level, high
speed protocol interactions. To detect network failures as fast as possible it
also implements [BFD](https://datatracker.ietf.org/wg/bfd/), and a VRRP state
transition can take a BFD hint into account to drive a fast failover.

Each framework works on its own or together with the others, so you can build
exactly the resilient infrastructure you need.

## Three frameworks, one daemon

| :shield: High availability (VRRP) | :balance_scale: Load balancing (LVS/IPVS) | :heartpulse: Health checking & BFD |
| :-- | :-- | :-- |
| A full implementation of VRRP v2 and v3 for IPv4 and IPv6, with sync groups that keep routing paths consistent after a takeover, plus IPSEC-AH securing of protocol adverts. | Layer 4 load balancing driven by the kernel IPVS module, configured and maintained from a single place, with several scheduling algorithms and forwarding methods. | Layer 4 to Layer 7 checkers add and remove real servers automatically, while BFD detects link and peer failures in milliseconds to trigger fast VRRP transitions. |

Keepalived is articulated around a central I/O multiplexer that drives a strong
multi threaded framework, and every event runs through this multiplexer. For
robustness the daemon splits into a minimalistic parent process that monitors
its children, while dedicated child processes run the VRRP, health checking and
BFD stacks. The [Software Design](https://www.keepalived.org/documentation/user-guide/software-design/)
page covers the internals in detail.

## Quick start

Most Linux distributions ship Keepalived as a mainline package, which is the
quickest path to a working install:

```sh
sudo apt install keepalived     # Debian / Ubuntu
sudo dnf install keepalived     # RHEL / Fedora / Rocky
```

A minimal floating IP that fails over between two nodes needs a single file,
`/etc/keepalived/keepalived.conf`. On the master:

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

On the backup use the same file, but set `state BACKUP` and a lower `priority`.
The node with the highest priority becomes master and carries the address.

> [!NOTE]
> The `virtual_router_id` must be identical on both nodes and unique among the
> VRRP routers on the LAN. Change `auth_pass` to your own value, and remember it
> travels in clear text, so VRRP authentication only guards against
> misconfiguration, not against an attacker on the wire.

Start the service on both hosts:

```sh
sudo systemctl enable --now keepalived
```

The full [Quick Start](https://www.keepalived.org/documentation/user-guide/quick-start/)
goes further and adds a load balanced service behind the floating IP.

## Building from source

```sh
git clone https://github.com/acassen/keepalived.git
cd keepalived
./configure
make && sudo make install
```

Building from the git tree needs autoconf, automake and a few libraries. The
[INSTALL](INSTALL) file lists what to install per distribution and what to run
before building.

## Documentation

The full documentation lives at [keepalived.org](https://www.keepalived.org):

- [User Guide](https://www.keepalived.org/documentation/user-guide/) for installation, configuration and the core concepts.
- [keepalived.conf(5)](https://www.keepalived.org/documentation/keepalived-conf/) for the exhaustive reference of every keyword.
- [Release Notes](https://www.keepalived.org/release-notes/) and the [ChangeLog](https://www.keepalived.org/documentation/changelog/) for the project history.

## Community

The [Keepalived Users Group](https://groups.io/g/keepalived-users) is the place
to ask questions, share configurations and follow announcements. Report bugs and
propose features on the [issue tracker](https://github.com/acassen/keepalived/issues),
and include a minimal configuration that reproduces the problem. Release
announcements are posted on the [Keepalived account on X](https://twitter.com/keepalived).

> [!IMPORTANT]
> AI tools are welcome, yet the core team keeps the code base small, clear and
> auditable. Large machine generated patches, comments or reports will not be
> read. Keep your work lean whether or not an AI helped, and read the
> [Using AI tools](https://www.keepalived.org/community/) guidance first.

## License

Keepalived is free software, Copyright (C) 2000-2026 Alexandre Cassen. You can
redistribute it and modify it under the terms of the GNU General Public License
as published by the Free Software Foundation, either version 2 of the License,
or any later version. See the [COPYING](COPYING) file for the full terms.

### OpenSSL toolkit licence exception

In addition, as the copyright holder of Keepalived, I, Alexandre Cassen,
&lt;acassen@linux-vs.org&gt;, grant the following special exception:

> I, Alexandre Cassen, &lt;acassen@gmail.com&gt;, explicitly allow the
> compilation and distribution of the Keepalived software with the OpenSSL
> Toolkit.
