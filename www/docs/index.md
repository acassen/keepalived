---
hide:
  - navigation
  - toc
---

<div class="ka-hero" markdown>

![Keepalived](assets/keepalived-logo.png){ .ka-logo }

# Load balancing & high availability for Linux

<p class="ka-sub">
Keepalived is a routing software written in C. It brings simple and robust
load balancing and high availability to Linux systems and Linux based
infrastructures, and it runs in production across data centers, ISPs and
hardware vendors worldwide.
</p>

[:material-bullhorn: Latest release **2.4.1** · June 2026 :octicons-arrow-right-24:](release-notes/Release-2.4.1.md){ .ka-latest }

[:material-newspaper-variant-outline: Latest article **VRRP HMAC Authentication** · June 2026 :octicons-arrow-right-24:](articles/vrrp-hmac-authentication.md){ .ka-latest }

[:material-rocket-launch-outline: Get started](documentation/user-guide/quick-start.md){ .md-button .md-button--primary }
[:material-download: Download](download.md){ .md-button }
[:fontawesome-brands-github: GitHub](https://github.com/acassen/keepalived){ .md-button }
[:material-book-open-variant: Documentation](documentation.md){ .md-button }

</div>

## What is Keepalived?

Keepalived builds load balancing on top of the well known [Linux Virtual
Server (IPVS)](https://www.linuxvirtualserver.org/) kernel module, which
delivers Layer 4 load balancing. On top of IPVS, Keepalived runs a set of
health checkers that watch each server pool and decide, in real time, whether
a real server stays in the topology or drops out according to its health.

High availability comes from the [VRRP](https://datatracker.ietf.org/wg/vrrp/)
protocol, the fundamental brick for router failover. Keepalived adds a set of
hooks to the VRRP finite state machine so it can react with low level, high
speed protocol interactions. To detect network failures as fast as possible it
also implements [BFD](https://datatracker.ietf.org/wg/bfd/), and a VRRP state
transition can take a BFD hint into account to drive a fast failover.

Each framework works on its own or together with the others, so you can build
exactly the resilient infrastructure you need.

## Three frameworks, one daemon

<div class="grid cards" markdown>

-   :material-server-network:{ .lg } __High availability (VRRP)__

    ---

    A full implementation of VRRP v2 and v3 for IPv4 and IPv6, with sync
    groups that keep routing paths consistent after a takeover, plus HMAC
    authentication that secures adverts on unicast and multicast.

-   :material-scale-balance:{ .lg } __Load balancing (LVS/IPVS)__

    ---

    Layer 4 load balancing driven by the kernel IPVS module, configured and
    maintained from a single place, with several scheduling algorithms and
    forwarding methods.

-   :material-heart-pulse:{ .lg } __Health checking & BFD__

    ---

    Layer 4 to Layer 7 checkers add and remove real servers automatically,
    while BFD detects link and peer failures in milliseconds to trigger fast
    VRRP transitions.

</div>

## License

Keepalived is free software. You can redistribute it and modify it under the
terms of the GNU General Public License as published by the Free Software
Foundation, either version 2 of the License, or any later version.
