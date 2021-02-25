keepalived: Loadbalancing & High-Availability
=============================================

[![Keepalived CI](https://github.com/acassen/keepalived/actions/workflows/build.yml/badge.svg)](https://github.com/acassen/keepalived/actions/workflows/build.yml)
[![Coverity Status](https://scan.coverity.com/projects/22678/badge.svg)](https://scan.coverity.com/projects/acassen-keepalived)
[![Language grade: C/C++](https://img.shields.io/lgtm/grade/cpp/g/acassen/keepalived.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/acassen/keepalived/context:cpp)
[![Total alerts](https://img.shields.io/lgtm/alerts/g/acassen/keepalived.svg?logo=lgtm&logoWidth=18)](https://lgtm.com/projects/g/acassen/keepalived/alerts/)
[![keepalived](https://snapcraft.io/keepalived/badge.svg)](https://snapcraft.io/keepalived)
[![Twitter Follow](https://img.shields.io/twitter/url/http/shields.io.svg?style=social&label=Follow)](https://twitter.com/keepalived)

The main goal of this project is to provide simple and robust facilities
for loadbalancing and high-availability to Linux system and Linux based
infrastructures. Loadbalancing framework relies on well-known and widely
used Linux Virtual Server (IPVS) kernel module providing Layer4 loadbalancing.
Keepalived implements a set of checkers to dynamically and adaptively maintain
and manage loadbalanced server pool according their health. On the other hand
high-availability is achieved by the Virtual Router Redundancy Protocol (VRRP).
VRRP is a fundamental brick for router failover. In addition, Keepalived
implements a set of hooks to the VRRP finite state machine providing low-level
and high-speed protocol interactions. In order to offer fastest network
failure detection, Keepalived implements the Bidirectional Forwarding Detection
(BFD) protocol. VRRP state transition can take into account BFD hints to drive
fast state transition. Keepalived frameworks can be used independently or all
together to provide resilient infrastructures.

Keepalived implementation is based on an I/O multiplexer to handle a
strong multi-threading framework. All the events process use this I/O
multiplexer.

To build keepalived from the git source tree, you will need to have
autoconf, automake and various libraries installed. See the INSTALL
file for details of what needs to be installed and what needs to be
executed before building keepalived.

Keepalived is free software, Copyright (C) Alexandre Cassen.
See the file COPYING for copying conditions.

OPENSSL TOOLKIT LICENCE EXCEPTION

In addition, as the copyright holder of Keepalived,
I, Alexandre Cassen, <acassen@linux-vs.org>,
grant the following special exception:

	I, Alexandre Cassen, <acassen@linux-vs.org>, explicitly allow
	the compilation and distribution of the Keepalived software with
	the OpenSSL Toolkit.

