########################
Configuring SNMP Support
########################

Keepalived provides an SNMP subsystem that can gather various metrics about the
VRRP stack and the health checker system. The keepalived MIB is in
the ``doc`` directory of the project. The base SNMP OID for the MIB is
`.1.3.6.1.4.1.9586.100.5`, which is hosted under the `Debian OID space`_
assigned by IANA.

.. _Debian OID space: https://dsa.debian.org/iana/


Prerequisites *************

Install the SNMP protocol tools and libraries onto your system.  This requires
the installation of a few packages::

    yum install net-snmp net-snmp-utils net-snmp-libs

Once SNMP has been installed on your system, configure keepalived with SNMP
support.  When compiling keepalived, add the ``--enable-snmp`` configure
option.  For example::

    ./configure --enable-snmp

During the configure step of the compiling process, you will get a
configuration summary before building with ``make``.  For example, you may see
similar output on a CentOS 6 machine::

    ./configure --prefix=/usr/local/keepalived-1.2.15 --enable-snmp
    Keepalived configuration
    ------------------------
    Keepalived version       : 1.2.15
    Compiler                 : gcc
    Compiler flags           : -g -O2 -I/usr/include/libnl3
    Extra Lib                : -Wl,-z,relro -Wl,-z,now -L/usr/lib64
    -lnetsnmpagent -lnetsnmphelpers -lnetsnmpmibs -lnetsnmp -Wl,-E
    -Wl,-rpath,/usr/lib64/perl5/CORE -lssl -lcrypto -lcrypt  -lnl-genl-3 -lnl-3
    Use IPVS Framework       : Yes
    IPVS sync daemon support : Yes
    IPVS use libnl           : Yes
    fwmark socket support    : Yes
    Use VRRP Framework       : Yes
    Use VRRP VMAC            : Yes
    SNMP support             : Yes
    SHA1 support             : No
    Use Debug flags          : No

Notice the *Extra Lib* section of the configuration summary.  It lists various
library flags that gcc will use to build keepalived, several of which have to do with
SNMP.

Configuring Support
*******************

Enable SNMP AgentX support by including the following line in the SNMP
daemon configuration file, typically ``/etc/snmp/snmpd.conf`` if you installed
via RPMs on a CentOS machine::

    master agentx

.. note::
   Be sure to reload or restart the SNMP service for the configuration change
   to take effect.

Adding the MIB
**************

You can query keepalived SNMP managed objects by using the OID.  For example::

    snmpwalk -v2c -c public localhost .1.3.6.1.4.1.9586.100.5.1.1.0
    SNMPv2-SMI::enterprises.9586.100.5.1.1.0 = STRING: "Keepalived v1.2.15 (01/10,2015)"

Alternatively, with the keepalived MIB, you can query using the MIB available
from the project.  First, copy the MIB to the system's global MIB directory or
to the user's local MIB directory::

    cp /usr/local/src/keepalived-1.2.15/doc/KEEPALIVED-MIB /usr/share/snmp/mibs

or::

    cp /usr/local/src/keepalived-1.2.15/doc/KEEPALIVED-MIB ~/.snmp/mibs

The SNMP daemon will check both directories for the existence of the MIB.  Once
the MIB is in place, the SNMP query can look as follows::

    snmpwalk -v2c -c public localhost KEEPALIVED-MIB::version
    KEEPALIVED-MIB::version.0 = STRING: Keepalived v1.2.15 (01/10,2015)


MIB Overview
************

There are four main sections to the keepalived MIB:

* global
* vrrp
* check
* conformance

Global
======

The global section includes objects that contain information about the
keepalived instance such as version, router ID and administrative email
addresses.

VRRP
====

The VRRP section includes objects that contain information about each
configured VRRP instance.  Within each instance, there are objects that include
instance name, current state, and virtual IP addresses.

Check
=====

The Check section includes objects that contain information about each
configured virtual server.  It includes server tables for virtual and real
servers and also configured load balancing algorithms, load balancing method,
protocol, status, real and virtual server network connection statistics.

Conformance
===========

.. todo::
   do conformance

.. note::
   Use a MIB browser, such as mbrowse, to see what managed objects are available to
   query for monitoring the health of your LVS servers.

