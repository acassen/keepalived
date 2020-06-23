#####################
Installing Keepalived
#####################

Install keepalived from the distribution's repositories or, alternatively,
compile from source.  Although installing from the repositories is generally
the fastest way to get keepalived running on a system, the version of
keepalived available in the repositories are typically a few releases behind
the latest available stable version.

Installing from the Repositories
********************************

Installing on Red Hat Enterprise Linux
======================================

As of Red Hat 6.4, Red Hat and the clones have included the keepalived package
in the base repository.  Therefore, run the following to install the keepalived
package and all the required dependencies using YUM::

    yum install keepalived

Installing on Debian
====================

Run the following to install the keepalived package and all the required
dependencies using Debian's APT package handling utility::

    apt-get install keepalived


Compiling and Building from Source
**********************************

In order to run the latest stable version, compile keepalived from source.
Compiling keepalived requires a compiler, OpenSSL and the Netlink Library.  You
may optionally install Net-SNMP, which is required for SNMP support.

Install Prerequisites on RHEL/CentOS/Fedora
===========================================

On RHEL, Centos, Fedora etc install the following prerequisites
(on older systems replace dnf with yum)::

    dnf install curl gcc autoconf automake openssl-devel libnl3-devel \
        iptables-devel ipset-devel net-snmp-devel libnfnetlink-devel file-devel

For DBUS support::

    dnf install glib2-devel

For JSON support::

    dnf install json-c-devel

Install Prerequisites on Debian/Ubuntu
======================================

On Debian/Ubuntu, install the following prerequisites::

    apt-get install pkg-config curl gcc autoconf automake libssl-dev libnl-3-dev \
        libnl-genl-3-dev libsnmp-dev libnl-route-3-dev libnfnetlink-dev libipset-dev \
        iptables-dev libsnmp-dev

For DBUS support::

    dnf install libglib2.0-dev

For JSON support::

    dnf install libjson-c-dev

Install Prerequisites on Alpine Linux
=====================================

On Alpine Linux install the following prerequisites::

    autoconf automake iptables-dev ipset-dev libnfnetlink-dev libnl3-dev musl-dev and
        openssl-dev or libressl-dev
 
For SNMP support::

    net-snmp-dev (requires libressl-dev and not openssl-dev)

Install Prerequisites on Archlinux
==================================

On Archlinux run the following to install the required libraries::

    pacman -S ipset libnfnetlink libnl1

For SNMP support::

    pacman -S net-snmp


Build and Install
=================

Use *curl* or any other transfer tool such as *wget* to download keepalived.
The software is available at http://www.keepalived.org/download.html or
https://github.com/acassen/keepalived. Then, compile the package::

    curl --progress http://keepalived.org/software/keepalived-1.2.15.tar.gz | tar xz
    cd keepalived-1.2.15
    ./build_setup
    ./configure
    make
    sudo make install

It is a general recommendation when compiling from source to specify a PREFIX.
For example::

    ./configure --prefix=/usr/local/keepalived-1.2.15

This makes it easy to uninstall a compiled version of keepalived simply by
deleting the parent directory.  Additionally, this method of installation
allows for multiple versions of Keepalived installed without overwriting each
other.  Use a symlink to point to the desired version.  For example, your
directory layout could look like this::

    [root@lvs1 ~]# cd /usr/local
    [root@lvs1 local]# ls -l
    total 12
    lrwxrwxrwx. 1 root root   17 Feb 24 20:23 keepalived -> keepalived-1.2.15
    drwxr-xr-x. 2 root root 4096 Feb 24 20:22 keepalived-1.2.13
    drwxr-xr-x. 2 root root 4096 Feb 24 20:22 keepalived-1.2.14
    drwxr-xr-x. 2 root root 4096 Feb 24 20:22 keepalived-1.2.15

Setup Init Scripts
==================

After compiling, create an init script in order to control the keepalived
daemon.

On RHEL::

    ln -s /etc/rc.d/init.d/keepalived.init /etc/rc.d/rc3.d/S99keepalived

On Debian::

    ln -s /etc/init.d/keepalived.init /etc/rc2.d/S99keepalived

Note: The link should be added in your default run level directory.
