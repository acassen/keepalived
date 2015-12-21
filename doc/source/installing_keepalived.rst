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

Install Prerequisites on RHEL/CentOS 
====================================

On RHEL, install the following prerequisites::

    yum install curl gcc openssl-devel libnl3-devel net-snmp-devel

Install Prerequisites on Debian
===============================

On Debian, install the following prerequisites::

    apt-get install curl gcc libssl-dev libnl-3-dev libnl-genl-3-dev libsnmp-dev


Build and Install
=================

Use *curl* or any other transfer tool such as *wget* to download keepalived.
The software is available at http://www.keepalived.org/download.html or
https://github.com/acassen/keepalived. Then, compile the package::

    curl --progress http://keepalived.org/software/keepalived-1.2.15.tar.gz | tar xz
    cd keepalived-1.2.15
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

On RHEL, 
