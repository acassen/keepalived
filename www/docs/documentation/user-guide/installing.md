# Installing Keepalived

Install keepalived from the distribution's repositories or, alternatively, compile from source. Although installing from the repositories is generally the fastest way to get keepalived running on a system, the version of keepalived available in the repositories are typically a few releases behind the latest available stable version.

## Installing from the Repositories

### Installing on Red Hat Enterprise Linux

As of Red Hat 6.4, Red Hat and the clones have included the keepalived package in the base repository. Therefore, run the following to install the keepalived package and all the required dependencies using dnf (or yum on older systems):

    dnf install keepalived

### Installing on Debian

Run the following to install the keepalived package and all the required dependencies using Debian's APT package handling utility:

    apt-get install keepalived

## Compiling and Building from Source

In order to run the latest stable version, compile keepalived from source. Compiling keepalived requires a compiler, OpenSSL and the Netlink Library. You may optionally install Net-SNMP, which is required for SNMP support.

### Install Prerequisites on RHEL/CentOS/Fedora

On RHEL, Centos, Fedora etc install the following prerequisites (on older systems replace dnf with yum):

    dnf install gcc make autoconf automake openssl-devel libnl3-devel \
        iptables-devel ipset-devel net-snmp-devel libnfnetlink-devel file-devel \
        glib2-devel pcre2-devel libnftnl-devel libmnl-devel systemd-devel kmod-devel

For DBUS support:

    dnf install glib2-devel

For JSON support:

    dnf install json-c-devel

Note: On RHEL the codeready-builder-for-rhel-8-x86_64-rpms (or equivalent) repo  
needs to be enabled, and on CentOS the PowerTools repo is needed.

### Install Prerequisites on Debian/Ubuntu

On Debian/Ubuntu, install the following prerequisites:

    apt-get install build-essential pkg-config curl gcc autoconf automake libssl-dev \
        libnl-3-dev libnl-genl-3-dev libsnmp-dev libnl-route-3-dev libnfnetlink-dev \
        iptables-dev* libipset-dev libsnmp-dev libmagic-dev libglib2.0-dev libpcre2-dev \
        libnftnl-dev libmnl-dev libsystemd-dev libkmod-dev

    * on more recent versions replace iptables-dev with libxtables-dev libip4tc-dev libip6tc-dev

For DBUS support:

    dnf install libglib2.0-dev

### Install Prerequisites on Alpine Linux

On Alpine Linux install the following prerequisites:

    autoconf automake iptables-dev ipset-dev libnfnetlink-dev libnl3-dev musl-dev 
        libnftnl-dev file-dev pcre2-dev
      and
        openssl-dev or libressl-dev

For SNMP support:

    net-snmp-dev (requires libressl-dev and not openssl-dev)

### Install Prerequisites on Archlinux

On Archlinux run the following to install the required libraries:

    pacman -S ipset libnfnetlink libnl1 pcre-2

For SNMP support:

    pacman -S net-snmp

### Build and Install

Use *curl* or any other transfer tool such as *wget* to download keepalived. The software is available at <https://www.keepalived.org/download.html> or <https://github.com/acassen/keepalived>. Then, compile the package:

    curl --location --progress https://www.keepalived.org/software/keepalived-2.3.4.tar.gz | tar xz
    cd keepalived-2.3.4
    ./configure
    make
    sudo make install

When building from a git clone rather than a release tarball, run `./autogen.sh` first to generate the `configure` script.

It is a general recommendation when compiling from source to specify a PREFIX. For example:

    ./configure --prefix=/usr/local/keepalived-2.3.4

This makes it easy to uninstall a compiled version of keepalived simply by deleting the parent directory. Additionally, this method of installation allows for multiple versions of Keepalived installed without overwriting each other. Use a symlink to point to the desired version. For example, your directory layout could look like this:

    [root@lvs1 ~]# cd /usr/local
    [root@lvs1 local]# ls -l
    total 12
    lrwxrwxrwx. 1 root root   16 Feb 24 20:23 keepalived -> keepalived-2.3.4
    drwxr-xr-x. 2 root root 4096 Feb 24 20:22 keepalived-2.3.2
    drwxr-xr-x. 2 root root 4096 Feb 24 20:22 keepalived-2.3.3
    drwxr-xr-x. 2 root root 4096 Feb 24 20:22 keepalived-2.3.4

### Enabling the Service

Modern distributions use systemd, and the keepalived package (or `make install`
from source) ships a `keepalived.service` unit. Enable it so the daemon starts at
boot and start it right away with:

    # systemctl enable --now keepalived

Check its status and read the logs with:

    # systemctl status keepalived
    # journalctl -u keepalived
