Summary: Generic HA monitor build upon VRRP and services poller, strongly recommanded for LVS HA.
Name: keepalived
Packager: Christophe Varoqui, <christophe.varoqui@free.fr>
Version: 0.7.6
Release: 1
Source: http://www.keepalived.org/software/keepalived-0.7.6.tar.gz
Copyright: GPL
Group: Utilities/File
BuildRoot: /tmp/%{name}-%{version}.build
BuildArchitectures: i386

%description
The main goal of the keepalived project is to add a strong & robust keepalive facility to the Linux Virtual Server project. This project is written in C with multilayer TCP/IP stack checks. Keepalived implements a framework based on three family checks : Layer3, Layer4 & Layer5. This framework gives the daemon the ability of checking a LVS server pool states. When one of the server of the LVS server pool is down, keepalived informs the linux kernel via a setsockopt call to remove this server entrie from the LVS topology. In addition keepalived implements a VRRPv2 stack to handle director failover. So in short keepalived is a userspace daemon for LVS cluster nodes healthchecks and LVS directors failover.

%prep
rm -rf %{buildroot}
%setup -n keepalived-0.7.6

%build
./configure --prefix=%{buildroot} --exec-prefix=%{buildroot} --sysconfdir=%{buildroot}/etc
make

%install
make install

%files
%defattr(-,root,root)
/bin/genhash
/sbin/keepalived
/etc/init.d/keepalived.init
%config /etc/keepalived/keepalived.conf
%config /etc/keepalived/samples/*
%doc AUTHOR CONTRIBUTORS TODO COPYING README INSTALL VERSION ChangeLog
