Name: keepalived
Summary: HA monitor built upon LVS, VRRP and services poller
Packager: Christophe Varoqui, <christophe.varoqui@free.fr>
Version: 1.0.2
Release: 1
Source: http://www.keepalived.org/software/%{name}-%{version}.tar.gz
Copyright: GPL
Group: Applications/System
BuildRoot: /tmp/%{name}-%{version}.build

%define _exec_prefix /

%description
The main goal of the keepalived project is to add a strong & robust keepalive facility to the Linux Virtual Server project. This project is written in C with multilayer TCP/IP stack checks. Keepalived implements a framework based on three family checks : Layer3, Layer4 & Layer5. This framework gives the daemon the ability of checking a LVS server pool states. When one of the server of the LVS server pool is down, keepalived informs the linux kernel via a setsockopt call to remove this server entrie from the LVS topology. In addition keepalived implements a VRRPv2 stack to handle director failover. So in short keepalived is a userspace daemon for LVS cluster nodes healthchecks and LVS directors failover.

%prep
rm -rf %{buildroot}
%setup -q

%build
./configure --prefix=%{buildroot} --exec-prefix=%{buildroot} --sysconfdir=%{buildroot}/etc
make

%install
rm -rf %{buildroot}
%makeinstall

%clean
rm -rf %{buildroot}

%post
/sbin/chkconfig --add keepalived

%preun
/sbin/chkconfig --del keepalived

%files
%defattr(-,root,root)
%{_bindir}/genhash
%{_sbindir}/keepalived
%{_sysconfdir}/init.d/keepalived
%dir %{_sysconfdir}/keepalived/
%doc doc
%doc AUTHOR CONTRIBUTORS TODO COPYING README INSTALL VERSION ChangeLog

%changelog
* Fri Dec 20 2002 Jason Gilbert <jason@doozer.com> 0.7.6-dzr1
- Move the samples to be %doc instead of %config
- Install the init script as 'keepalived' instead of 'keepalived.init'
- Use the rpm %configure macro
- No initial config file supplied in /etc/keepalived since it's hard to say what
  a default config should be
