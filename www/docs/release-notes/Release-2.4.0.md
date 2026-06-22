# Release 2.4.0 `22nd June 2026`

This is a major release, roughly a year after 2.3.4. Its headline feature is
`auth_hmac`, a new VRRP authentication extension that signs every advert with an
HMAC-SHA256 trailer. This closes the long standing exposure of unicast
deployments, where adverts cross routers and the TTL guard no longer protects
them, to off-segment spoofing and replay. The release also carries a broad
security hardening pass over the parser, netlink, checker, notify and DBus
paths, a few new configuration conveniences, and a fully rebuilt website on
Material for MkDocs.

## New

- **vrrp**: new `auth_hmac` authentication extension. It appends an HMAC-SHA256
  trailer to each advert, carrying a truncated tag and a time based sequence
  number, so a receiver can prove an advert came from a holder of the shared key
  and is fresh. It behaves the same for VRRPv2 and v3, IPv4 and IPv6, unicast and
  multicast, and it is the recommended protection for unicast where the TTL guard
  no longer holds. Keys are 32 to 64 bytes, carried inline, read from a `file:`,
  or sourced from a systemd encrypted credential, and support make before break
  rotation. A `mode permissive` eases migration on a running cluster, and per
  instance counters report the outcome of each verification. See the
  [VRRP HMAC Authentication](../articles/vrrp-hmac-authentication.md) article and
  the [keepalived.conf(5)](../documentation/keepalived-conf.md#vrrp-instances)
  man page.

- **config**: add `${_ENV ...}` to read values from environment variables, so
  secrets and host specific values stay out of `keepalived.conf`.

- **vrrp**: add the `vrrp_delay_after_boot` global keyword, and hold VRRP
  instances and gratuitous ARP until `vrrp_startup_delay` expires.

- **check**: add an SNMP variable for the number of checkers not run per real
  server.

## Security

- **check**: fix a heap buffer overflow in the HTTP checker regex partial match,
  where a crafted server response could overflow the checker buffer.

- **check**: fix a stack buffer overflow in `set_ping_group_range`.

- **parser**: resolve a heap buffer overflow, fix an invalid free and a SIGFPE
  in builtin definitions, and ignore config lines that contain NUL bytes.

- **core**: harden parsing of kernel and untrusted input. Bound netlink
  attribute access and require a kernel origin on netlink messages, bound the
  `/proc` stat parse in track_process, validate the BFD event pipe read length,
  and clamp the SMTP alert body offset.

- **notify**: validate the resolved symlink target of scripts and of the notify
  FIFO, and harden the script execution environment and quoting.

- **dbus**: deny keepalived methods by default, validate the object path, and
  narrow the `CreateInstance` vrid.

- **vrrp**: mask the authentication password in dump and JSON output, wipe HMAC
  key material after use, validate the VRRPv2 password against the checked
  length, and bound hardware address and interface name copies.

- **core**: abort on out of memory in `STRDUP`, `STRNDUP` and `REALLOC` rather
  than risk an invalid free, correct JSON string escaping, and set CLOEXEC on the
  IPVS netlink socket.

## Improvements

- **www**: the keepalived.org website is rebuilt on Material for MkDocs. The
  former Sphinx user guide is migrated into the new framework, the historical
  ChangeLog stays available, and the old Sphinx build dependencies and Coverity
  scaffolding are removed.

- **build**: discover OpenSSL through pkg-config, which drives the header checks
  and the link flags.

- **build**: resolve warnings and errors identified by gcc 16.

- **build**: portability fixes to `configure.ac`, using `command -v`, `printf`
  and the `=` test operator, and avoiding bash substring expansion.

- **snap**: stage the libssl3 and libkmod2 packages.

- **github**: build keepalived explicitly for CodeQL and bump codeql-action to
  v4.

## Fixes

- **vrrp**: fix the strict mode check for instances that have unicast peers.

- **vrrp**: correct the report of MASTER/BACKUP on the notify FIFO at reload.

- **vrrp**: warn when iptables rules cannot be applied, and remove VMAC firewall
  rules before deleting the link.

- **vrrp**: log an error when updating sysctl settings fails, and reset
  rate-limit flags only after accepting a packet.

- **check**: fix an MD5 context leak and a DNS response length check.

- **parser**: keep the full 64-bit value in `read_unsigned64`, fix
  `${NAME param}` substitution when trailing text follows, and handle `~SEQ`
  with a missing close bracket.

- **config**: improve parameter substitution, comment stripping and continuation
  lines, and check `PATH_MAX` when resolving track file paths.

- **snmp**: reject an out of range instance index and fix operator precedence.
