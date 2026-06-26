# Release 2.4.1 `26th June 2026`

This point release follows closely on 2.4.0 and aligns the `auth_hmac` VRRP
authentication extension, introduced in 2.4.0, with the updated IETF
Internet-Draft
[draft-cassen-vrrp-auth-hmac](https://datatracker.ietf.org/doc/draft-cassen-vrrp-auth-hmac/).
The on-the-wire trailer and its terminology changed, so every node in a virtual
router that uses `auth_hmac` must run the same version. A 2.4.1 node is not
guaranteed to interoperate with a 2.4.0 node for `auth_hmac`, so upgrade them
together. No other component is affected.

## Changed

- **vrrp**: the `auth_hmac` sequence number now splits into seconds, a
  sub-second fraction and a small counter. The sub-second timestamp makes
  same-instant ties rare, so the previous full width counter is no longer
  needed.

- **vrrp**: order `auth_hmac` sequences with serial number arithmetic
  ([RFC 1982](https://www.rfc-editor.org/rfc/rfc1982)) and a modular freshness
  window, so the field wrap is a non-event and no special epoch is required.

- **vrrp**: rename the trailer value from MAC to HMAC, since VRRP already uses
  MAC for the Ethernet address. This renames the related log message, the
  `Invalid HMAC` statistic, and the `auth_ext_invalid_hmac` JSON field.
