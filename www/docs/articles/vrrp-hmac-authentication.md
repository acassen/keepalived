---
description: Authenticate VRRP adverts with an HMAC-SHA256 trailer to stop off-segment injection and replay on unicast deployments.
# 1200x630 social/LinkedIn preview card:
image: images/vrrp-hmac-card.png
---

# VRRP HMAC Authentication
<p class="article-byline">Alexandre Cassen, &lt;<a href="mailto:acassen@gmail.com">acassen@gmail.com</a>&gt;<!--readtime--></p>

!!! danger "Strongly recommended for unicast"
    VRRP over unicast carries no authentication of its own. The TTL guard that
    protects multicast falls away once adverts cross a router, so an off-segment
    attacker can spoof an advert that demotes your master or forces an election.
    We strongly encourage every unicast deployment to enable `auth_hmac`, and the
    rest of this page shows how.

VRRP authenticates an advert by trusting the hop limit. An active router sends
every advert with an IPv4 TTL or IPv6 hop limit of 255, and a receiver drops
anything that arrives lower, which proves the packet never crossed a router.
That guard is the Generalized TTL Security Mechanism, and it is the only
protection VRRPv3 carries. It holds only as long as adverts stay on one link.

Unicast breaks that assumption. When Keepalived runs in a cloud or overlay
network where multicast is unavailable, adverts travel as routed unicast to a
configured peer list, they cross hops, and they arrive well below 255. The
receiver has to relax the check to accept them, and once it does, nothing stops
an off-segment attacker. Anyone who can land a spoofed packet at the receiver
injects a higher priority advert to demote the master, or a priority 0 advert
to force an election, and captured adverts replay just as easily.

```text
   Routed / overlay: no multicast, TTL decremented en route

     ACTIVE  --- advert (VRID 51, prio 200) --->  BACKUP
   198.51.100.10                              192.0.2.10
       ^
       |  spoofed advert: src = 192.0.2.10 (a peer), prio 255
   ATTACKER
   203.0.113.9
```

The `auth_hmac` extension closes that gap. It appends a trailer to each advert
carrying an HMAC-SHA256 tag truncated to 128 bits and a time-based sequence
number. The tag proves the advert came from a holder of the shared key and was
not altered, the sequence number proves it is fresh, and both behave the same
for VRRPv2 and v3, IPv4 and IPv6, unicast and multicast. It encrypts nothing,
because adverts are not secret, and a captured advert is useless once it leaves
the freshness window. The legacy `authentication` block never offered this. Its
cleartext password travels in the open, which is why RFC 3768 removed it, and
the IPSEC-AH option only ever existed for VRRPv2.

!!! info "Specification"
    The wire format, the pseudo-header bound into the MAC, and the full threat
    model are specified in the [IETF Internet-Draft](#ietf-draft) referenced at
    the bottom of this page.

## Minimal configuration

The extension links OpenSSL and rides on the same build flag that enabled the
legacy `authentication` block. Every node in the virtual router shares the same
keys under the same key ids, since the construction is symmetric and
provisioning the key material to each node is your responsibility. With no
`mode` set the block enforces, so a node rejects any advert that lacks a valid
trailer. To bring the extension up on a running cluster without dropping
adverts, start in permissive mode while you roll out, as described below.

The two nodes carry a near-mirror configuration, the active on `198.51.100.10`
and the backup on `192.0.2.10`. Only the `state`, the `priority` and the unicast
addresses differ between them.

=== "Active node"

    ```
    vrrp_instance VI_1 {
        state MASTER
        interface eth0
        virtual_router_id 51
        priority 200
        advert_int 1

        unicast_src_ip 198.51.100.10
        unicast_peer {
            192.0.2.10
        }

        auth_hmac {
            key 1 hex:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
            active_key 1
            anti_replay time
            time_window 5
        }

        virtual_ipaddress {
            192.0.2.100/32
        }
    }
    ```

=== "Backup node"

    ```
    vrrp_instance VI_1 {
        state BACKUP
        interface eth0
        virtual_router_id 51
        priority 100
        advert_int 1

        unicast_src_ip 192.0.2.10
        unicast_peer {
            198.51.100.10
        }

        auth_hmac {
            key 1 hex:000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f
            active_key 1
            anti_replay time
            time_window 5
        }

        virtual_ipaddress {
            192.0.2.100/32
        }
    }
    ```

The `auth_hmac` block is identical on both nodes, as it is on every node in the
virtual router. `key` defines a signing key by id, `active_key` selects the id
used when sending, and a receiver verifies an incoming advert against whichever
configured key its `key_id` names. `auth_hmac` and the legacy `authentication`
block are mutually exclusive, and Keepalived drops the legacy one when both
appear.

## Generating and sourcing keys

A key is 32 to 64 bytes, and 32 random bytes is the right default because it
keeps a 128 bit margin even against a quantum search. Generate one with:

```sh
openssl rand -hex 32
```

Carry the value inline as a `hex:` string or an ASCII passphrase, and the
secret then lives in `keepalived.conf`. To keep it out of the configuration,
read it from a file instead, where the file holds the same `hex:` line or a raw
ASCII key:

```
key 1 file:/etc/keepalived/keys/vrrp51
```

Keepalived warns when that file is readable by group or others, so keep it
`root` owned and mode `0600`.

## Keys from systemd credentials

The strongest way to source a key pairs `file:` with a systemd encrypted
credential, which seals the key to the TPM or host key and never writes it to
disk in the clear. Provision the credential once, sealed and readable only by
root:

```sh
umask 077
install -d /etc/keepalived/creds
printf 'hex:%s' "$(openssl rand -hex 32)" > /run/vrrp51.plain
systemd-creds encrypt --name=vrrp51 \
    /run/vrrp51.plain /etc/keepalived/creds/vrrp51.cred
shred -u /run/vrrp51.plain
```

Then add a unit drop-in so systemd decrypts it at start, installed as
`/etc/systemd/system/keepalived.service.d/auth_hmac.conf`:

```
[Service]
LoadCredentialEncrypted=vrrp51:/etc/keepalived/creds/vrrp51.cred
```

After `systemctl daemon-reload && systemctl restart keepalived`, systemd
decrypts the credential, exposes it read only to root on a private tmpfs at
`/run/credentials/keepalived.service`, drops it when the unit stops, and points
`$CREDENTIALS_DIRECTORY` there. Reference it from `keepalived.conf` with the
`${_ENV ...}` expansion, where the credential name is the last path component:

```
auth_hmac {
    key 1 file:${_ENV CREDENTIALS_DIRECTORY}/vrrp51
    active_key 1
}
```

Without a TPM or host key, swap `LoadCredentialEncrypted` for `LoadCredential`
with a plaintext key file, which still lands on the same root only tmpfs, just
not encrypted at rest.

To carry several keys, for instance across a rotation, give each key id its own
credential. Provision each one as above, then list them in the drop-in with a
numbered scheme:

```
[Service]
LoadCredentialEncrypted=vrrp51_1:/etc/keepalived/creds/vrrp51_1.cred
LoadCredentialEncrypted=vrrp51_2:/etc/keepalived/creds/vrrp51_2.cred
```

systemd writes one file per credential under `$CREDENTIALS_DIRECTORY`, so each
key id reads from its own:

```
auth_hmac {
    key 1 file:${_ENV CREDENTIALS_DIRECTORY}/vrrp51_1
    key 2 file:${_ENV CREDENTIALS_DIRECTORY}/vrrp51_2
    active_key 1
}
```

A numbered unit line per key works, but you edit the unit on every rotation. To
avoid that, keep the encrypted blobs in the system credential store and import
the whole set with one glob. Encrypt each key into `/etc/credstore.encrypted/`,
where the filename is the credential name:

```sh
printf 'hex:%s' "$(openssl rand -hex 32)" \
    | systemd-creds encrypt --name=vrrp51_1 - /etc/credstore.encrypted/vrrp51_1
```

A single directive then imports every match, while the `key` lines stay exactly
as above:

```
[Service]
ImportCredential=vrrp51_*
```

Adding a key later is one more `systemd-creds encrypt` into the store plus a
`key` line, with no unit edit, since the glob already covers it.
`ImportCredential=` needs systemd 254 or newer. A ready to install drop-in with
these variants ships under `doc/samples/`.

## Replay protection

`anti_replay time`, the default, enforces a freshness window and a per-sender
monotonic sequence, so it needs the nodes to agree on wall clock time within
`time_window` seconds. The window accepts 1 to 300 seconds and defaults to
`max(3 x advert_int, 5)`, and a small window such as 5 seconds is a good start
when NTP is healthy. `anti_replay monotonic` drops the clock dependency and only
asks each sender's sequence to keep growing, which suits deployments that cannot
guarantee synchronized clocks, at the cost of the freshness guarantee.

## Rolling out without breaking the cluster

A Keepalived that does not understand the trailer drops any advert that carries
one, because the receive path checks the exact length and fails closed. Sequence
the migration so no node sends a signed advert to a node that cannot yet accept
it.

1. Upgrade the binary on every node first, with no configuration change, so
   nothing signs and the cluster behaves as before.
2. Add the `auth_hmac` block in `mode permissive` everywhere, then reload the
   nodes in a tight sweep. A reloaded node signs and, being permissive, still
   accepts unsigned adverts from peers not yet reloaded. Keep the sweep well
   under the master down interval, since a not yet reloaded peer drops the
   signed adverts and a long sweep risks a needless election.
3. Confirm every node now sends and verifies trailers. Authenticated adverts
   flow both ways, though an unsigned injected advert is still accepted while
   you stay permissive.
4. Switch `mode enforce` everywhere and reload again. Every peer already signs,
   so nothing drops, and from now on an advert without a valid trailer is
   rejected.

`strict_mode` requires `enforce`, so finish the migration before turning strict
mode on.

## Rotating keys

Because a receiver accepts any configured key id, rotation is make before break.
Add the new key under a fresh id on every node while keeping the old
`active_key`, then reload so each node verifies both ids while still signing
with the old one:

```
key 1 file:/etc/keepalived/keys/vrrp51
key 2 file:/etc/keepalived/keys/vrrp51.new
active_key 1
```

Move `active_key 2` on every node and reload, so senders switch to the new key
that receivers already accept, then drop the retired key and reload once more.

## Verifying the rollout

Keepalived logs and counts each authentication outcome per instance, rate
limited, so you can watch the migration and spot trouble. A missing trailer is
informational in permissive mode and means a node is not signing once you
enforce. An invalid MAC points at a key mismatch or a forgery attempt. A stale
trailer is reported apart from an invalid MAC, so you can tell clock drift from
an attack, and a clock skew warning fires on accepted adverts once the skew
passes half the window, which is the early signal to fix NTP before adverts
start failing.

## Configuration reference

The [keepalived.conf(5)](../documentation/keepalived-conf.md#vrrp-instances) man page carries
the same `auth_hmac` block in its VRRP instance example as the canonical
reference. The keywords are:

| Keyword | Values | Default | Notes |
|---|---|---|---|
| `key <id> <value>` | id 1 to 255; value `hex:...`, an ASCII string, or `file:<path>` | none | 32 to 64 bytes, define several for rotation |
| `active_key <id>` | 1 to 255 | none | the id used when signing |
| `anti_replay` | `time` or `monotonic` | `time` | `time` needs synced clocks |
| `time_window <sec>` | 1 to 300 | `max(3 x advert_int, 5)` | freshness window, `time` mode only |
| `mode` | `enforce` or `permissive` | `enforce` | start `permissive` to migrate |

## Security notes

The construction is symmetric with no key exchange on the wire, so it has no
exposure to Shor's algorithm and stays post-quantum resistant by design. A
quantum search only halves the effective key strength, which is the reason for
the 32 byte minimum, since it preserves a 128 bit margin. The MAC binds the
address family, VRRP version, virtual router id, and source address into the
digest, so an attacker cannot splice a valid trailer onto a different instance
or a different sender, while the IP header stays out of the MAC, which keeps the
design clean across IPv4, IPv6, and the unicast TTL handling. The trailer adds
28 bytes to each advert, and Keepalived reserves that room when it decides how
many virtual addresses fit in a packet, so on an instance whose address list
sits near the interface MTU a few addresses move to the excluded set rather than
overflowing the packet.

## IETF draft { #ietf-draft }

The on-the-wire format and the security analysis are specified in an IETF
Internet-Draft, *An HMAC Authentication Extension for the Virtual Router
Redundancy Protocol (VRRP)* (`draft-cassen-vrrp-auth-hmac`), by A. Cassen and
Q. Armitage. The link will point at the IETF Datatracker once the draft is
published.

<!-- TODO: replace with the Datatracker URL once draft-cassen-vrrp-auth-hmac is published -->
