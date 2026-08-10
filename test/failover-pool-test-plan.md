# Failover pool test plan

Test plan for the virtual server failover pool feature: a backup pool of
health-checked real servers that replaces the primary pool when a
configurable percentage (by server count) of the primary pool has failed,
layered above the existing sorry server.

The suite has three tiers. Tiers 1 and 2 need no privileges and run
anywhere the tree builds; tier 3 exercises the real IPVS kernel path and
needs a root-capable VM.

## Environment requirements

### Tiers 1-2 (unit + config parsing)

- Linux with gcc, make, libssl-dev and the kernel UAPI headers
  (`linux/ip_vs.h`)
- autoconf, automake, pkg-config to generate `configure`
- No root, no `ip_vs` module and no network privileges required

### Tier 3 (VM integration)

- A VM (not an unprivileged container: the test loads kernel modules and
  creates network namespaces)
- root
- Kernel with `ip_vs` and `ip_vs_rr` modules (any distribution kernel)
- Packages:
  `autoconf automake libtool pkg-config gcc make libssl-dev libnl-3-dev libnl-genl-3-dev ipvsadm iproute2 procps`

## Build

```sh
./autogen.sh
./configure            # add --disable-libnl only if libnl-3-dev is unavailable
make -j"$(nproc)"
cd test
make failover_pool_test tcp_server
```

## Tier 1 - state machine unit test (no privileges)

```sh
cd test
./failover_pool_test
```

`failover_pool_test` compiles `keepalived/check/ipwrapper.c` against a
stubbed IPVS command layer that records every command issued, then asserts
the exact command sequences for:

1. default threshold (100%): no switch until every primary has failed
2. percentage rounding: 50%/34%/33% of 3 servers switch at 2, 2 and 1
   failures respectively (implicit ceiling)
3. exact boundary: 2 of 4 at 50% switches
4. recovery below the threshold reverts to the primary pool
5. a backup member flapping while active touches only that member
6. a primary flapping while the pool stays above threshold issues no
   IPVS commands
7. sorry server layering: activated only when the failover pool is
   exhausted, yields as soon as a backup recovers
8. legacy regression: without a failover pool the quorum / sorry server
   command sequences are unchanged
9. reload: `failover_state_up` and backup server state carry over with
   zero spurious commands; removing the pool on reload reinstates the
   alive primaries
10. reload with a checker-migration up event mid-diff: pool decisions
    are deferred until the diff is fully migrated, then converge with
    a single clean revert
11. inhibit_on_failure on a backup member applies only while the pool
    is active: reverting removes its weight-0 entry, and it is never
    inserted while the primary pool serves
12. alpha mode startup: sorry server first, failover pool once its
    checkers pass, primary pool once a primary recovers

Expected: every line `PASS`, final line `all tests passed`, exit code 0.

## Tier 2 - configuration parsing (no privileges)

```sh
cd test
./failover-config-test.sh          # uses ../bin/keepalived
```

Runs `keepalived --config-test` against good configurations (threshold,
default threshold, sorry server combination, notify scripts, full
real_server option set on backup members) expecting exit 0, and bad
configurations (threshold 0/150, failover options without a pool,
duplicate backup servers, backup duplicating a primary or the sorry
server, a VS with only backup servers) expecting exit 5 with the specific
error message.

Expected: `all config tests passed`, exit code 0.

## Tier 3 - VM integration test (root)

```sh
cd test
sudo ./failover-netns-test.sh      # uses ../bin/keepalived
```

The script builds this topology inside a dedicated network namespace, so
the host IPVS table and network configuration are never touched:

| Role          | Address            |
|---------------|--------------------|
| VIP           | 10.255.0.1:80      |
| primary pool  | 127.0.1.1-3:8080   |
| failover pool | 127.0.2.1-2:8080   |
| sorry server  | 127.0.3.1:8080     |

Each real server is a `tcp_server` instance; keepalived runs TCP_CHECKs
with a 1s delay loop. The script kills and restarts servers and asserts
the IPVS destination set (via `ipvsadm -Ln`) after every transition:

1. startup: primary pool in the table
2. 1 of 3 primaries down (33% < 50%): primary pool stays
3. 2 of 3 down (66% >= 50%): failover pool replaces the primaries
4. a primary recovers: primary pool reinstated
5. all primaries down: failover pool again
6. one backup down: remaining backup serves alone
7. failover pool exhausted: sorry server takes over
8. a backup recovers: sorry server yields
9. all primaries recovered: primary pool again
10. SIGHUP reload with threshold 100: no disturbance, and the new
    threshold takes effect (2 of 3 down no longer switches, 3 of 3 does)
11. shutdown: the IPVS table is fully cleaned

A traffic probe through the VIP is attempted at key points; it is
informational (NAT to loopback destinations may need `route_localnet`),
the table assertions are authoritative.

Expected: every step `PASS`, `all integration tests passed`, exit 0.

## Manual checks worth doing on the VM

- `keepalived --config-test -f doc/samples/keepalived.conf.failover_pool`
- Run with `-D` and watch the log for the
  `Switching to failover pool for VS ...` / `Reverting to primary pool
  for VS ...` messages and the `FAILOVER` / `FAILBACK` lines on a
  configured `notify_fifo`
- SNMP walks (if built with `--enable-snmp-checker`): backup pool members
  are intentionally not exposed in the RS tables yet; the walk must still
  terminate correctly with a pool configured
