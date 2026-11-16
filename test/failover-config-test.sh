#!/bin/bash
#
# Configuration tests for virtual server failover pools.
#
# Runs keepalived --config-test, which needs no privileges, against good
# and bad configurations and checks the exit status and the reported
# errors. keepalived exits 0 for an acceptable configuration and 5
# (KEEPALIVED_EXIT_CONFIG) when a configuration error was reported.
#
# Usage: failover-config-test.sh [path-to-keepalived]
#        The default is $KEEPALIVED, which "make check" sets, or
#        ../bin/keepalived.

KEEPALIVED=${1:-${KEEPALIVED:-../bin/keepalived}}
TMPDIR=$(mktemp -d)
trap 'rm -rf "$TMPDIR"' EXIT

fails=0

# run <name> <expected-exit> <expected-message-regex (empty = none)>
run()
{
	local name=$1 expected_status=$2 expected_msg=$3
	local output status

	output=$("$KEEPALIVED" --config-test -f "$TMPDIR/$name.conf" 2>&1)
	status=$?

	if [ "$status" -ne "$expected_status" ]; then
		echo "FAIL $name: exit $status, expected $expected_status"
		echo "$output" | sed 's/^/    /'
		fails=$((fails+1))
		return
	fi

	if [ -n "$expected_msg" ] && ! grep -q -- "$expected_msg" <<< "$output"; then
		echo "FAIL $name: expected message '$expected_msg' not reported"
		echo "$output" | sed 's/^/    /'
		fails=$((fails+1))
		return
	fi

	echo "PASS $name"
}

vs_open()
{
	cat <<-EOF
	virtual_server 10.10.10.2 80 {
	    delay_loop 5
	    lvs_sched rr
	    lvs_method NAT
	    protocol TCP
	EOF
}

# rs_block <address> [<weight>] [<indent>]
rs_block()
{
	local indent=${3:-}

	if [ -n "$2" ]; then
		cat <<-EOF
		$indent    real_server $1 80 {
		$indent        weight $2
		$indent        TCP_CHECK { connect_timeout 3 }
		$indent    }
		EOF
	else
		cat <<-EOF
		$indent    real_server $1 80 {
		$indent        TCP_CHECK { connect_timeout 3 }
		$indent    }
		EOF
	fi
}

pool_rs_block()
{
	rs_block "$1" "$2" "    "
}

# ---------- good configurations ----------

{ vs_open
  rs_block 192.168.1.1; rs_block 192.168.1.2
  echo "    failover_pool 1 {"
  pool_rs_block 192.168.2.1; pool_rs_block 192.168.2.2
  echo "    }"
  echo "}"
} > "$TMPDIR/good-one-pool.conf"
run good-one-pool 0 ""

# Pools may be configured in any order, and with gaps in the priorities
{ vs_open
  echo "    quorum 2"
  rs_block 192.168.1.1; rs_block 192.168.1.2
  echo "    failover_pool 20 {"
  pool_rs_block 192.168.3.1
  echo "    }"
  echo "    failover_pool 5 {"
  echo "        quorum 2"
  echo "        hysteresis 1"
  pool_rs_block 192.168.2.1; pool_rs_block 192.168.2.2; pool_rs_block 192.168.2.3
  echo "    }"
  echo "    sorry_server 192.168.200.200 80"
  echo "}"
} > "$TMPDIR/good-multiple-pools.conf"
run good-multiple-pools 0 ""

# The quorum of a pool is a weight
{ vs_open
  rs_block 192.168.1.1
  echo "    failover_pool 1 {"
  echo "        quorum 4"
  pool_rs_block 192.168.2.1 3; pool_rs_block 192.168.2.2
  echo "    }"
  echo "}"
} > "$TMPDIR/good-pool-weights.conf"
run good-pool-weights 0 ""

# The real servers of a pool take all the real_server options
{ cat <<-EOF
	global_defs {
	    enable_script_security
	    script_user $(id -un)
	}
	EOF
  vs_open
  rs_block 192.168.1.1
  cat <<-EOF
	    failover_pool 1 {
	        quorum_up "/bin/true pool up"
	        quorum_down "/bin/true pool down"
	        real_server 192.168.2.1 80 {
	            weight 3
	            inhibit_on_failure
	            notify_up "/bin/true rs up"
	            notify_down "/bin/true rs down"
	            MISC_CHECK { misc_path "/bin/true" }
	        }
	    }
	}
	EOF
} > "$TMPDIR/good-pool-full-options.conf"
run good-pool-full-options 0 ""

# ---------- bad configurations ----------

{ vs_open
  rs_block 192.168.1.1
  echo "    failover_pool 0 {"
  pool_rs_block 192.168.2.1
  echo "    }"
  echo "}"
} > "$TMPDIR/bad-priority-zero.conf"
run bad-priority-zero 5 "failover_pool priority 0 must be in \[1, 255\]"

{ vs_open
  rs_block 192.168.1.1
  echo "    failover_pool 256 {"
  pool_rs_block 192.168.2.1
  echo "    }"
  echo "}"
} > "$TMPDIR/bad-priority-256.conf"
run bad-priority-256 5 "failover_pool priority 256 must be in \[1, 255\]"

{ vs_open
  rs_block 192.168.1.1
  echo "    failover_pool {"
  pool_rs_block 192.168.2.1
  echo "    }"
  echo "}"
} > "$TMPDIR/bad-priority-missing.conf"
run bad-priority-missing 5 "failover_pool priority .* must be in"

{ vs_open
  rs_block 192.168.1.1
  echo "    failover_pool 1 {"
  pool_rs_block 192.168.2.1
  echo "    }"
  echo "    failover_pool 1 {"
  pool_rs_block 192.168.3.1
  echo "    }"
  echo "}"
} > "$TMPDIR/bad-duplicate-priority.conf"
run bad-duplicate-priority 5 "failover_pool 1 is duplicated"

{ vs_open
  rs_block 192.168.1.1
  echo "    failover_pool 1 {"
  echo "        quorum 1"
  echo "    }"
  echo "}"
} > "$TMPDIR/bad-empty-pool.conf"
run bad-empty-pool 5 "failover_pool 1 has no real servers"

# A virtual server needs real servers outside its failover pools
{ vs_open
  echo "    failover_pool 1 {"
  pool_rs_block 192.168.2.1
  echo "    }"
  echo "}"
} > "$TMPDIR/bad-pool-only.conf"
run bad-pool-only 5 "has no real servers other than in failover pools"

# A real server can only be in one pool; the pool then has none left
{ vs_open
  rs_block 192.168.1.1
  echo "    failover_pool 1 {"
  pool_rs_block 192.168.1.1
  echo "    }"
  echo "}"
} > "$TMPDIR/bad-cross-pool-duplicate.conf"
run bad-cross-pool-duplicate 5 "real server .* is duplicated"

{ vs_open
  echo "    sorry_server 192.168.2.1 80"
  rs_block 192.168.1.1
  echo "    failover_pool 1 {"
  pool_rs_block 192.168.2.1; pool_rs_block 192.168.2.2
  echo "    }"
  echo "}"
} > "$TMPDIR/bad-pool-rs-is-sorry.conf"
run bad-pool-rs-is-sorry 5 "failover pool 1 real server .* is the sorry server"

{ vs_open
  rs_block 192.168.1.1
  echo "    failover_pool 1 {"
  echo "        quorum 3"
  pool_rs_block 192.168.2.1; pool_rs_block 192.168.2.2
  echo "    }"
  echo "}"
} > "$TMPDIR/bad-pool-quorum.conf"
run bad-pool-quorum 5 "quorum 3 for failover pool 1 of .* exceeds total weight of its real servers 2"

{ vs_open
  rs_block 192.168.1.1
  echo "    failover_pool 1 {"
  echo "        quorum 2"
  echo "        hysteresis 2"
  pool_rs_block 192.168.2.1; pool_rs_block 192.168.2.2
  echo "    }"
  echo "}"
} > "$TMPDIR/bad-pool-hysteresis.conf"
run bad-pool-hysteresis 5 "failover pool 1 hysteresis 2 >= quorum 2"

# Virtual server keywords other than the quorum ones are not pool keywords
{ vs_open
  rs_block 192.168.1.1
  echo "    failover_pool 1 {"
  echo "        lvs_sched wrr"
  pool_rs_block 192.168.2.1
  echo "    }"
  echo "}"
} > "$TMPDIR/bad-pool-keyword.conf"
run bad-pool-keyword 5 "Unknown keyword 'lvs_sched'"

echo
if [ $fails -eq 0 ]; then
	echo "all config tests passed"
else
	echo "$fails config test(s) FAILED"
fi

[ $fails -eq 0 ]
