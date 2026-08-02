#!/bin/bash
#
# Configuration parsing tests for the virtual server failover pool.
#
# Runs keepalived --config-test (which needs no privileges) against a set
# of good and bad configurations and checks the exit status and reported
# errors. keepalived exits 0 for an acceptable configuration and 5
# (KEEPALIVED_EXIT_CONFIG) when a configuration error was reported.
#
# Usage: ./failover-config-test.sh [path-to-keepalived]
#        (defaults to ../bin/keepalived)

KEEPALIVED=${1:-../bin/keepalived}
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

	if [ -n "$expected_msg" ] && ! grep -q "$expected_msg" <<< "$output"; then
		echo "FAIL $name: expected message '$expected_msg' not reported"
		echo "$output" | sed 's/^/    /'
		fails=$((fails+1))
		return
	fi

	echo "PASS $name"
}

# Common fragments
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

rs_block()
{
	cat <<-EOF
	    real_server $1 80 {
	        weight ${2:-1}
	        TCP_CHECK { connect_timeout 3 }
	    }
	EOF
}

backup_rs_block()
{
	cat <<-EOF
	    backup_real_server $1 80 {
	        weight ${2:-1}
	        TCP_CHECK { connect_timeout 3 }
	    }
	EOF
}

# ---------- good configurations ----------

{ vs_open
  echo "    failover_threshold 50"
  rs_block 192.168.1.1; rs_block 192.168.1.2
  backup_rs_block 192.168.2.1; backup_rs_block 192.168.2.2
  echo "}"
} > "$TMPDIR/good-pool-threshold.conf"
run good-pool-threshold 0 ""

{ vs_open
  rs_block 192.168.1.1
  backup_rs_block 192.168.2.1
  echo "}"
} > "$TMPDIR/good-pool-default-threshold.conf"
run good-pool-default-threshold 0 ""

{ vs_open
  echo "    failover_threshold 100"
  echo "    sorry_server 192.168.200.200 80"
  rs_block 192.168.1.1
  backup_rs_block 192.168.2.1
  echo "}"
} > "$TMPDIR/good-pool-with-sorry.conf"
run good-pool-with-sorry 0 ""

{ vs_open
  echo '    failover_up "/bin/true up"'
  echo '    failover_down "/bin/true down"'
  rs_block 192.168.1.1
  backup_rs_block 192.168.2.1
  echo "}"
} > "$TMPDIR/good-pool-notify.conf"
run good-pool-notify 0 ""

# backup_real_server accepts the full real_server option set
{ cat <<-EOF
	global_defs {
	    enable_script_security
	    script_user $(id -un)
	}
	EOF
  vs_open
  rs_block 192.168.1.1
  cat <<-EOF
	    backup_real_server 192.168.2.1 80 {
	        weight 3
	        inhibit_on_failure
	        notify_up "/bin/true bup"
	        notify_down "/bin/true bdown"
	        MISC_CHECK { misc_path "/bin/true" }
	    }
	}
	EOF
} > "$TMPDIR/good-pool-full-options.conf"
run good-pool-full-options 0 ""

# ---------- bad configurations ----------

{ vs_open
  echo "    failover_threshold 0"
  rs_block 192.168.1.1
  backup_rs_block 192.168.2.1
  echo "}"
} > "$TMPDIR/bad-threshold-zero.conf"
run bad-threshold-zero 5 "Failover threshold 0 must be in \[1, 100\]"

{ vs_open
  echo "    failover_threshold 150"
  rs_block 192.168.1.1
  backup_rs_block 192.168.2.1
  echo "}"
} > "$TMPDIR/bad-threshold-150.conf"
run bad-threshold-150 5 "Failover threshold 150 must be in \[1, 100\]"

{ vs_open
  echo "    failover_threshold 50"
  rs_block 192.168.1.1
  echo "}"
} > "$TMPDIR/bad-threshold-without-pool.conf"
run bad-threshold-without-pool 5 "failover_threshold specified without backup_real_servers"

{ vs_open
  echo '    failover_up "/bin/true up"'
  rs_block 192.168.1.1
  echo "}"
} > "$TMPDIR/bad-notify-without-pool.conf"
run bad-notify-without-pool 5 "failover_up specified without backup_real_servers"

{ vs_open
  rs_block 192.168.1.1
  backup_rs_block 192.168.1.1
  echo "}"
} > "$TMPDIR/bad-cross-pool-duplicate.conf"
run bad-cross-pool-duplicate 5 "duplicates a real server"

{ vs_open
  echo "    sorry_server 192.168.2.1 80"
  rs_block 192.168.1.1
  backup_rs_block 192.168.2.1
  echo "}"
} > "$TMPDIR/bad-backup-duplicates-sorry.conf"
run bad-backup-duplicates-sorry 5 "duplicates the sorry server"

{ vs_open
  backup_rs_block 192.168.2.1
  backup_rs_block 192.168.2.1
  rs_block 192.168.1.1
  echo "}"
} > "$TMPDIR/bad-duplicate-backup.conf"
run bad-duplicate-backup 5 "backup real server .* is duplicated"

# A VS with only backup servers has no primary pool and is rejected
{ vs_open
  backup_rs_block 192.168.2.1
  echo "}"
} > "$TMPDIR/bad-backup-only.conf"
run bad-backup-only 5 "has no real servers"

echo
if [ $fails -eq 0 ]; then
	echo "all config tests passed"
else
	echo "$fails config test(s) FAILED"
fi

exit $fails
