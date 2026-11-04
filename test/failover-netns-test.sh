#!/bin/bash
#
# End-to-end test of virtual server failover pools.
#
# Runs keepalived with a real IPVS table inside a network namespace, and
# changes which pool is in use by stopping and starting the real servers,
# checking the IPVS destinations after every step.
#
# Requirements (a VM is fine, a container usually is not):
#   - root
#   - a kernel with the ip_vs and ip_vs_rr modules available
#   - iproute2 and ipvsadm
#   - a built keepalived, and ./tcp_server (run "make tcp_server" here)
#
# Usage: sudo ./failover-netns-test.sh [path-to-keepalived]
#        The default is ../bin/keepalived.
#
# Topology, all inside network namespace $NS on the loopback interface:
#   VIP             10.255.0.1:80
#   primary pool    127.0.1.1-3:8080, quorum 2
#   failover pool 1 127.0.2.1-2:8080, quorum 2
#   failover pool 2 127.0.3.1:8080
#   sorry server    127.0.4.1:8080

KEEPALIVED=${1:-../bin/keepalived}
TCP_SERVER=./tcp_server
NS=kafailover
TMPDIR=$(mktemp -d)
CONF=$TMPDIR/keepalived.conf
PIDFILE=$TMPDIR/keepalived.pid
CHECKER_PIDFILE=$TMPDIR/checkers.pid

PRIMARY="127.0.1.1 127.0.1.2 127.0.1.3"
POOL1="127.0.2.1 127.0.2.2"
POOL2="127.0.3.1"
SORRY="127.0.4.1"
PORT=8080

fails=0

cleanup()
{
	[ -f "$PIDFILE" ] && kill "$(cat "$PIDFILE")" 2>/dev/null
	sleep 1
	ip netns pids $NS 2>/dev/null | xargs -r kill 2>/dev/null
	ip netns del $NS 2>/dev/null
	rm -rf "$TMPDIR"
}
trap cleanup EXIT

die()
{
	echo "ERROR: $*" >&2
	exit 1
}

[ "$(id -u)" -eq 0 ] || die "must be run as root"
command -v ip >/dev/null || die "iproute2 not installed"
command -v ipvsadm >/dev/null || die "ipvsadm not installed"
[ -x "$KEEPALIVED" ] || die "$KEEPALIVED not found - build keepalived first"
[ -x "$TCP_SERVER" ] || die "$TCP_SERVER not found - run: make tcp_server"
modprobe ip_vs 2>/dev/null
modprobe ip_vs_rr 2>/dev/null
grep -q '^ip_vs ' /proc/modules || die "ip_vs kernel module not available"

# ---------- environment ----------

ip netns add $NS || die "cannot create network namespace"
ip -n $NS link set lo up
ip -n $NS addr add 10.255.0.1/32 dev lo
# Allow IPVS NAT to the real servers on loopback for the traffic probes
ip netns exec $NS sysctl -q -w net.ipv4.conf.all.route_localnet=1
ip netns exec $NS sysctl -q -w net.ipv4.vs.conntrack=1 2>/dev/null

declare -A SERVER_PID

start_server()
{
	local addr=$1

	ip netns exec $NS $TCP_SERVER -4 -s -a "$addr" -p $PORT &
	SERVER_PID[$addr]=$!
	sleep 0.2
	kill -0 "${SERVER_PID[$addr]}" 2>/dev/null || die "cannot start server on $addr"
}

stop_server()
{
	local addr=$1

	kill "${SERVER_PID[$addr]}" 2>/dev/null
	wait "${SERVER_PID[$addr]}" 2>/dev/null
	unset "SERVER_PID[$addr]"
}

# rs_blocks <indent> <addr>...
rs_blocks()
{
	local indent=$1 addr
	shift

	for addr in "$@"; do
		cat <<-EOF
		$indent    real_server $addr $PORT {
		$indent        TCP_CHECK {
		$indent            connect_timeout 1
		$indent            retry 1
		$indent            delay_before_retry 1
		$indent        }
		$indent    }
		EOF
	done
}

# write_conf <primary quorum> <pool 1 quorum>
write_conf()
{
	{
		cat <<-EOF
		virtual_server 10.255.0.1 80 {
		    delay_loop 1
		    lvs_sched rr
		    lvs_method NAT
		    protocol TCP
		    quorum $1
		    sorry_server $SORRY $PORT
		EOF
		# shellcheck disable=SC2086
		rs_blocks "" $PRIMARY
		echo "    failover_pool 1 {"
		echo "        quorum $2"
		# shellcheck disable=SC2086
		rs_blocks "    " $POOL1
		echo "    }"
		echo "    failover_pool 2 {"
		# shellcheck disable=SC2086
		rs_blocks "    " $POOL2
		echo "    }"
		echo "}"
	} > "$CONF"
}

current_dests()
{
	# Only take the destination lines, which start with an address,
	# and only those with a weight, i.e. in use
	ip netns exec $NS ipvsadm -Ln 2>/dev/null | \
		awk '$1 == "->" && $2 ~ /^[0-9]/ && $4 != 0 { sub(/:.*/, "", $2); print $2 }' | sort | tr '\n' ' '
}

# expect_dests <description> <addr>...
expect_dests()
{
	local what=$1; shift
	local expected
	local i got

	expected=$(printf '%s\n' "$@" | sort | tr '\n' ' ')

	for ((i = 0; i < 60; i++)); do
		got=$(current_dests)
		[ "$got" = "$expected" ] && break
		sleep 0.5
	done

	if [ "$got" = "$expected" ]; then
		echo "PASS $what"
	else
		echo "FAIL $what"
		echo "    expected: [$expected]"
		echo "    got:      [$got]"
		ip netns exec $NS ipvsadm -Ln | sed 's/^/    /'
		fails=$((fails+1))
	fi
}

check_traffic()
{
	local what=$1

	# A completed TCP handshake through the VIP shows that IPVS forwards
	# to an alive real server. This is informational; the checks of the
	# IPVS table are what matter.
	if ip netns exec $NS nc -z -w 2 10.255.0.1 80 2>/dev/null; then
		echo "PASS $what (TCP connection through the VIP succeeded)"
	else
		echo "INFO $what: no connection through the VIP"
	fi
}

# ---------- test sequence ----------

for addr in $PRIMARY $POOL1 $POOL2 $SORRY; do
	start_server "$addr"
done

write_conf 2 2
ip netns exec $NS "$KEEPALIVED" -n -l -C -f "$CONF" -p "$PIDFILE" -c "$CHECKER_PIDFILE" &
KA_PID=$!
sleep 2
kill -0 $KA_PID 2>/dev/null || die "keepalived did not start"

# shellcheck disable=SC2086
expect_dests "startup: primary pool in use" $PRIMARY
check_traffic "startup traffic"

stop_server 127.0.1.1
expect_dests "1 of 3 primary down, quorum 2 kept: primary pool stays" 127.0.1.2 127.0.1.3

stop_server 127.0.1.2
# shellcheck disable=SC2086
expect_dests "2 of 3 primary down, quorum lost: failover pool 1 in use" $POOL1
check_traffic "failover pool 1 traffic"

start_server 127.0.1.2
expect_dests "primary pool regains quorum: primary pool in use again" 127.0.1.2 127.0.1.3

stop_server 127.0.1.2
stop_server 127.0.1.3
# shellcheck disable=SC2086
expect_dests "all primary down: failover pool 1 in use" $POOL1

stop_server 127.0.2.1
# shellcheck disable=SC2086
expect_dests "failover pool 1 loses quorum: failover pool 2 in use" $POOL2
check_traffic "failover pool 2 traffic"

stop_server 127.0.3.1
expect_dests "no pool has quorum: sorry server in use" $SORRY

start_server 127.0.2.1
# shellcheck disable=SC2086
expect_dests "failover pool 1 regains quorum: sorry server removed" $POOL1

for addr in 127.0.1.1 127.0.1.2 127.0.1.3 127.0.3.1; do
	start_server "$addr"
done
# shellcheck disable=SC2086
expect_dests "all recovered: primary pool in use" $PRIMARY

# Reload with primary quorum 3 and failover pool 1 quorum 1
write_conf 3 1
kill -HUP "$(cat "$PIDFILE")"
sleep 2
# shellcheck disable=SC2086
expect_dests "reload: primary pool still in use" $PRIMARY

stop_server 127.0.1.1
# shellcheck disable=SC2086
expect_dests "after reload, 1 primary down loses quorum 3: failover pool 1 in use" $POOL1

stop_server 127.0.2.1
expect_dests "after reload, failover pool 1 keeps quorum 1" 127.0.2.2

# Shutdown must clean the whole table
kill "$(cat "$PIDFILE")"
for ((i = 0; i < 30; i++)); do
	ip netns exec $NS ipvsadm -Ln | grep -q 10.255.0.1 || break
	sleep 0.5
done
if ! ip netns exec $NS ipvsadm -Ln | grep -q 10.255.0.1; then
	echo "PASS shutdown: IPVS table cleaned"
else
	echo "FAIL shutdown: IPVS table not cleaned"
	ip netns exec $NS ipvsadm -Ln | sed 's/^/    /'
	fails=$((fails+1))
fi

echo
if [ $fails -eq 0 ]; then
	echo "all integration tests passed"
else
	echo "$fails integration test(s) FAILED"
fi

[ $fails -eq 0 ]
