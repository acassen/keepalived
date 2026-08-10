#!/bin/bash
#
# End-to-end integration test for the virtual server failover pool.
#
# Runs keepalived with a real IPVS table inside a dedicated network
# namespace and drives pool transitions by killing and restarting the
# real servers, asserting the IPVS destination set after every step.
#
# Environment requirements (a VM is fine, a container usually is not):
#   - root
#   - kernel with the ip_vs and ip_vs_rr modules available
#   - packages: iproute2, ipvsadm, gcc, make (plus the keepalived build
#     dependencies: autoconf automake libtool pkg-config libssl-dev
#     libnl-3-dev libnl-genl-3-dev)
#   - a built ../bin/keepalived and ./tcp_server (run "make tcp_server")
#
# Usage: sudo ./failover-netns-test.sh [path-to-keepalived]
#
# Topology (everything inside netns $NS, all on loopback):
#   VIP            10.255.0.1:80
#   primary pool   127.0.1.1-3:8080
#   failover pool  127.0.2.1-2:8080
#   sorry server   127.0.3.1:8080

KEEPALIVED=${1:-../bin/keepalived}
TCP_SERVER=./tcp_server
NS=kfailover
TMPDIR=$(mktemp -d)
CONF=$TMPDIR/keepalived.conf
PIDFILE=$TMPDIR/keepalived.pid

PRIMARIES="127.0.1.1 127.0.1.2 127.0.1.3"
BACKUPS="127.0.2.1 127.0.2.2"
SORRY="127.0.3.1"
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
modprobe ip_vs ip_vs_rr 2>/dev/null
grep -q '^ip_vs ' /proc/modules || die "ip_vs kernel module not available"

# ---------- environment ----------

ip netns add $NS || die "cannot create netns"
ip -n $NS link set lo up
ip -n $NS addr add 10.255.0.1/32 dev lo
# Allow IPVS NAT to loopback-bound real servers for the traffic probes
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

write_conf()
{
	local threshold=$1

	{
		cat <<-EOF
		virtual_server 10.255.0.1 80 {
		    delay_loop 1
		    lvs_sched rr
		    lvs_method NAT
		    protocol TCP
		    quorum 1
		    failover_threshold $threshold
		    sorry_server $SORRY $PORT
		EOF
		for addr in $PRIMARIES; do
			cat <<-EOF
			    real_server $addr $PORT {
			        weight 1
			        TCP_CHECK {
			            connect_timeout 1
			            retry 1
			            delay_before_retry 1
			        }
			    }
			EOF
		done
		for addr in $BACKUPS; do
			cat <<-EOF
			    backup_real_server $addr $PORT {
			        weight 1
			        TCP_CHECK {
			            connect_timeout 1
			            retry 1
			            delay_before_retry 1
			        }
			    }
			EOF
		done
		echo "}"
	} > "$CONF"
}

current_dests()
{
	# Skip the "-> RemoteAddress:Port" column header - only take
	# destination lines, which start with a numeric address
	ip netns exec $NS ipvsadm -Ln 2>/dev/null | \
		awk '$1 == "->" && $2 ~ /^[0-9]/ { sub(/:.*/, "", $2); print $2 }' | sort | tr '\n' ' '
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

	# A completed TCP handshake through the VIP proves the IPVS NAT
	# path forwards to a live real server. Traffic flow is
	# informational; the table state assertions are authoritative.
	if ip netns exec $NS nc -z -w 2 10.255.0.1 80 2>/dev/null; then
		echo "PASS $what (TCP connection through the VIP succeeded)"
	else
		echo "INFO $what: no connection through the VIP"
	fi
}

# ---------- test sequence ----------

for addr in $PRIMARIES $BACKUPS $SORRY; do
	start_server "$addr"
done

write_conf 50
ip netns exec $NS "$KEEPALIVED" -n -l -f "$CONF" -p "$PIDFILE" &
KA_PID=$!
sleep 2
kill -0 $KA_PID 2>/dev/null || die "keepalived did not start"

expect_dests "startup: primary pool active" $PRIMARIES
check_traffic "startup traffic"

stop_server 127.0.1.1
expect_dests "1 of 3 primaries down (33% < 50%): primaries stay" 127.0.1.2 127.0.1.3

stop_server 127.0.1.2
expect_dests "2 of 3 primaries down (66% >= 50%): failover pool active" $BACKUPS
check_traffic "failover pool traffic"

start_server 127.0.1.2
expect_dests "primary recovered below threshold: revert to primary pool" 127.0.1.2 127.0.1.3

stop_server 127.0.1.2
stop_server 127.0.1.3
expect_dests "all primaries down: failover pool again" $BACKUPS

stop_server 127.0.2.1
expect_dests "one backup down: remaining backup serves" 127.0.2.2

stop_server 127.0.2.2
expect_dests "failover pool exhausted: sorry server takes over" $SORRY

start_server 127.0.2.1
expect_dests "backup recovered: sorry server yields" 127.0.2.1

for addr in 127.0.1.1 127.0.1.2 127.0.1.3 127.0.2.2; do
	start_server "$addr"
done
expect_dests "primaries recovered: primary pool again" $PRIMARIES

# Reload with a new threshold: only switch when every primary is down
write_conf 100
kill -HUP "$(cat "$PIDFILE")"
sleep 2
expect_dests "reload with threshold 100: primary pool unchanged" $PRIMARIES

stop_server 127.0.1.1
stop_server 127.0.1.2
expect_dests "2 of 3 down (66% < 100%): primaries stay" 127.0.1.3

stop_server 127.0.1.3
expect_dests "3 of 3 down: failover pool active" $BACKUPS

# Shutdown must clean the whole table
kill "$(cat "$PIDFILE")"
for ((i = 0; i < 30; i++)); do
	[ -z "$(current_dests)" ] && break
	sleep 0.5
done
if [ -z "$(current_dests)" ] && ! ip netns exec $NS ipvsadm -Ln | grep -q 10.255.0.1; then
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

exit $fails
