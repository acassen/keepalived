#!/bin/bash
# Run in an isolated network namespace, e.g.:
# unshare -Urn test/interface-churn.sh "$PWD/bin/keepalived"
set -eu

if [ "$(readlink /proc/self/ns/net)" = "$(readlink /proc/1/ns/net)" ]; then
	echo "Run this test in a separate network namespace" >&2
	exit 77
fi
binary=$(realpath "$1")
work=$(mktemp -d)
pid=
cleanup()
{
	status=$?
	if [ -n "$pid" ]; then
		kill "$pid" 2>/dev/null || :
		wait "$pid" 2>/dev/null || status=1
	fi
	if [ -f "$work/log" ]; then
		if grep -Eq 'AddressSanitizer|runtime error:' "$work/log"; then
			status=1
		fi
		[ "$status" -eq 0 ] || cat "$work/log" >&2
	fi
	rm -rf "$work"
	exit "$status"
}
trap cleanup EXIT

for name in ka0 tracked0 route0; do
	ip link add "$name" type dummy
	ip link set "$name" multicast on up
done
ip address add 10.99.0.2/24 dev ka0
cat >"$work/config" <<CONF
global_defs {
	router_id CHURN
	state_dump_file $work/state
}
static_routes {
	198.51.100.0/24 dev route0 no_track
}
vrrp_instance VI_1 {
	state MASTER
	interface ka0
	virtual_router_id 51
	priority 150
	advert_int 1
	track_interface {
		tracked0 weight 1
	}
	virtual_ipaddress {
		10.99.0.78/24
	}
}
CONF
"$binary" -n -l -G -R -f "$work/config" -p "$work/parent.pid" \
	-r "$work/vrrp.pid" >"$work/log" 2>&1 &
pid=$!
for ((i=0; i<100; i++)); do
	[ ! -s "$work/vrrp.pid" ] || break
	sleep .05
done
if [ ! -s "$work/vrrp.pid" ]; then
	cat "$work/log"
	exit 1
fi
child=$(cat "$work/vrrp.pid")

churn()
{
	for ((i=0; i<100; i++)); do
		ip link add "ka_t$i" type veth peer name "ka_p$i"
		ip link delete "ka_t$i"
	done
}

check_dump()
{
	rm -f "$work/state"
	kill -USR1 "$child"
	for ((i=0; i<100; i++)); do
		if [ -s "$work/state" ]; then
			writing=false
			for fd in /proc/"$child"/fd/*; do
				if [ "$(readlink "$fd" || :)" = "$work/state" ]; then
					writing=true
					break
				fi
			done
			$writing || break
		fi
		sleep .05
	done
	grep -q 'Name = ka0$' "$work/state"
	grep -q 'Name = tracked0$' "$work/state"
	grep -q 'Name = route0$' "$work/state"
	if grep -Eq 'Name = (ka_t[0-9]+|ka_p[0-9]+|ka_old|ka_base|ka_mac|ka_vrf|ka_member)$' "$work/state"; then
		echo "Deleted transient interfaces were retained" >&2
		grep 'Name = ' "$work/state" >&2
		exit 1
	fi
	kill -0 "$child"
}

churn
ip link add ka_base type dummy
ip link add ka_mac link ka_base type macvlan mode private
ip link delete ka_base
if ip link add ka_vrf type vrf table 100; then
	ip link add ka_member type dummy
	ip link set ka_member master ka_vrf
	ip link delete ka_vrf
	ip link show ka_member >/dev/null
	ip link delete ka_member
else
	echo "Skipping VRF exercise: kernel support unavailable"
fi
ip link add ka_old type dummy
ip link set ka_old name ka_new
check_dump
grep -q 'Name = ka_new$' "$work/state"

# Configured interfaces survive deletion, including an untracked route device.
for name in ka0 tracked0 route0; do
	ip link delete "$name"
done
check_dump
for name in ka0 tracked0 route0; do
	ip link add "$name" type dummy
	ip link set "$name" multicast on up
done
ip address add 10.99.0.2/24 dev ka0
churn
check_dump
for ((i=0; i<100; i++)); do
	if ip -4 address show dev ka0 | grep -q '10.99.0.78/24'; then
		break
	fi
	sleep .05
done
ip -4 address show dev ka0 | grep -q '10.99.0.78/24'

# Recreated configuration references must survive another deletion.
for name in ka0 tracked0 route0; do
	ip link delete "$name"
done
check_dump
echo "Interface churn and configuration retention passed"
