#! /bin/bash

# Usage:
#  netns-test.sh [options]
#
# This script will create interfaces in a network namespace (default test)
# that are needed for the specified keepalived configuration (or all
# interfaces if configuration explicitly set to ""), so that keepalived
# can be run in that namespace for testing or other purposes.

DFLT_NS=test
DFLT_CONF=/etc/keepalived/keepalived.conf

NS_NAME=$DFLT_NS
CONF=$DFLT_CONF
IP=ip
CREATE_PREFIX=
EXTRA_IF=

CREATED_IFACES=
SHOW_IFACES=

show_help()
{
	cat <<EOF
$0 - Usage:
        -h              Show this!
	-n		network namespace name (default test)
	-f		keepalived config file to read interfaces from
			  if no config file, all interfaces will be duplicated
	-i		command to use instead of \`ip\`
	-u		use 'unshare -n' before creating network namespace
	-x		create interfaces in config file that don't exist
	-p		show created interfaces
EOF
}

while getopts ":hn:f:i:uxp" opt; do
	case $opt in
	h)
		show_help
		exit 0
		;;
	n)
		NS_NAME=$OPTARG
		;;
	f)
		CONF=$OPTARG
		;;
	i)
		IP=$OPTARG
		;;
	u)
		CREATE_PREFIX="unshare -n"
		;;
	x)
		EXTRA_IF=yes
		;;
	p)
		SHOW_IFACES=yes
		;;
	?)
		echo Unknown option \'$OPTARG\' && show_help && exit 1
		;;
	esac
done

[[ -n $CONF && ! -f $CONF ]] && echo Cannot read config file $CONF && exit 1

IPN="$IP netns exec $NS_NAME $IP"

if [[ -n $CONF ]]; then
	IFACES=$(grep interface $CONF | sed -e "s/[!#].*//" -e "s/interface //" | sort -u)
	IFACES=$(echo $IFACES)
	IFACES=" $IFACES "

	HOSTED_IFACES=$($IP link show | grep @ | sed -e "s/^[0-9]*: //" -e "s/:.*//")

	# Add parents of any sub interfaces
	for if in $HOSTED_IFACES; do
		[[ $IFACES =~ " ${if%@*} " ]] && IFACES="$IFACES ${if##*@} "
	done
else
	IFACES=
fi

$IP netns del $NS_NAME 2>/dev/null

$CREATE_PREFIX $IP netns add $NS_NAME

$IPN link set up lo

ip addr show | \
while read line; do
	set $line
	if [[ ${line:0:1} =~ [1-9] ]]; then
		iface=$(<<<$line sed -e "s/^[0-9]*: *//" -e "s/:.*//")
		[[ -n $IFACES && ! $IFACES =~ " ${iface%@*} " ]] && iface= && continue

		if [[ $iface =~ @ ]]; then
			# This is an interface built on top of another one
			vlan_info=$(grep "^${iface%@*} " /proc/net/vlan/config)
			if [[ -n $vlan_info ]]; then
				set $vlan_info
				vlan_id=$3
				vlan_parent=$5
			fi

			iface=${iface%@*}
		else
			vlan_id=
		fi
		continue
	fi

	[[ -z $iface ]] && continue

	if [[ $line =~ "link/ether" ]]; then
		if [[ -n $vlan_id ]]; then
			$IPN link add link $vlan_parent name $iface type vlan id $vlan_id
		else
			$IPN link add $iface address $2 broadcast $4 type dummy
		fi
		$IPN link set up $iface
		CREATED_IFACES=" $CREATED_IFACES $iface "
	elif [[ $1 = inet ]]; then
		[[ $3 = brd ]] && BCAST="$3 $4" || BCAST=
		$IPN addr add $2 $BCAST dev $iface 2>/dev/null
	elif [[ $1 = inet6 ]]; then
		# We could try and detect the default link local address, and not try to
		# add it again, but let's just be lazy and ignore an error.
		$IPN addr add $2 dev $iface 2>/dev/null
	else
:		echo Unknown line: $line
	fi
done

# Now deal with any additional interfaces in the config that don't exist
if [[ -n $CONF ]]; then
	for if in $IFACES; do
		if [[ ! $CREATED_IFACES =~ " $if " ]]; then
			if [[ -z $EXTRA_IF ]]; then
				echo Interface $if specified in configuration file doesn\'t exist
			else
				$IPN link add $if type dummy
				$IPN link set up $if
			fi
		fi
	done
fi

[[ -n $SHOW_IFACES ]] && $IPN addr show

[[ -n $CONF ]] && EXTRA=" for config $CONF" || EXTRA=
echo
echo Network namespace $NS_NAME set up to mirror default namespace$EXTRA.
echo
[[ -n $CONF ]] && echo To test keepalived execute \`$IP netns exec $NS_NAME keepalived [OPTIONS] -f $CONF -s $NS_NAME\` && echo
echo Don\'t forget to delete namespace $NS_NAME with \'$IP netns del $NS_NAME\' when finished.
echo
