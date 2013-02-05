#! /bin/sh
# 
# Gael Charriere <gael.charriere@gmail.com>
# 10.11.2008
#
# Invoked by keepalived from master/slave
# to slave/master transition to add or remove
# a PREROUTING rule
#
# Essential for slave to redirect incoming 
# service packet to localhost. Otherwise a
# loop can appear between master and slave.
# 
# The routing table is consulted when a packet
# that creates a new connection is encountered.
# PREROUTING rule alters packets as soon as they come in.
# REDIRECT statement redirects the packet to the machine
# itself by changing the destination IP to the primary
# address of the incoming interface (locally-generated
# packets are mapped to the 127.0.0.1 address).

# Check number of command line args
EXPECTED_ARGS=2
if [ $# -ne $EXPECTED_ARGS ]; then
  echo "Usage: $0 {add|del} ipaddress"
  exit 1
fi

# Check if second arg is a valid ip address
VIP=$2
OLD_IFS=$IFS
IFS="."
VIP=( $VIP )
IFS=$OLD_IFS
# Check that ip has 4 parts
if [ ${#VIP[@]} -ne 4 ]; then
  echo "IP address must have 4 parts"
  echo "Usage: $0 {add|del} ipaddress"
  exit 1
fi

# Check that each parts is a number which
# varies between 0 and 255
for oct in ${VIP[@]} ; do
  echo $oct | egrep "^[0-9]+$" >/dev/null 2>&1
  if [ $? -ne 0 ]; then
    echo "$oct: Not numeric"
    echo "Usage: $0 {add|del} ipaddress"
    exit 1
  else
    if [ $oct -lt 0 -o $oct -gt 255 ]; then
      echo "$oct: Out of range"
      echo "Usage: $0 {add|del} ipaddress"
      exit 1
    fi
  fi
done

# If we are here, ip address is validated
VIP="${VIP[0]}.${VIP[1]}.${VIP[2]}.${VIP[3]}"

# Add or remove the prerouting rule
case "$1" in
  add)
  	# check if the rule was already specified
  	n=$(iptables -t nat -L| grep $VIP | wc -l)
    if [[ $n == 0 ]]; then
    	# the rule was not found, add it
    	iptables -A PREROUTING -t nat -d $VIP -p tcp -j REDIRECT
    fi
    ;;
  del)
  	# check if the rule was already specified
    n=$(iptables -t nat -L| grep $VIP | wc -l)
    while [[ $n > 0 ]]; do
    	# remove the rule
    	iptables -D PREROUTING -t nat -d $VIP -p tcp -j REDIRECT
    	n=$(($n-1))
    done
    ;;
  *)
    echo "Usage: $0 {add|del} ipaddress"
    exit 1
esac
exit 0

