#!/bin/bash

# To use this script, copy it to directory /etc/keepalived/scripts
# and add one or more of the following to the keepalived configuration
# file in the global_defs section:
#     notify_fifo /etc/keepalived/scripts/notify_fifo
#     vrrp_notify_fifo /etc/keepalived/scripts/vrrp_notify_fifo
#     lvs_notify_fifo /etc/keepalived/scripts/lvs_notify_fifo
# This script will then need to be executed, passing it the name of the
# fifo.
#
# As an alternative to executing this script manually, add one or more of
# the following in the global_defs section of the config:
#     notify_fifo_script /etc/keepalived/scripts/sample_notify_fifo.sh
#     vrrp_notify_fifo_script /etc/keepalived/scripts/sample_notify_fifo.sh
#     lvs_notify_fifo_script /etc/keepalived/scripts/sample_notify_fifo.sh
# If run this way, Keepalived will terminate the script with SIGTERM when
# it exits.

CREATED_FIFO=0
SHUTDOWN=0

FIFO=$1
[[ -z $FIFO ]] && echo "A FIFO name must be specified" && exit 1

LOG_FILE=/tmp/${FIFO##*/}.log

stopping()
{
	PROLOGUE=$(echo "$(date +"%a %b %e %X %Y")": \[$PPID:$$\])
	echo "$PROLOGUE" STOPPING >>$LOG_FILE
	[[ $CREATED_FIFO -eq 1 ]] && rm -f $FIFO
	exit 0
}

start_shutdown()
{
	# When keepalived terminates, it sends a TERM signal to this script before
	#  sending the fifo notifies. We catch the SIGTERM here, and after a short
	#  delay send a SIGALRM to the main script process

	SHUTDOWN=1

	( sleep 0.5
	  kill -ALRM $$ 2>/dev/null
	) &
}

trap stopping HUP INT QUIT USR1 USR2 PIPE ALRM
trap start_shutdown TERM

if [[ ! -p $FIFO ]]; then
	mkfifo $FIFO
	if [[ $? -eq 0 ]]; then
		CREATED_FIFO=1
	else
		echo "Unable to create fifo $FIFO" >>$LOG_FILE
		exit 1
	fi
fi

# If keepalived terminates, the FIFO will be closed, so
# read the FIFO in a loop. It keepalived hasn't opened the
# FIFO, the script will be blocked until it has been opened.
while [[ 1 ]]
do
	[ $SHUTDOWN -eq 1 ] && break
	[[ ! -p $FIFO ]] && echo FIFO $FIFO missing >>$LOG_FILE && exit 1

	while [ $SHUTDOWN -eq 0 ] && read line; do
		PROLOGUE=$(echo "$(date +"%a %b %e %X %Y")": \[$PPID:$$\])
		set $line
		TYPE=$1
		if [[ $TYPE = INSTANCE || $TYPE = GROUP ]]; then
			VRRP_INST=${2//\"/}
			STATE=$3
			PRIORITY=$4

			# Now take whatever action is required
			echo "$PROLOGUE" $TYPE $VRRP_INST $STATE $PRIORITY >>$LOG_FILE
		elif [[ $TYPE = VS ]]; then
			VS=$2
			STATE=$3

			# Now take whatever action is required
			echo "$PROLOGUE" $TYPE $VS $STATE >>$LOG_FILE
		elif [[ $TYPE = RS ]]; then
			RS=$2
			VS=$3
			STATE=$4

			# Now take whatever action is required
			echo "$PROLOGUE" $TYPE $RS $VS $STATE >>$LOG_FILE
		else
			echo "$PROLOGUE" $TYPE - unknown "($*)" >>$LOG_FILE
		fi
	done < $FIFO

	echo "$PROLOGUE" STOPPED >>$LOG_FILE
done

stopping
