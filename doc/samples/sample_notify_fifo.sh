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
TIMEOUT=10

FIFO=$1
[[ -z $FIFO ]] && echo "A FIFO name must be specified" && exit 1

LOG_FILE=/tmp/${FIFO##*/}.log

if [[ -d /run ]]; then
    PID_DIR=/run
elif [[ -d /var/run ]]; then
    PID_DIR=/var/run
else
    PID_DIR=/tmp
fi
PID_FILE=$PID_DIR/${FIFO##*/}.pid

exiting()
{
	# When this script exists, this function is always executed because
	# it is associated to the bash EXIT signal.
    [[ $CREATED_FIFO -eq 1 ]] && rm -f $FIFO

    flock -u $FD
}

reload_terminate()
{
    exit 0
}

stopping()
{
	PROLOGUE=$(echo "$(date +"%a %b %e %X %Y")": \[$PPID:$$\])
	echo "$PROLOGUE" STOPPING >>$LOG_FILE
	exit 0
}

start_shutdown()
{
	SHUTDOWN=1

	# When keepalived terminates, it sends a TERM signal to this script before
	#  sending the fifo notifies. We catch the SIGTERM here, and after a short
	#  delay send a SIGALRM to the main script process
	( sleep 0.5
	  kill -ALRM $$ 2>/dev/null
	) &
}

trap stopping HUP INT QUIT USR1 USR2 PIPE ALRM
trap reload_terminate QUIT
trap start_shutdown TERM
trap exiting EXIT

exec {FD}>>"$PID_FILE"
if ! flock -e -n $FD; then
		# Send SIGQUIT signal to the previous instance of this script.
		# The previous script waits for its current executed command to end
		# before actually calling reload_terminate(). The TIMEOUT value must
		# take this constraint into account.
       OLD_PID=$(cat $PID_FILE)
       if ls -l /proc/$OLD_PID/fd | grep -qw "$(readlink -f "$PID_FILE")"
       then
			kill -QUIT $OLD_PID
       fi
       flock -e --timeout $TIMEOUT $FD || exit 1
fi
echo $$ >"$PID_FILE"

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
# When keepalived reloads, it sends the script a SIGTERM, and
# then closes the FIFO. Since keepalived removes the FIFO,
# creates a new one and runs the (possibly changed) FIFO script
# again, we need to terminate if the FIFO is closed and we have
# received a SIGTERM.
# When keepalived stops it sends SIGTERM to the script and
# afterwards send STOPPING messages, so we need to continue
# reading the FIFO until it is closed.
FIFO_INODE=$(stat -c "%i" $FIFO)
[[ $? -ne 0 ]] && echo FIFO $FIFO not accessible >>$LOG_FILE && exit 1

while [[ $SHUTDOWN -eq 0 ]]
do
	[[ ! -p $FIFO ]] && echo FIFO $FIFO missing >>$LOG_FILE && exit 1
	exec <$FIFO
	[[ $? -ne 0 || $(stat -c "%i" $FIFO 2>/dev/null) -ne $FIFO_INODE ]] && break

	while read line; do
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
	done

	[[ $SHUTDOWN -eq 0 ]] && echo "$PROLOGUE" FIFO CLOSED >>$LOG_FILE
done

stopping
