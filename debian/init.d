#! /bin/sh
#
# keepalived   LVS cluster monitor daemon.
#
#              Written by Andres Salomon <dilinger@voxel.net>
#

PATH=/sbin:/bin:/usr/sbin:/usr/bin
DAEMON=/usr/sbin/keepalived
NAME=keepalived
DESC=keepalived

set -e
test -f $DAEMON || exit 0

case "$1" in
  start)
       echo -n "Starting $DESC: "
       start-stop-daemon --start --quiet --pidfile /var/run/$NAME.pid \
               --exec $DAEMON
       echo "$NAME."
       ;;
  stop)
       echo -n "Stopping $DESC: "
       start-stop-daemon --oknodo --stop --quiet --pidfile /var/run/$NAME.pid \
               --exec $DAEMON
       echo "$NAME."
       ;;
  reload|force-reload)
       echo "Reloading $DESC configuration file."
       start-stop-daemon --stop --quiet --signal 1 --pidfile \
               /var/run/$NAME.pid --exec $DAEMON
       ;;
  restart)
       echo -n "Restarting $DESC: "
       start-stop-daemon --stop --quiet --pidfile \
               /var/run/$NAME.pid --exec $DAEMON
       sleep 1
       start-stop-daemon --start --quiet --pidfile \
               /var/run/$NAME.pid --exec $DAEMON
       echo "$NAME."
       ;;
  *)
       echo "Usage: /etc/init.d/$NAME {start|stop|restart|reload|force-reload}" >&2
       exit 1
       ;;
esac

exit 0
