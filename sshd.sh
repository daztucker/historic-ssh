#! /bin/sh
#
# $Id: sshd.sh,v 1.6 1999/10/31 12:23:06 bg Exp $
#
# chkconfig: 345 75 25
# description: OSSH Secure Shell Daemon

if   [ -x /usr/local/libexec/sshd ]; then
     SSHD=/usr/local/libexec/sshd
elif [ -x /usr/libexec/sshd ]; then
     SSHD=/usr/libexec/sshd
else
     SSHD=/usr/local/sbin/sshd
fi

if    [ -d /var/run ]; then
  SSHD_PID=/var/run/sshd.pid
else
  SSHD_PID=/etc/sshd.pid
fi

rval=0
case "$1" in
  start_msg)
    echo "Start secure shell daemon"
    ;;
  stop_msg)
    echo "Stopping secure shell daemon"
    ;;
  start|'')
    $SSHD
    rval=$?
    echo -n " sshd"
    ;;
  stop)
    [ -f $SSHD_PID ] || exit 0
    kill -TERM `cat $SSHD_PID`
    rval=$?
    rm -f $SSHD_PID
    echo " sshd"
    ;;
  restart)
    $0 stop
    $0 start
    rval=$?
    ;;
  status)
    [ -f $SSHD_PID ] || exit 1
    cat $SSHD_PID
    rval=$?
    ;;
  *)
    echo "Usage: $0 {start|stop|restart|status}"
    rval=1
esac

exit $rval
