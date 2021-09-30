#!/bin/sh

if [ -f /zroot/rsyslog/var/run/filebeat.pid ] ; then
    if /bin/kill -0 "$(cat /zroot/rsyslog/var/run/filebeat.pid)" ; then
        /bin/kill -TERM "$(cat /zroot/rsyslog/var/run/filebeat.pid)"
    fi
fi

