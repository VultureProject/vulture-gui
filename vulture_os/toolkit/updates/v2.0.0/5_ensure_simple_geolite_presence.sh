#!/bin/sh

city=`ls -1 /var/db/darwin/GeoLite2-City_* 2> /dev/null | head -n 1`
country=`ls -1 /var/db/darwin/GeoLite2-Country_* 2> /dev/null | head -n 1`

if [ -n "$city" ] && [ ! -f /var/db/darwin/GeoLite2-City.mmdb ] ; then
    /bin/cp $city /var/db/darwin/GeoLite2-City.mmdb.tmp
    /bin/mv /var/db/darwin/GeoLite2-City.mmdb.tmp /var/db/darwin/GeoLite2-City.mmdb
    chown vlt-os:vlt-conf /var/db/darwin/GeoLite2-City.mmdb
    /usr/local/bin/sudo /usr/sbin/jexec rsyslog /usr/sbin/service rsyslogd reload || true
fi;

if [ -n "$country" ] && [ ! -f /var/db/darwin/GeoLite2-Country.mmdb ]; then
    /bin/cp $country /var/db/darwin/GeoLite2-Country.mmdb.tmp
    /bin/mv /var/db/darwin/GeoLite2-Country.mmdb.tmp /var/db/darwin/GeoLite2-Country.mmdb
    chown vlt-os:vlt-conf /var/db/darwin/GeoLite2-Country.mmdb
    /usr/local/bin/sudo /usr/sbin/jexec rsyslog /usr/sbin/service rsyslogd reload || true
fi;
