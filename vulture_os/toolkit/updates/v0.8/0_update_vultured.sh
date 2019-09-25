#!/bin/sh

if [ -f /var/run/vulture/vultured.pid ] ; then
    /bin/kill -9 $(/bin/cat /var/run/vulture/vultured.pid)
fi

/bin/echo "[!] Please start vultured at the end of the update [!]"
