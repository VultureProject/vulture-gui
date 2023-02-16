#!/usr/bin/env sh

/bin/echo "Cleaning up old configuration..."

/home/vlt-os/scripts/write_netconfig.sh "" "network" 0 > /dev/null
/bin/rm -f /etc/rc.conf.d/routing
/bin/rm -f /etc/rc.conf.d/netaliases*

/bin/echo "Done."
