#!/usr/bin/env sh

if /usr/sbin/service tshark status; then
    /bin/echo "Restarting tshark service..."
    /usr/sbin/service tshark restart
fi

/bin/echo "Done."
