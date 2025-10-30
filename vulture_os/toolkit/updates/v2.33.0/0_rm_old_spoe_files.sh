#!/usr/bin/env sh

if [ -f /usr/local/etc/haproxy.d/spoe_session.txt ]; then
    echo "Removing old spoe_session.txt file in haproxy configurations..."
    /bin/rm /usr/local/etc/haproxy.d/spoe_session.txt
fi

echo "Done."
