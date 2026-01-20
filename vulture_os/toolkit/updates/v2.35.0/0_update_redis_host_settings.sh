#!/usr/bin/env sh

if [ -f /home/vlt-os/vulture_os/vulture_os/.env ]; then
    /usr/sbin/sysrc -f /home/vlt-os/vulture_os/vulture_os/.env VULTURE_REDIS_HOST="127.0.0.5"
fi

echo "Done."
