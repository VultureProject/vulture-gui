#!/usr/bin/env sh

/bin/echo "[+] Updating .env files to ensure default Redis host used is '127.0.0.5' (Haproxy Load-Balancer)..."

/usr/sbin/sysrc -f /home/vlt-os/vulture_os/vulture_os/.env VULTURE_REDIS_HOST="127.0.0.5"
/usr/sbin/sysrc -f /home/vlt-os/vulture_os/portal/.env VULTURE_REDIS_HOST="127.0.0.5"

/bin/echo "[-] Done."