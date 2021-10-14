#!/bin/sh

echo "[+] Stopping filebeat to remove useless files"
/usr/sbin/jexec rsyslog /usr/sbin/service filebeat stop
echo "[*] done"

echo "[+] Removing filebeat configuration files"
/bin/rm -f /usr/local/etc/filebeat/filebeat_*.yml
echo "[*] done"

