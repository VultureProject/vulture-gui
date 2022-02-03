#!/bin/sh

echo "[+] Stopping apache into portal jail"
/usr/sbin/jexec portal /usr/sbin/service apache24 stop
echo "[*] done"

/bin/rm /zroot/portal/etc/rc.conf.d/apache24

/bin/echo 'gunicorn_enable="YES"' > /zroot/portal/etc/rc.conf.d/gunicorn
