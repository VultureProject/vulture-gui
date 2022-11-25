#!/bin/sh

echo "[+] Stopping apache into apache jail"
/usr/sbin/jexec apache /usr/sbin/service apache24 stop
echo "[*] done"

/bin/rm /zroot/apache/etc/rc.conf.d/apache24

echo "[+] Installation of nginx into apache jail"
/usr/sbin/pkg -j apache install -y nginx || (/bin/echo "Fail to install nginx!" ; exit 1)
echo "[*] done"

/bin/echo 'gunicorngui_enable="YES"' > /zroot/apache/etc/rc.conf.d/gunicorngui
/bin/echo 'nginx_enable="YES"' > /zroot/apache/etc/rc.conf.d/nginx
