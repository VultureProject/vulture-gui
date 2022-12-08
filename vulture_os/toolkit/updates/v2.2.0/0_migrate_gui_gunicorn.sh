#!/bin/sh

echo "[+] Stopping apache into apache jail"
/usr/sbin/jexec apache /usr/sbin/service apache24 stop
echo "[*] done"

/bin/rm /zroot/apache/etc/rc.conf.d/apache24

echo "[+] Installation of nginx into apache jail"
/usr/sbin/pkg -j apache remove -y www/apache24 || (/bin/echo "apache24 already removed!" ; exit 1)
/usr/sbin/pkg -j apache remove -y www/mod_wsgi4 || (/bin/echo "mod_wsgi4 already removed!" ; exit 1)
/usr/sbin/pkg -j apache autoremove -y
# Ensure python is installed (can be removed through mod_wsgi4)
/usr/sbin/pkg -j apache install -y lang/python || (/bin/echo "Fail to install python!" ; exit 1)
/usr/sbin/pkg -j apache install -y nginx || (/bin/echo "Fail to install nginx!" ; exit 1)
echo "[*] done"

echo "[+] Mounting new folders in apache jail"
mount_path="/var/sockets/gui /zroot/apache/var/sockets/gui"
if [ "$(/usr/bin/grep "$mount_path" "/etc/fstab" 2> /dev/null)" == "" ]  ; then
    /bin/echo "$mount_path nullfs   rw,late      0       0" >> "/etc/fstab"
fi
if [ "$(/sbin/mount -p | /usr/bin/sed -E 's/[[:cntrl:]]+/ /g' | /usr/bin/grep "$mount_path")" == "" ] ; then
    /sbin/mount_nullfs -o rw,late $mount_path
fi
echo "[*] done"

echo "[+] Enabling gunicorn and nginx services"
/bin/echo 'gunicorn_enable="YES"' > /zroot/apache/etc/rc.conf.d/gunicorn
/bin/echo 'nginx_enable="YES"' > /zroot/apache/etc/rc.conf.d/nginx
echo "[*] done"
