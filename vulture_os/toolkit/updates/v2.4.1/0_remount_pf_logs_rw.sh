#!/usr/bin/env sh

if ! /usr/bin/grep -E ".*/zroot/rsyslog/var/log/pf.*rw,late.*" /etc/fstab >/dev/null ; then
    /bin/echo "[*] Remounting /var/log/pf to /zroot/rsyslog/var/log/pf as read-write..."
    /sbin/umount -f /zroot/rsyslog/var/log/pf
    sed -i '' '/rsyslog\/var\/log\/pf/ s/ro,late/rw,late/' /etc/fstab
    /sbin/mount -f /zroot/rsyslog/var/log/pf
    /bin/echo "[*] Ok!"
fi
