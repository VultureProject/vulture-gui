#!/usr/bin/env sh


/bin/echo "[+] Fixing filebeat mountpoints..."
/usr/sbin/chown vlt-os:wheel /usr/local/etc/filebeat
/usr/sbin/chown vlt-os:wheel /usr/local/etc/filebeat/filebeat_*

if /usr/bin/grep -Eq "/zroot/rsyslog/usr/local/etc/filebeat[[:space:]]+/usr/local/etc/filebeat" /etc/fstab ; then
    /bin/echo "Fixing filebeat mountpoint from host to rsyslog jail..."
    temp_dir=$(mktemp -d)
    /bin/mv /zroot/rsyslog/usr/local/etc/filebeat/* ${temp_dir}/
    /sbin/umount /usr/local/etc/filebeat
    /usr/sbin/chown vlt-os:wheel /usr/local/etc/filebeat
    /usr/bin/sed -Ei "" "s|^(/zroot/rsyslog)(/usr/local/etc/filebeat)[[:space:]]+/usr|\2 \1/usr|g" /etc/fstab
    /sbin/mount -aL
    /bin/mv ${temp_dir}/* /usr/local/etc/filebeat/
fi

if /usr/bin/grep -Eq "/zroot/rsyslog/usr/local/etc/filebeat[[:space:]]+/zroot/apache/usr/local/etc/filebeat" /etc/fstab ; then
    /bin/echo "Fixing filebeat mountpoint from host to apache jail..."
    /sbin/umount /zroot/apache/usr/local/etc/filebeat
    /usr/sbin/chown vlt-os:wheel /zroot/apache/usr/local/etc/filebeat
    /usr/bin/sed -Ei "" "s|^/zroot/rsyslog(/usr/local/etc/filebeat[[:space:]]+/zroot)|\1|g" /etc/fstab
    /sbin/mount -aL
fi
