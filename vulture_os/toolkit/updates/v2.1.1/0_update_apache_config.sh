#!/bin/sh

if [ -d /zroot/apache ] ; then
    cp -r /home/jails.apache/.zfs-source/usr/local/etc/apache24/* /zroot/apache/usr/local/etc/apache24/
    echo "[38;5;196m! WARNING ! - Please restart apache with : '/usr/sbin/jexec apache /usr/sbin/service apache24 restart'[0m"
fi
