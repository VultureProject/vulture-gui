#!/usr/bin/env sh

/bin/echo "backing up network and system configuration files..."

for file in /etc/rc.conf /etc/rc.conf.d/network /etc/rc.conf.d/routing /etc/rc.conf.d/netaliases*
do
    filename=$(/usr/bin/basename $file)
    /bin/echo "Backing up file $file to /var/backups/${filename}.bak"
    /bin/cp -f "${file}" "/var/backups/${filename}.bak"
done

/bin/echo "Done."
