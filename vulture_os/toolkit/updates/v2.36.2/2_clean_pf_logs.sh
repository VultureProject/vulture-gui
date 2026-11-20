#!/usr/bin/env sh

files_count="$(/usr/bin/find /zroot/rsyslog/var/log/garbage/ -atime +30d | wc -l)"
echo "Cleaning ${files_count} pf logs that are more than 30 days old..."
/usr/bin/find /zroot/rsyslog/var/log/garbage/ -atime +30d -delete
echo "Done."
