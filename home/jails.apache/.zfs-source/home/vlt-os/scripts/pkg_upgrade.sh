#!/bin/sh

if /usr/local/bin/sudo -u vlt-os /home/vlt-os/env/bin/python /home/vlt-os/vulture_os/manage.py check >/dev/null 2>&1; then
    /usr/sbin/service vultured status && /bin/kill -9 $(/bin/cat /var/run/vulture/vultured.pid)
    echo "[38;5;196m! WARNING ! - Please start vultured at the end of the upgrade[0m"

    sleep 5
    /usr/local/bin/sudo -u vlt-os /home/vlt-os/env/bin/python /home/vlt-os/vulture_os/manage.py migrate

    # Add crontabs (removed in pre_install routine)
    /usr/local/bin/sudo -u vlt-os /home/vlt-os/env/bin/python /home/vlt-os/vulture_os/manage.py crontab add

else
    echo "Node not bootstrapped yet."
    exit 0
fi
# Launch upgrade scripts depending on version
# Get old version
old_version="$(/bin/cat /home/vlt-os/vulture_os/gui_old_version)"
# If no old_version, do not do anything cause the package was not installed
if [ -z "$old_version" ] ; then
    exit 0
fi
for dir_version in $(basename $(ls -d /home/vlt-os/vulture_os/toolkit/updates/v*) | cut -d 'v' -f 2 | sort -t '.' -k1n -k2n -k3n)
do
    # If old_version < dir_version && dir_version <= current_version
    if [ "$(pkg version --test-version "$old_version" "$dir_version")" == "<" -a "$(pkg version --test-version "$dir_version" "$(pkg query "%v" vulture-gui)" | grep -E "<|=")" ]
    then
        /bin/chmod u+x /home/vlt-os/vulture_os/toolkit/updates/v${dir_version}/*
        # Use ls to sort files and execute them orderly
        /bin/ls -1 /home/vlt-os/vulture_os/toolkit/updates/v${dir_version}/* | while read line ; do echo "[+] Executing $line..." ; $line ; done
    fi
done
