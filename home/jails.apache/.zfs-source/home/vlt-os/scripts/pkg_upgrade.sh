#!/bin/sh

if [ -f /etc/host-hostname ] ; then
    /usr/sbin/service vultured status && /bin/kill -9 $(/bin/cat /var/run/vulture/vultured.pid)
    echo "[38;5;196m! WARNING ! - Please start vultured at the end of the upgrade[0m"
    /usr/sbin/service netdata status && /usr/sbin/service netdata forcestop

    echo "[38;5;196m! WARNING ! - Please start netdata at the end of the upgrade[0m"

    #Relocate Python
    /usr/local/bin/virtualenv-3.6 /home/vlt-os/env/
    
    sleep 5
    /usr/local/bin/sudo -u vlt-os /home/vlt-os/env/bin/python3.6 /home/vlt-os/vulture_os/manage.py migrate
else
    echo "Node not bootstrapped yet."
fi
# Launch upgrade scripts depending on version
# Get old version
old_version="$(/bin/cat /home/vlt-os/vulture_os/gui_old_version)"
# If no old_version, do not do anything cause the package was not installed
if [ -z "$old_version" ] ; then
    exit 0
fi
for update_dir in $(ls /home/vlt-os/vulture_os/toolkit/updates)
do
    dir_version=$(echo "$update_dir" | cut -d 'v' -f 2)
    # If old_version < dir_version && dir_version <= current_version
    if [ "$(pkg version --test-version "$old_version" "$dir_version")" == "<" -a "$(pkg version --test-version "$dir_version" "$(pkg query "%v" vulture-gui)" | grep -E "<|=")" ]
    then
        /bin/chmod u+x /home/vlt-os/vulture_os/toolkit/updates/${update_dir}/*
        # Use ls to sort files and execute them orderly
        /bin/ls -1 /home/vlt-os/vulture_os/toolkit/updates/${update_dir}/* | while read line ; do echo "[+] Executing $line..." ; $line ; done
    fi
done
