#!/bin/sh

# Load initial data of logrotate

# If the loaddata has already been executed
if sudo -u  vlt-os /home/vlt-os/env/bin/python /home/vlt-os/vulture_os/manage.py check >/dev/null 2>&1; then
    # Install logrotate initial_data
    /usr/local/bin/sudo -u vlt-os /home/vlt-os/env/bin/python /home/vlt-os/vulture_os/manage.py loaddata logrotate_settings
fi
