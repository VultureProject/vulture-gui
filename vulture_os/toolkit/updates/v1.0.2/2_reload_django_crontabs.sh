#!/bin/sh

# If node already created
sudo -u  vlt-os /home/vlt-os/env/bin/python /home/vlt-os/vulture_os/manage.py check >/dev/null 2>&1
if [ $? = 0 ]; then
    /usr/local/bin/sudo -u vlt-os /home/vlt-os/env/bin/python /home/vlt-os/vulture_os/manage.py crontab remove
    /usr/local/bin/sudo -u vlt-os /home/vlt-os/env/bin/python /home/vlt-os/vulture_os/manage.py crontab add
fi
