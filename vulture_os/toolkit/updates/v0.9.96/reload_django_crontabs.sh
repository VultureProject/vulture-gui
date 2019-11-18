#!/bin/sh

# If node already created
if [ -f /home/vlt-os/vulture_os/.install ] ; then
    /usr/local/bin/sudo -u vlt-os /home/vlt-os/env/bin/python /home/vlt-os/vulture_os/manage.py crontab remove
    /usr/local/bin/sudo -u vlt-os /home/vlt-os/env/bin/python /home/vlt-os/vulture_os/manage.py crontab add
fi
