#!/bin/sh

/home/vlt-os/env/bin/python /home/vlt-os/vulture_os/manage.py migrate
if [ $? -ne 0 ] ; then
    /bin/echo "ERROR:: migrate : Please solve and relaunch bootstrap"
    exit 1
fi

/home/vlt-os/env/bin/python /home/vlt-os/vulture_os/manage.py loaddata applications filters services_settings default_template repositories tenants reputation_ctx
if [ $? -ne 0 ] ; then
    /bin/echo "ERROR:: initial data: Please solve and relaunch bootstrap"
    exit 1
fi

/home/vlt-os/env/bin/python /home/vlt-os/vulture_os/manage.py crontab add
if [ $? -ne 0 ] ; then
    /bin/echo "ERROR:: crontab add : Please solve and relaunch bootstrap"
    exit 1
fi
