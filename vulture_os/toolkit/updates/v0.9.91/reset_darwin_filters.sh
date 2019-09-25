#!/bin/sh

# If it is the master mongo
if /usr/sbin/jexec mongodb /usr/local/bin/mongo --quiet --ssl --sslCAFile /var/db/pki/ca.pem --sslPEMKeyFile /var/db/pki/node.pem "`hostname`:9091/vulture" --eval "db.isMaster()['ismaster']" | /usr/bin/grep "true" ; then
    /usr/local/bin/sudo -u vlt-os /home/vlt-os/env/bin/python3.6 /home/vlt-os/vulture_os/manage.py loaddata filters
fi
