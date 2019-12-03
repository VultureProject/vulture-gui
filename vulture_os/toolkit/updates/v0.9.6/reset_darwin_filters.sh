#!/bin/sh

# If node bootstrapped
if [ -f /home/vlt-os/vulture_os/.install ] ; then
    # If it is the master mongo
    /bin/echo -n "Verifying if the current node is master : "
    if /usr/sbin/jexec mongodb /usr/local/bin/mongo --quiet --ssl --sslCAFile /var/db/pki/ca.pem --sslPEMKeyFile /var/db/pki/node.pem "`hostname`:9091/vulture" --eval "db.isMaster()['ismaster']" | /usr/bin/grep "true" ; then
        /usr/local/bin/sudo -u vlt-os /home/vlt-os/env/bin/python3.6 /home/vlt-os/vulture_os/manage.py loaddata filters
    else
        echo "false"
    fi
fi
