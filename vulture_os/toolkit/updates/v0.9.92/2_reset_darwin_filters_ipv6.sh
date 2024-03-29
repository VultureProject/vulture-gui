#!/bin/sh

# If node already created
if /usr/local/bin/sudo -u vlt-os /home/vlt-os/env/bin/python /home/vlt-os/vulture_os/manage.py is_node_bootstrapped >/dev/null 2>&1; then
    # If IPv6 - Make v0.9 migration
    if /usr/sbin/sysrc -f /etc/rc.conf.d/network -n management_ip | /usr/bin/grep ":" > /dev/null 2>&1; then
        # If it is the master mongo
        /bin/echo -n "Verifying if the current node is master : "
        options="--quiet --ssl --sslCAFile /var/db/pki/ca.pem --sslPEMKeyFile /var/db/pki/node.pem --ipv6"
        if /usr/sbin/jexec mongodb /usr/local/bin/mongo $options "`hostname`:9091/vulture" --eval "db.isMaster()['ismaster']" | /usr/bin/grep "true" ; then
            /usr/local/bin/sudo -u vlt-os /home/vlt-os/env/bin/python3.7 /home/vlt-os/vulture_os/manage.py loaddata filters
        else
            echo "false"
        fi
    fi
fi