#!/bin/sh

## If node already created
#if [ -f /home/vlt-os/vulture_os/.node_ok ] ; then
#
#    # If it is the master mongo
#    /bin/echo -n "Verifying if the current node is master : "
#    options="--quiet --ssl --sslCAFile /var/db/pki/ca.pem --sslPEMKeyFile /var/db/pki/node.pem --ipv6"
#    if /usr/sbin/jexec mongodb /usr/local/bin/mongo $options "`hostname`:9091/vulture" --eval "db.isMaster()['ismaster']" | /usr/bin/grep "true" ; then
#
#        # Alter NetworkAddress* models to add new fields
#        /usr/sbin/jexec mongodb /usr/local/bin/mongo $options "`hostname`:9091/vulture" --eval "db.system_networkaddress.update({}, {\$set: {\"vlan\": 0, \"vlandev_id\": null, \"fib\": 0}}, {upsert:false, multi:true})"
#
#
#        # Migrate the model, because previous attempt has failed in pkg_update.sh
#        /usr/local/bin/sudo -u vlt-os /home/vlt-os/env/bin/python3.7 /home/vlt-os/vulture_os/manage.py migrate
#
#    else
#        echo "false"
#    fi
#fi
