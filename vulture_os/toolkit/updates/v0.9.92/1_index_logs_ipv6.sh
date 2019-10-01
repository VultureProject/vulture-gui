#!/bin/sh

# If IPv6 - Make v0.9 migration
if /usr/bin/grep ":" /usr/local/etc/management.ip > /dev/null ; then
    # If it is the master mongo
    /bin/echo -n "Verifying if the current node is master : "
    options="--quiet --ssl --sslCAFile /var/db/pki/ca.pem --sslPEMKeyFile /var/db/pki/node.pem --ipv6"
    if /usr/sbin/jexec mongodb /usr/local/bin/mongo $options "`hostname`:9091/vulture" --eval "db.isMaster()['ismaster']" | /usr/bin/grep "true" ; then
        # Flush MessageQueues after 24h (86400s)  that have a status != done and != failure
        /usr/sbin/jexec mongodb /usr/local/bin/mongo $options "`hostname`:9091/vulture" --eval "db.system_messagequeue.createIndex({\"modified\":1}, {partialFilterExpression: {status: \"done\"}, expireAfterSeconds:86400})"
        /usr/sbin/jexec mongodb /usr/local/bin/mongo $options "`hostname`:9091/vulture" --eval "db.system_messagequeue.createIndex({\"date_add\":1}, {partialFilterExpression: {status: \"failure\"}, expireAfterSeconds:86400})"
        # Keep internal,PF logs 7 days by default
        /usr/sbin/jexec mongodb /usr/local/bin/mongo $options "`hostname`:9091/logs" --eval "db.internal.createIndex({\"timestamp\":1}, {expireAfterSeconds:604800})"
        /usr/sbin/jexec mongodb /usr/local/bin/mongo $options "`hostname`:9091/logs" --eval "db.pf.createIndex({\"time\":1}, {expireAfterSeconds:604800})"
    else
        echo "false"
    fi
fi
