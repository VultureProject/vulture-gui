#!/usr/bin/env sh

_HOSTNAME="$(hostname)"

if [ -z "$_HOSTNAME" ]; then
    echo "Could not get machine hostname!"
    exit 1
fi

if ! [ -f /var/db/pki/ca.pem ] || ! [ -f /var/db/pki/node.pem ]; then
    echo "Missing a pki file to connect to mongodb!"
    exit 1
fi

if ! jls -j mongodb > /dev/null 2>&1; then
    echo "Mongodb jail is not running!"
    exit 1
fi

if ! jexec mongodb service mongod status > /dev/null 2>&1; then
    echo "Mongod service is not running!"
    exit 1
fi

echo "Cleaning system statuses..."

jexec mongodb mongo --ssl --sslCAFile /var/db/pki/ca.pem --sslPEMKeyFile /var/db/pki/node.pem ${_HOSTNAME}:9091/vulture --eval 'db.gui_monitor.remove({})' > /dev/null
jexec mongodb mongo --ssl --sslCAFile /var/db/pki/ca.pem --sslPEMKeyFile /var/db/pki/node.pem ${_HOSTNAME}:9091/vulture --eval 'db.gui_servicestatus.remove({})' > /dev/null

echo "Done."
