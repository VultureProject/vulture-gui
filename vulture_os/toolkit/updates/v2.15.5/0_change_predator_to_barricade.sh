#!/usr/bin/env sh

# If node bootstrapped
if /usr/local/bin/sudo -u vlt-os /home/vlt-os/env/bin/python /home/vlt-os/vulture_os/manage.py is_node_bootstrapped >/dev/null 2>&1; then
    # If it is the master mongo
    /bin/echo -n "Verifying if the current node is master : "
    options="--quiet --ssl --sslCAFile /var/db/pki/ca.pem --sslPEMKeyFile /var/db/pki/node.pem"
    if /usr/sbin/jexec mongodb /usr/local/bin/mongo $options "`hostname`:9091/vulture" --eval "db.isMaster()['ismaster']" | /usr/bin/grep "true" ; then
        /usr/sbin/jexec mongodb /usr/local/bin/mongo $options `hostname`:9091/vulture --eval 'db.applications_reputationcontext.find({url:{$regex:"predator"}}).forEach(function(e){e.url=e.url.replace("predator","barricade");eval(printjson(e.url));db.applications_reputationcontext.save(e)})'
        /bin/echo "Reputation contexts moved to barricade"
    else
        echo "false"
    fi
fi
