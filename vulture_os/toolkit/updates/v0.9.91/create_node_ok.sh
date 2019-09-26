#!/bin/sh

# Add the file /home/vlt-os/vulture_os/.node_ok if the node has already been bootstrapped (cluster_create or cluster_join)

# If the node has been bootstrapped, the rsyslog configuration file has been created
if [ -f /usr/local/etc/rsyslog.d/pf.conf ] ; then
    /usr/bin/touch /home/vlt-os/vulture_os/.node_ok
fi
