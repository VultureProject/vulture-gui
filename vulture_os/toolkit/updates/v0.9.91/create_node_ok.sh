#!/bin/sh

# Add the file /home/vlt-os/vulture_os/.node_ok if the node has already been bootstrapped (cluster_create or cluster_join)

if [ -f /home/vlt-os/.install ] ; then
    /bin/mv /home/vlt-os/.install /home/vlt-os/vulture_os/.node_ok
fi
