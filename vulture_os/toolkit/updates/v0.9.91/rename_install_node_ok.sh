#!/bin/sh

# The file /home/vlt-os/.install has been renamed to /home/vlt-os/vulture_os/.node_ok

if [ -f /home/vlt-os/.install ] ; then
    /bin/mv /home/vlt-os/.install /home/vlt-os/vulture_os/.node_ok
fi
