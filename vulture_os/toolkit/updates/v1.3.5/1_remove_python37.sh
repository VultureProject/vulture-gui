#!/bin/sh

# lock packages depending on python to avoid uninstalling them in case of conflict
/usr/sbin/pkg lock -y darwin vulture-gui vulture-base

/usr/sbin/pkg remove -y python37

# unlock the packages
/usr/sbin/pkg unlock -y darwin vulture-gui vulture-base
