#!/bin/sh

if [ -d /zroot/apache ] ; then
    /usr/sbin/pkg -j apache install -y python38 ap24-py38-mod_wsgi
    /usr/sbin/pkg -j apache remove -y python37 ap24-py37-mod_wsgi
fi
if [ -d /zroot/portal ] ; then
    /usr/sbin/pkg -j portal install -y python38 ap24-py38-mod_wsgi
    /usr/sbin/pkg -j portal remove -y python37 ap24-py37-mod_wsgi
fi
