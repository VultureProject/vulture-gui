#!/bin/sh

cat /usr/local/etc/redis/redis.conf.sample > /usr/local/etc/redis/redis.conf
cat /usr/local/etc/redis/sentinel.conf.sample > /usr/local/etc/redis/sentinel.conf
jexec redis service redis restart
jexec redis service sentinel restart

jexec mongodb service mongod stop
rm -rf /zroot/mongodb/var/db/mongodb/*

rm -rf /var/db/pki/ca.pem
rm -rf /var/db/pki/ca.key
rm -rf /var/db/pki/node.cert
rm -rf /var/db/pki/node.key
rm -rf /var/db/pki/node.pem

