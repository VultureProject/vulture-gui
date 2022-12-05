#!/bin/sh

mv -f /var/tmp/ca.pem /var/db/pki/
mv -f /var/tmp/node.cert /var/db/pki/
mv -f /var/tmp/node.key /var/db/pki/
mv -f /var/tmp/node.pem /var/db/pki/

chown root:vlt-conf /var/db/pki/ca.pem
chown root:vlt-conf /var/db/pki/node.cert
chown root:vlt-conf /var/db/pki/node.key
chown root:vlt-conf /var/db/pki/node.pem
chmod 440 /var/db/pki/ca.pem
chmod 440 /var/db/pki/node.cert
chmod 440 /var/db/pki/node.key
chmod 440 /var/db/pki/node.pem
