#/bin/sh

/home/vlt-os/scripts/write_cert.sh

/usr/sbin/jexec mongodb /usr/sbin/service mongod restart

/usr/sbin/jexec apache /usr/sbin/service nginx restart
/usr/sbin/jexec apache /usr/sbin/service gunicorn restart
/usr/sbin/jexec portal /usr/sbin/service gunicorn restart
