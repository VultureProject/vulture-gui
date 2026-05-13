#!/usr/bin/env sh

COLOR_RESET='\033[0m'
COLOR_RED='\033[0;31m'

if ! [ -t 1 ]; then
    /bin/echo "This script should only be ran interactively! Please relaunch from an interactive terminal."
    exit 1
fi

answer=""
/usr/bin/printf "${COLOR_RED}/!\ WARNING /!\ This script will remove every configuration created through use of the Node${COLOR_RESET}\n"
/usr/bin/printf "${COLOR_RED}/!\ WARNING /!\ Please make sure to remove the Node from any Cluster before launching this script${COLOR_RESET}\n"
/usr/bin/printf "By reseting this Node, all configurations will be deleted and the Node will have to be bootstrapped again, do you want to continue? [yN]: "
read -r answer
case "${answer}" in
    y|Y|yes|Yes|YES)
    # Do nothing, continue
    ;;
    *)  /bin/echo "Wipe canceled."
        exit 0;
    ;;
esac

# Reset Filebeat configurations
/bin/echo "Resetting Filebeat configurations..."
/usr/sbin/jexec rsyslog service filebeat stop
/usr/bin/find /usr/local/etc/filebeat/* -not -path "/usr/local/etc/filebeat/module*" -not -path "/usr/local/etc/filebeat/modules.d*" -delete

# Reset Rsyslog configurations
/bin/echo "Resetting Rsyslogd configurations..."
/usr/sbin/jexec rsyslog service rsyslogd stop
for file in $(/usr/bin/find /usr/local/etc/rsyslog.d/ -type f); do
    if ! /usr/sbin/pkg which "$file" >/dev/null ; then
        /bin/rm -f "$file"
    fi
done
/usr/sbin/jexec rsyslog service rsyslogd start

# Reset Haproxy configurations
/bin/echo "Resetting Haproxy configurations..."
/usr/sbin/jexec haproxy service haproxy stop
/usr/bin/find /usr/local/etc/haproxy.d/ -not -name backend_session.cfg -type f -delete
/usr/sbin/jexec haproxy service haproxy start

# Reset Redis
/bin/echo "Resetting Redis configurations..."
/usr/sbin/jexec redis service redis stop
/usr/sbin/jexec redis service sentinel stop
/bin/cat /usr/local/etc/redis/redis.conf.sample > /usr/local/etc/redis/redis.conf
/bin/cat /usr/local/etc/redis/sentinel.conf.sample > /usr/local/etc/redis/sentinel.conf
/usr/bin/find /zroot/redis/var/db/vulture-redis/ -type f -delete
/usr/sbin/jexec redis service redis start
/usr/sbin/jexec redis service sentinel start

# Reset Mongodb
/bin/echo "Resetting Mongodb configurations..."
/bin/echo "Resetting redis configurations..."
/usr/sbin/jexec mongodb service mongod stop
/usr/bin/find /zroot/mongodb/var/db/mongodb/* -not -name "mongod.log" -delete

# Clear Certificatess
/bin/echo "Deleting Certificates..."
/usr/bin/find /var/db/pki/ -type f -delete

# Reset Logrotate configurations
/bin/echo "Resetting Logrotate configurations..."
/bin/rm -f /usr/local/etc/logrotate.d/logrotate.conf


# Reset PF configuration
/bin/echo "Resetting PF configuration..."
/usr/local/bin/pfctl-init.sh
/sbin/pfctl -f /usr/local/etc/pf.conf

/bin/echo "Reset Finished!"
exit 0
