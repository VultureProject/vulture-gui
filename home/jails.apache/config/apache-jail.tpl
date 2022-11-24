apache {                                                            #APACHE24JAIL
        host.hostname = "apache";                                   #APACHE24JAIL
        ip4.addr = "lo5|127.0.0.6";                                 #APACHE24JAIL
        ip6.addr = "lo5|fd00::206";                                 #APACHE24JAIL
        allow.raw_sockets = 0;                                      #APACHE24JAIL
        exec.clean;                                                 #APACHE24JAIL
        exec.system_user = "root";                                  #APACHE24JAIL
        exec.jail_user = "root";                                    #APACHE24JAIL
        exec.start += "/bin/sh /etc/rc";                            #APACHE24JAIL
        exec.stop = "/bin/sh /etc/rc.shutdown";                     #APACHE24JAIL
        exec.consolelog = "/var/log/jail_apache_console.log";       #APACHE24JAIL
        allow.set_hostname = 0;                                     #APACHE24JAIL
        allow.sysvipc = 0;                                          #APACHE24JAIL
        enforce_statfs = "2";                                       #APACHE24JAIL
        devfs_ruleset = "4";    #devfsrules_jail                    #APACHE24JAIL
    	mount.devfs;                                                #APACHE24JAIL
}                                                                   #APACHE24JAIL
