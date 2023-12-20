#!/home/vlt-os/env/bin/python
"""This file is part of Vulture 3.

Vulture 3 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Vulture 3 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Vulture 3.  If not, see http://www.gnu.org/licenses/.
"""
__author__ = "Jérémie JOURDIN"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture Project"
__email__ = "contact@vultureproject.org"
__doc__ = 'System Utils Redis Toolkit'


from redis import Redis
from toolkit.network.network import get_hostname

import logging
logger = logging.getLogger('debug')


class RedisBase:

    def __init__(self, node=None, port=None, password=None):
        self.port = port
        self.node = node
        self.password = password
        self.db = '/var/sockets/redis/redis.sock'

        if node and port:
            self.redis = Redis(host=node, port=port, password=password, socket_connect_timeout=1.0)
        elif node:
            self.redis = Redis(host=node, password=password, socket_connect_timeout=1.0)
        else:
            self.redis = Redis(unix_socket_path=self.db, password=password, socket_connect_timeout=1.0)

    def get_master(self, node=None):
        """ return the master node of the redis cluster or query the given node
        :return: Name or False in case of failure
        """

        try:
            if node:
                redis = Redis(host=node, password=self.password, socket_connect_timeout=1.0)
            else:
                redis = self.redis
            redis_info = redis.info()
            if redis_info.get('role') == 'master':
                if node:
                    return node
                else:
                    return get_hostname()
            elif redis_info.get('role') == 'slave':
                return redis_info.get('master_host')
        except Exception as e:
            logger.error("RedisBase::get_master: {}".format(str(e)))
            return None

        return False

    def replica_of(self, node, port):
        """
        Make the current redis node a replica of the specified one
        :param node: IP address of an existing master node
        :param port: TCP port of the master node
        :return:
        """
        return self.redis.slaveof(node, port)

    def config_set(self, key, value):
        return self.redis.config_set(key,value)

    def config_get(self, key, value):
        return self.redis.config_get(key,value)

    def config_rewrite(self):
        return self.redis.config_rewrite()

    def reset_password(self, password=""):
        try:
            self.config_set("requirepass", password)
            self.config_set("masterauth", password)
            self.config_rewrite()
        except Exception as e:
            logger.exception(f"[REDIS RESET PASSWORD] Error: {e}")
        else:
            self.password = password
            return True
        return False

    def sentinel_monitor(self, node=None):
        """
        Dynamically configure sentinel to monitor the local redis node.
         WARNING: For sentinel to work properly, self.node is supposed to be an IP address)
        :param node: IP address of an existing node
        :return: False if we are not connected to sentinel
        """

        if not node and not self.node or not self.port or self.port != 26379:
            return False

        return self.redis.sentinel_monitor('mymaster', node or self.node, 6379, 2)

    def sentinel_reset(self, password):
        """
        Set sentinel configuration through RedisBase class.
        :param password: redis_password of redis nodes
        :return: False if we are not connected to sentinel
        """

        if not self.node or not self.port or self.port != 26379:
            return False

        try:
            self.redis.execute_command('sentinel', 'config', 'set', 'announce-ip', self.node)
            self.redis.sentinel_set('mymaster', 'auth-pass', password)
        except Exception as e:
            logger.exception(f"[SENTINEL RESET PASSWORD] Error: {e}")

        return True

    # Write function : need master Redis
    def hmset(self, hash, mapping):
        result = None
        # Get role of current cluster
        cluster_info = self.redis.info()
        # If current cluster isn't master: get the master
        if "master" not in cluster_info['role']:
            # backup current cluster
            r_backup = self.redis
            # And connect to master
            try:
                self.redis = Redis(host=cluster_info['master_host'], port=cluster_info['master_port'], password=self.password, db=0)
                result = self.redis.hmset(hash, mapping)
            except Exception as e:
                self.logger.info("REDISSession: Redis connexion issue")
                self.logger.exception(e)
                result = None
            # Finally restore the backuped cluster
            self.redis = r_backup
        else:  # If current cluster is Master
            result = self.redis.hmset(hash, mapping)
        return result

    # Write function : need master Redis
    def expire(self, key, ttl):
        result = None
        # Get role of current cluster
        cluster_info = self.redis.info()
        # If current cluster isn't master: get the master
        if "master" not in cluster_info['role']:
            # backup current cluster
            r_backup = self.redis
            # And connect to master
            try:
                self.redis = Redis(host=cluster_info['master_host'], port=cluster_info['master_port'], password=self.password, db=0)
                result = self.redis.expire(key, ttl)
            except Exception as e:
                self.logger.info("REDISSession: Redis connexion issue")
                self.logger.exception(e)
                result = None
            # Finally restore the backuped cluster
            self.redis = r_backup
        else:  # If current cluster is Master
            result = self.redis.expire(key, ttl)
        return result