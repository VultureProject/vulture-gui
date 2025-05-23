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


from ast import literal_eval
from os.path import join as path_join
from redis import Redis, Sentinel, RedisError
from toolkit.network.network import get_management_ip

from django.conf import settings

import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('debug')


class RedisBase:

    def __init__(self, node=None, port=None, password=None):
        self.node = node
        self.port = port
        self.password = password
        self.db = path_join(settings.SOCKETS_PATH, 'redis/redis.sock')
        self._redis_client = None

    @property
    def redis(self):
        if not self._redis_client:
            if self.node and self.port:
                self._redis_client = Redis(host=self.node, port=self.port, password=self.password, socket_connect_timeout=1.0)
            elif self.node:
                self._redis_client = Redis(host=self.node, password=self.password, socket_connect_timeout=1.0)
            else:
                self._redis_client = Redis(unix_socket_path=self.db, password=self.password, socket_connect_timeout=1.0)
        return self._redis_client

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
                    return settings.HOSTNAME
            elif redis_info.get('role') == 'slave':
                return redis_info.get('master_host')
        except Exception as e:
            logger.error("RedisBase::get_master: {}".format(str(e)))
            return None

        return False

    def get_role(self):
        return self.redis.role()[0].decode()

    def replica_of(self, node, port):
        """
        Make the current redis node a replica of the specified one
        :param node: IP address of an existing master node
        :param port: TCP port of the master node
        :return:
        """
        return self.redis.slaveof(node, port)

    def config_set(self, key, value):
        return self.redis.config_set(key, value)

    def config_get(self, key):
        return self.redis.config_get(key)

    def config_rewrite(self):
        return self.redis.config_rewrite()

    def set_password(self, password=""):
        try:
            self.config_set("requirepass", password or "")
            self.config_set("masterauth", password or "")
            self.config_rewrite()
        except Exception as e:
            logger.exception(f"[REDIS RESET PASSWORD] Error: {e}")
        else:
            self.password = password
            self._redis_client = None
            return True
        return False

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
                self._redis_client = Redis(host=cluster_info['master_host'], port=cluster_info['master_port'], password=self.password, db=0)
                result = self.redis.hmset(hash, mapping)
            except Exception as e:
                logger.info("REDISSession: Redis connexion issue")
                logger.exception(e)
                result = None
            # Finally restore the backuped cluster
            self._redis_client = r_backup
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
                self._redis_client = Redis(host=cluster_info['master_host'], port=cluster_info['master_port'], password=self.password, db=0)
                result = self.redis.expire(key, ttl)
            except Exception as e:
                logger.info("REDISSession: Redis connexion issue")
                logger.exception(e)
                result = None
            # Finally restore the backuped cluster
            self._redis_client = r_backup
        else:  # If current cluster is Master
            result = self.redis.expire(key, ttl)
        return result


class SentinelBase(RedisBase):

    def __init__(self, node=None, port=None, password=None):
        self.node = node
        self.port = port
        self.password = password
        self._redis_client = None

    @property
    def redis(self):
        if not self._redis_client:
            if self.node and self.port:
                self._redis_client = Sentinel([(self.node, self.port)], password=self.password, socket_connect_timeout=1.0)
            elif self.node:
                self._redis_client = Sentinel([(self.node, 26379)], password=self.password, socket_connect_timeout=1.0)
            else:
                self._redis_client = Sentinel([(settings.REDISIP, 26379)], password=self.password, socket_connect_timeout=1.0)

        return self._redis_client

    def sentinel_monitor(self, node=None):
        """
        Dynamically configure sentinel to monitor the local redis node.
         WARNING: For sentinel to work properly, self.node is supposed to be an IP address)
        :param node: IP address of an existing node
        :return: False if we are not connected to sentinel
        """
        return self.redis.sentinel_monitor('mymaster', node or self.node, 6379, 2)

    def sentinel_failover(self):
        """
        Force a new election inside the replicaset.
         WARNING: For sentinel to work properly, self.node is supposed to be an IP address)
        :return: False if we are not connected to sentinel
        """
        return self.redis.sentinel_failover('mymaster')

    def sentinel_remove(self):
        """
        Configure sentinel to remove monitoring on local redis node.
         WARNING: For sentinel to work properly, self.node is supposed to be an IP address)
        :return: False if we are not connected to sentinel
        """
        return self.redis.sentinel_remove('mymaster')

    def sentinel_reset(self):
        """
        Forget a replica from configuration.
         WARNING: For sentinel to work properly, self.node is supposed to be an IP address)
        :return: False if we are not connected to sentinel
        """
        return self.redis.sentinel_reset('mymaster')

    def sentinel_set_announce_ip(self):
        """
        Set sentinel announce_ip through RedisBase class.
        :return: False if we are not connected to sentinel
        """
        try:
            self.redis.execute_command('sentinel', 'config', 'set', 'announce-ip', self.node)
        except Exception as e:
            logger.exception(f"[SENTINEL SET ANNOUNCE IP] Error: {e}")
            return False
        return True

    def sentinel_set_cluster_password(self, password):
        """
        Set sentinel password to authenticate against
        redis servers through RedisBase class.
        :param password: redis_password of redis nodes
        :return: False if we are not connected to sentinel
        """
        try:
            self.redis.sentinel_set('mymaster', 'auth-pass', password)
        except Exception as e:
            logger.exception(f"[SENTINEL SET CLUSTER PASSWORD] Error: {e}")
            return False
        return True


def set_replica_of(logger, args):
    """
    Set Redis as a replica of the current main node
    :param args: tuple of
        - IP of the main node to set the replication to
        - the potential redis_password already configured on the node/cluster
    :return: True if Redis replication was successfully set
    """
    if isinstance(args, str):
        main_node, redis_password = literal_eval(args)
    else:
        main_node, redis_password = args
    redis = RedisBase(password=redis_password)
    result = redis.replica_of(main_node, 6379)
    if not result:
        logger.error("Unable to set Redis replication")
        raise RedisError("Unable to set Redis replication")

    sentinel = SentinelBase(get_management_ip(), 26379)
    result = sentinel.sentinel_monitor(node=main_node)
    if not result:
        logger.error("Unable to set Sentinel monitor")
        raise RedisError("Unable to set Sentinel monitor")
    return result


def set_password(logger, passwords=("","")):
    """
    Set Redis server password
    :param passwords: tuple of (redis_password, old_redis_password)
    :return: True if Redis password successfully set
    """
    if isinstance(passwords, str):
        redis_password, old_redis_password = literal_eval(passwords)
    else:
        redis_password, old_redis_password = passwords
    try:
        redis = RedisBase(password=old_redis_password)
        redis.redis.ping()
    except Exception as e:
        raise RedisError(f"Cannot connect to Redis: {e}")
    try:
        sentinel = SentinelBase(get_management_ip(), 26379)
        assert sentinel.redis.execute_command("PING")
    except Exception as e:
        raise RedisError(f"Cannot connect to Redis Sentinel: {e}")

    result = redis.set_password(redis_password)
    if not result:
        logger.error("Unable to set Redis password")
        raise RedisError("Unable to set Redis password")

    result = sentinel.sentinel_set_cluster_password(redis_password)
    if not result:
        logger.error("Unable to set Redis password in Sentinel")
        raise RedisError("Unable to set Redis password in Sentinel")
    return result


def renew_sentinel_configuration(logger):
    """
    Reset sentinel known sentinels and replicas
    :return: True if Sentinel command succeded
    """
    sentinel = SentinelBase(get_management_ip(), 26379)
    result = sentinel.sentinel_reset()
    if not result:
        logger.error("Unable to reset Sentinel monitor")
        raise RedisError("Unable to reset Sentinel monitor")
    return result
