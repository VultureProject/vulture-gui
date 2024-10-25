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
__doc__ = 'System Utils Database Toolkit'


from pymongo import MongoClient, ReadPreference
from pymongo.errors import OperationFailure, AutoReconnect
from django.conf import settings
from re import search as re_search
import subprocess
import logging

logging.config.dictConfig(settings.LOG_SETTINGS)
# No database logging to prevent infinite loop
logger = logging.getLogger('system')


def parse_uristr(uristr):
    """ Parse uristr and returns list of tuples (ip|host, port) """
    result = []
    uristr = uristr.replace("mongodb://", "").split('/')[0]
    for ip_port in uristr.split(','):
        splitted = ip_port.split(':')
        ip = splitted[0]
        port = splitted[1] if len(splitted) > 0 else 27017
        result.append((ip, port))
    return result


class MongoBase:

    def __init__(self):
        self.db = None

    @staticmethod
    def get_local_node():
        return '{}:9091'.format(settings.HOSTNAME)

    @staticmethod
    def get_local_uri():
        return 'mongodb://{}:9091'.format(settings.HOSTNAME)

    @staticmethod
    def get_replicaset_uri():
        from system.cluster.models import Node

        try:
            node_list = "{}".format(str.join(',', [node.name + ":9091" for node in Node.objects.all().only('name')]))
            if node_list:
                return "mongodb://{}".format(node_list)
        except Exception as e:
            logger.error("Failed to retrieve replicaset_uri from Mongo : ")
            logger.exception(e)

        logger.info("Could not connect to Node, connecting to local")
        return MongoBase.get_local_uri()

    def execute_aggregation(self, database, collection, agg):
        try:
            if not self.db:
                self.connect()

            db = self.db[database]
            coll = db[collection]

            res = coll.aggregate(agg)
            return res

        except Exception as e:
            if settings.DEV_MODE:
                raise

            logger.critical(e, exc_info=1)
            return []

    def execute_request(self, database, collection, query, start=None, length=None, sorting=None, type_sorting=None, first=None):
        try:
            if not self.db:
                self.connect()

            db = self.db[database]
            coll = db[collection]

            if first:
                res = coll.find_one(query)
                return res

            nb_res = coll.find(query).count()
            res = coll.find(query).sort(sorting, type_sorting).limit(length).skip(start)
            return nb_res, res

        except Exception as e:
            if settings.DEV_MODE:
                raise

            logger.critical(e, exc_info=1)
            return 0, []

    def insert(self, database, collection, data):
        try:
            if not self.db:
                self.connect()

            db = self.db[database]
            coll = db[collection]

            coll.insert_one(data)
            return True
        except Exception as e:
            if settings.DEV_MODE:
                raise

            logger.critical(e, exc_info=1)
            return False

    def update_one(self, database, query, newvalue, collection=None):
        try:
            if not self.db:
                self.connect()

            db = self.db[database]
            if collection:
                coll = db[collection]
                coll.update_one(query, newvalue)
            else:
                for collName in db.list_collection_names():
                    coll = db[collName]
                    coll.update_one(query, newvalue)
                    return True
            return True
        except Exception as e:
            if settings.DEV_MODE:
                raise

            logger.critical(e, exc_info=1)
            return False

    def update_many(self, database, collection, query, newvalue):
        try:
            if not self.db:
                self.connect()

            db = self.db[database]
            coll = db[collection]

            coll.update_many(query, newvalue)
            return True
        except Exception as e:
            if settings.DEV_MODE:
                raise

            logger.critical(e, exc_info=1)
            return False

    def connect_with_retries(self, retries, node=None, primary=True, timeout=2):
        connection_ok = False
        tries = 1
        while not connection_ok and tries <= retries:
            logger.debug(f"connect_when_ready: Trying to connect to Mongodb (try {tries})")
            connection_ok = self.connect(node, primary, timeout_ms=timeout * 1000)
            tries += 1

        return connection_ok

    def connect(self, node=None, primary=True, timeout_ms=5000):
        try:
            args = settings.DATABASES['default']['CLIENT']
            args['serverSelectionTimeoutMS'] = timeout_ms

            if node:
                args['host'] = f'mongodb://{node}'
            else:
                args['host'] = self.get_replicaset_uri()

            if primary:
                args['read_preference'] = ReadPreference.PRIMARY
            else:
                args['read_preference'] = ReadPreference.PRIMARY_PREFERRED

            self.db = MongoClient(**args)
            # Execute a request to test connection (pymongo doesn't try connecting until a command is executed on client)
            self.db.admin.command('ping')
        except Exception as e:
            logger.error("connect: Error during mongoDB connection: {}".format(str(e)), exc_info=1)
            return False

        return True

    def get_primary(self):
        try:
            return self.db.admin.command("isMaster").get('primary')
        except Exception as e:
            logger.error("get_primary: {}".format(str(e)))
            return False

    def connect_primary(self):
        if self.db is None:
            self.connect()
        return self.connect(self.get_primary())

    def get_version(self):
        try:
            if self.db is None:
                self.connect()
            return self.db.server_info()['version']
        except Exception as e:
            logger.error(f"get_version: {str(e)}")
            return None

    def repl_state(self):
        try:
            return self.db.admin.command("replSetGetStatus")['members']
        except Exception as e:
            logger.error("repl_state: Error while getting MongoDB replication info: {}".format(str(e)), exc_info=1)
            return ""

    def repl_initiate(self):
        """
            ADD ourself to a local Vulture replicaset (bootstrap process)
        :return:
            True / False
        """
        config = {
            '_id': 'Vulture', 'members': [
                {'_id': 0, 'host': "{}:9091".format(settings.HOSTNAME)}
            ]
        }
        try:
            self.db.admin.command("replSetInitiate", config)
        except Exception as e:
            logger.error("replSetInitiate: Error during mongoDB replSetInitiate: {}".format(str(e)))
            return False

    def repl_destroy(self):
        """
        Destroy the local replicaset
        :return:
        """

        logger.info("replDestroy: Stopping Mongodb")
        # We are calling from Host, we don't need sudo
        logger.info(subprocess.check_output(
            ['/usr/sbin/jexec', 'mongodb', '/usr/sbin/service', 'mongod', 'stop']
        ).rstrip().decode('utf-8'))

        logger.info("replDestroy: Destroying local databases")
        # We are calling from Host, we don't need sudo
        logger.info(subprocess.check_output(
            ['/home/vlt-os/scripts/reset_mongo.sh']
        ).rstrip().decode('utf-8'))

        logger.info("replDestroy: Starting Mongodb")
        # We are calling from Host, we don't need sudo
        logger.info(subprocess.check_output(
            ['/usr/sbin/jexec', 'mongodb', '/usr/sbin/service', 'mongod', 'start']
        ).rstrip().decode('utf-8'))

    def repl_add(self, node):
        """
        Add the given node to a Vulture replicaset
        This command MUST be executed on a PRIMARY node

        :return: True / False
        """

        self.connect_primary()
        config = self.db.admin.command("replSetGetConfig")['config']
        config['version'] = config['version'] + 1
        ids = list(member.get("_id") for member in config['members'])
        i = 0
        while i in ids:
            i+=1
        config['members'].append({"_id": i, "host": node})
        config = self.repl_ensure_voting_count(config)

        try:
            res = self.db.admin.command("replSetReconfig", config)
        except OperationFailure as e:
            logger.error(f"MongoBase::repl_add: Error during mongoDB replSetReconfig: {e}")
            return False, f"{e.details.get('codeName')} : {e.details.get('errmsg')}"
        except Exception as e:
            logger.error(f"MongoBase::repl_add: Error during mongoDB replSetReconfig: {e}")
            return False, str(e)

        return True, f"Status code : {res.get('ok')}"

    def repl_remove(self, node):
        """
        REMOVE the given node from the Vulture replicaset
        This command exit if executed on a non-PRIMARY node
        :return:  Tuple with (status, message)
        """

        self.connect_primary()
        config = self.db.admin.command("replSetGetConfig")['config']

        # If we are the only one member in the replicaset, we can't do anything
        if len(config['members']) == 1 and node == config['members']:
            logger.warning("replRemove: Destroying local database, because there is only one member")
            self.replDestroy()
            return True, "Replicaset destroyed"

        config['version'] = config['version'] + 1
        for i, member in enumerate(config['members']):
            if node == member.get('host'):
                del config['members'][i]
        config = self.repl_ensure_voting_count(config)

        try:
            res = self.db.admin.command("replSetReconfig", config)
        except OperationFailure as e:
            logger.error(f"MongoBase::repl_remove: Error during mongoDB replSetReconfig: {e}")
            return False, f"{e.details.get('codeName')} : {e.details.get('errmsg')}"
        except Exception as e:
            logger.error(f"MongoBase::repl_remove: Error during mongoDB replSetReconfig: {e}")
            return False, str(e)

        return True, f"Status code : {res.get('ok')}"

    def repl_rename(self, old_name, new_name):
        """
        Change the hostname inside a replicahost.
        This assumes that our "hostname" has already been
        changed on all FreeBSD system
        This assumes that our PKI has been updated with our new name

        :param old_name: the old node's hostname
        :param new_name: the new node's hostname
        :return:  Tuple (status, message)
        """
        """ If there is no node, force reconfig """
        if len(self.db.nodes) == 0:
            return False, "No node connected"
        if len(self.db.nodes) == 1:
            force = True
        else:
            """ Connect to the PRIMARY and call replSetReconfig
            with the new configuration """
            self.connect_primary()
            force = True

        config = self.db.admin.command("replSetGetConfig")['config']
        config['version'] = config['version'] + 1
        for i, member in enumerate(config['members']):
            if f"{old_name}:{9091}" == member.get('host'):
                config['members'][i]['host'] = f"{new_name}:{9091}"

        try:
            self.db.admin.command("replSetReconfig", config, force=force)
        except Exception as e:
            logger.error("replRename: Error during mongoDB replSetReconfig: {}".format(str(e)))
            return False, str(e)

        """ Then, we need to restart ourselves """
        logger.info("replRename: Restarting Mongodb")
        message = subprocess.check_output(
            ['/usr/sbin/jexec', 'mongodb', '/usr/sbin/service', 'mongod', 'restart']).rstrip().decode('utf-8')

        return True, message

    def repl_set_step_down(self):
        """
        Instructs the primary of the replica set to become a secondary.
        After the primary steps down, eligble secondaries will
        hold an election for primary.

        This command MUST be executed on a PRIMARY node

        :return: Tuple (status, message)
        """

        self.connect_primary()
        try:
            logger.info("MongoBase::replSetStepDown: calling replSetStepDown")
            return True, self.db.admin.command({"replSetStepDown": 60})
        except AutoReconnect:
            return True, "Node stepped down"
        except Exception as e:
            logger.error("MongoBase::replSetStepDown: Error during mongoDB replSetStepDown: {}".format(str(e)))
            return False, str(e)

    def repl_ensure_voting_count(self, config={}):
        """
        MongoDB can have up to 7 voting members.
        If a voting member is added/deleted, we ensure that the voting members count
        is at least 7 if nodes are more than that in the cluster
        """
        if len(config.get("members", [])):
            members = []
            for i, member in enumerate(config['members']):
                member['votes'] = 1 if i < 7 else 0
                member['priority'] = 1 if i < 7 else 0
                members.append(member)
            config['members'] = members
        return config

    def set_index_ttl(self, db, collection, time_field, nb_seconds, index_filter=None):
        """
        Create an index on a collection, and set a TTL for documents based on a time field and nb_seconds.

        This command MUST be executed on a PRIMARY node

        :return: Tuple (status, message)
        """
        self.connect_primary()
        # Try to create index
        try:
            result = self.db[db][collection].create_index(time_field, expireAfterSeconds=nb_seconds,
                                                          partialFilterExpression=index_filter or {})
            logger.info("MongoBase::set_index_ttl: Index '{}' created.".format(result))
            return True, result
        except OperationFailure as e:
            # If it already exists
            index_regex = re_search("Index with name: ([^ ]+) already exists (.*)", str(e))
            if index_regex:
                index_name = index_regex.group(1)
                # Delete it
                self.db[db][collection].drop_index(index_name)
                logger.info("MongoBase::set_index_ttl: Index '{}' deleted.".format(index_name))
                # And recreate-it
                result = self.db[db][collection].create_index(time_field, expireAfterSeconds=nb_seconds,
                                                              partialFilterExpression=index_filter or {})
                logger.info("MongoBase::set_index_ttl: Index '{}' created.".format(result))
                return True, result
        except Exception as e:
            logger.error("MongoBase::replSetStepDown: Error during mongoDB replSetStepDown: {}".format(str(e)))
            return False, str(e)
