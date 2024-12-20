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

    def update_one(self, database, collection, query, newvalue):
        try:
            if not self.db:
                self.connect()

            db = self.db[database]
            coll = db[collection]

            coll.update_one(query, newvalue)
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

    def update_one(self, database, query, newvalue):
        try:
            if not self.db:
                self.connect()

            db = self.db[database]

            for collName in db.list_collection_names():
                coll = db[collName]
                coll.update_one(query, newvalue)
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
            if node:
                host = 'mongodb://{}'.format(node)
            else:
                host = self.get_replicaset_uri()

            args = {'host': host,
                    'ssl': True,
                    'tlsCertificateKeyFile': "/var/db/pki/node.pem",
                    'tlsCAFile': "/var/db/pki/ca.pem",
                    'read_preference': ReadPreference.PRIMARY_PREFERRED,
                    "serverSelectionTimeoutMS": timeout_ms}
            if primary:
                args['replicaset'] = "Vulture"
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
        i = len(config['members'])
        config['members'].append({"_id": i, "host": node})

        try:
            res = self.db.admin.command("replSetReconfig", config)
        except Exception as e:
            logger.error("MongoBase::repl_add: Error during mongoDB replSetReconfig: {}".format(str(e)))
            return False, str(e)

        return True, res

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
            logger.warn("replRemove: Destroying local database, because there is only one member")
            self.replDestroy()
            return True, "Replicaset destroyed"

        config['version'] = config['version'] + 1
        i = 0
        for member in config['members']:
            if node == member.get('host'):
                del config['members'][i]
            i = i + 1

        try:
            res = self.db.admin.command("replSetReconfig", config)
            return True, res
        except Exception as e:
            logger.error("replRemove: Error during mongoDB replSetReconfig: {}".format(str(e)))
            return False, str(e)

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
        i = 0
        for member in config['members']:
            if "{}:{}".format(old_name, 9091) == member.get('host'):
                config['members'][i]['host'] = "{}:{}".format(new_name, "9091")
            i = i + 1
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
