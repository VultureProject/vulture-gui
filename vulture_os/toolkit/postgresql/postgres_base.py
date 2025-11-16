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
__author__ = "Mael BONNIOT"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture Project"
__email__ = "contact@vultureproject.org"
__doc__ = 'System Utils Database Toolkit'


import psycopg
from psycopg import sql
from psycopg.rows import dict_row
from django.conf import settings
from re import search as re_search
import subprocess
import logging
import json
from typing import Optional, List, Tuple, Dict, Any

logging.config.dictConfig(settings.LOG_SETTINGS)
# No database logging to prevent infinite loop
logger = logging.getLogger('system')


def parse_uristr(uristr):
    """ Parse uristr and returns list of tuples (ip|host, port) """
    result = []
    uristr = uristr.replace("postgresql://", "").replace("postgres://", "")

    # Remove credentials if present
    if '@' in uristr:
        uristr = uristr.split('@')[1]

    # Remove database name if present
    uristr = uristr.split('/')[0]

    for ip_port in uristr.split(','):
        splitted = ip_port.split(':')
        ip = splitted[0]
        port = splitted[1] if len(splitted) > 1 else 5432
        result.append((ip, port))
    return result


class PostgresBase:

    def __init__(self):
        self.db = None
        self.conn = None
        self.is_replica_setup = False

    @staticmethod
    def get_local_node():
        return '{}:5432'.format(settings.HOSTNAME)

    @staticmethod
    def get_local_uri():
        return 'postgresql://{}:5432'.format(settings.HOSTNAME)

    @staticmethod
    def get_replicaset_uri():
        """Get PostgreSQL connection URI for the cluster (primary or replicas)"""
        from system.cluster.models import Node

        try:
            node_list = "{}".format(str.join(',', [node.name + ":5432" for node in Node.objects.all().only('name')]))
            if node_list:
                # PostgreSQL format for multiple hosts (libpq multi-host connection)
                return "postgresql://{}".format(node_list)
        except Exception as e:
            logger.error("Failed to retrieve replicaset_uri from Postgres : ")
            logger.exception(e)

        logger.info("Could not connect to Node, connecting to local")
        return PostgresBase.get_local_uri()

    def database_exists(self, db_name: str) -> bool:
        if not self.conn:
            self.connect()

        with self.conn.cursor() as cur:
            cur.execute(
                "SELECT 1 FROM pg_database WHERE datname = %s",
                (db_name,)
            )
            return cur.fetchone() is not None

    def table_exists(self, table_name, schema='public'):
        if not self.conn:
            self.connect()

        with self.conn.cursor() as cur:
            cur.execute("""
                SELECT EXISTS (
                    SELECT 1
                    FROM information_schema.tables
                    WHERE table_schema = %s
                    AND table_name = %s
                )
            """, (schema, table_name))

            result = cur.fetchone()[0]
            return result

    def execute_aggregation(self, database, collection, agg):
        """
        Execute aggregation-like query in PostgreSQL.
        Since PostgreSQL doesn't have direct aggregation pipelines like MongoDB,
        this will translate to SQL with GROUP BY, window functions, etc.
        """
        try:
            if not self.conn:
                self.connect()

            with self.conn.cursor(row_factory=dict_row) as cursor:
                # If agg is a SQL string, execute it directly
                if isinstance(agg, str):
                    cursor.execute(f"SET search_path TO {database}")
                    cursor.execute(agg)
                    return cursor.fetchall()
                else:
                    # Complex aggregation translation would go here
                    logger.warning("Complex aggregation pipeline translation not implemented")
                    return []

        except Exception as e:
            if settings.DEV_MODE:
                raise

            logger.critical(e, exc_info=1)
            return []

    def execute_request(self, database, collection, query, start=None, length=None, sorting=None, type_sorting=None, first=None):
        """
        Execute a query on PostgreSQL table (MongoDB collection).
        Query should be a dict that gets translated to SQL WHERE conditions.
        """
        try:
            if not self.conn:
                self.connect()

            with self.conn.cursor(row_factory=dict_row) as cursor:
                cursor.execute(f"SET search_path TO {database}")
                
                # Build WHERE clause from query dict
                where_clause = self._build_where_clause(query)
                
                if first:
                    sql_query = sql.SQL("SELECT * FROM {} {}").format(
                        sql.Identifier(collection),
                        sql.SQL(where_clause) if where_clause else sql.SQL("")
                    )
                    sql_query = sql.SQL("{} LIMIT 1").format(sql_query)
                    cursor.execute(sql_query)
                    return cursor.fetchone()

                # Count total results
                count_query = sql.SQL("SELECT COUNT(*) as count FROM {} {}").format(
                    sql.Identifier(collection),
                    sql.SQL(where_clause) if where_clause else sql.SQL("")
                )
                cursor.execute(count_query)
                nb_res = cursor.fetchone()['count']
                
                # Build main query with sorting and pagination
                sql_query = sql.SQL("SELECT * FROM {} {}").format(
                    sql.Identifier(collection),
                    sql.SQL(where_clause) if where_clause else sql.SQL("")
                )
                
                if sorting:
                    order_direction = "DESC" if type_sorting == -1 else "ASC"
                    sql_query = sql.SQL("{} ORDER BY {} {}").format(
                        sql_query,
                        sql.Identifier(sorting),
                        sql.SQL(order_direction)
                    )
                
                if length:
                    sql_query = sql.SQL("{} LIMIT {}").format(sql_query, sql.Literal(length))
                
                if start:
                    sql_query = sql.SQL("{} OFFSET {}").format(sql_query, sql.Literal(start))
                
                cursor.execute(sql_query)
                res = cursor.fetchall()
                
                return nb_res, res

        except Exception as e:
            if settings.DEV_MODE:
                raise

            logger.critical(e, exc_info=1)
            return 0, []

    def insert(self, database, collection, data):
        """Insert a document/row into PostgreSQL table"""
        try:
            if not self.conn:
                self.connect()

            with self.conn.cursor() as cursor:
                cursor.execute(f"SET search_path TO {database}")
                
                # Convert dict to INSERT statement
                columns = list(data.keys())
                values = list(data.values())
                
                # Handle JSON fields if needed
                for i, val in enumerate(values):
                    if isinstance(val, (dict, list)):
                        values[i] = json.dumps(val)
                
                insert_query = sql.SQL("INSERT INTO {} ({}) VALUES ({})").format(
                    sql.Identifier(collection),
                    sql.SQL(', ').join(map(sql.Identifier, columns)),
                    sql.SQL(', ').join(sql.Placeholder() * len(values))
                )
                
                cursor.execute(insert_query, values)
                self.conn.commit()
                return True
                
        except Exception as e:
            if self.conn:
                self.conn.rollback()
            if settings.DEV_MODE:
                raise

            logger.critical(e, exc_info=1)
            return False

    def update_one(self, database, query, newvalue, collection=None):
        """Update one row in PostgreSQL table"""
        try:
            if not self.conn:
                self.connect()

            with self.conn.cursor() as cursor:
                cursor.execute(f"SET search_path TO {database}")
                
                # Build WHERE clause from query
                where_clause = self._build_where_clause(query)
                
                # Build SET clause from newvalue
                set_clause = self._build_set_clause(newvalue)
                
                if collection:
                    update_query = sql.SQL("UPDATE {} {} {} LIMIT 1").format(
                        sql.Identifier(collection),
                        sql.SQL(set_clause),
                        sql.SQL(where_clause) if where_clause else sql.SQL("")
                    )
                    cursor.execute(update_query)
                else:
                    # Update in all tables of the schema
                    cursor.execute("""
                        SELECT table_name FROM information_schema.tables 
                        WHERE table_schema = %s AND table_type = 'BASE TABLE'
                    """, [database])
                    
                    for row in cursor.fetchall():
                        table_name = row[0]
                        update_query = sql.SQL("UPDATE {} {} {} LIMIT 1").format(
                            sql.Identifier(table_name),
                            sql.SQL(set_clause),
                            sql.SQL(where_clause) if where_clause else sql.SQL("")
                        )
                        cursor.execute(update_query)
                        if cursor.rowcount > 0:
                            break
                
                self.conn.commit()
                return True
                
        except Exception as e:
            if self.conn:
                self.conn.rollback()
            if settings.DEV_MODE:
                raise

            logger.critical(e, exc_info=1)
            return False

    def update_many(self, database, collection, query, newvalue):
        """Update multiple rows in PostgreSQL table"""
        try:
            if not self.conn:
                self.connect()

            with self.conn.cursor() as cursor:
                cursor.execute(f"SET search_path TO {database}")
                
                where_clause = self._build_where_clause(query)
                set_clause = self._build_set_clause(newvalue)
                
                update_query = sql.SQL("UPDATE {} {} {}").format(
                    sql.Identifier(collection),
                    sql.SQL(set_clause),
                    sql.SQL(where_clause) if where_clause else sql.SQL("")
                )
                
                cursor.execute(update_query)
                self.conn.commit()
                return True
                
        except Exception as e:
            if self.conn:
                self.conn.rollback()
            if settings.DEV_MODE:
                raise

            logger.critical(e, exc_info=1)
            return False

    def connect_with_retries(self, retries=3, node=None, primary=True, timeout=2):
        """Connect to PostgreSQL with retry logic"""
        connection_ok = False
        tries = 1
        while not connection_ok and tries <= retries:
            logger.debug(f"connect_when_ready: Trying to connect to PostgreSQL (try {tries})")
            connection_ok = self.connect(node, primary, timeout_ms=timeout * 1000)
            tries += 1

        return connection_ok

    def connect(self, node=None, primary=True, timeout_ms=5000):
        """Connect to PostgreSQL database"""
        try:
            # Build connection parameters
            conn_params = {
                'dbname': settings.DATABASES['default'].get('NAME', 'vulture'),
                'user': settings.DATABASES['default'].get('USER', 'vulture'),
                'password': settings.DATABASES['default'].get('PASSWORD', ''),
                'connect_timeout': timeout_ms // 1000,
                'options': '-c statement_timeout={}'.format(timeout_ms)
            }
            
            if node:
                # Connect to specific node
                host, port = node.split(':') if ':' in node else (node, '5432')
                conn_params['host'] = host
                conn_params['port'] = port
            else:
                # Get cluster URI and parse it
                uri = self.get_replicaset_uri()
                hosts = parse_uristr(uri)
                if hosts:
                    # PostgreSQL libpq supports multiple hosts for failover
                    conn_params['host'] = ','.join([h[0] for h in hosts])
                    conn_params['port'] = ','.join([str(h[1]) for h in hosts])
                    
                    if primary:
                        # Prefer primary server
                        conn_params['target_session_attrs'] = 'read-write'
                    else:
                        # Allow any server (primary or standby)
                        conn_params['target_session_attrs'] = 'any'
            
            # Close existing connection if any
            if self.conn:
                self.conn.close()
            
            # Create new connection
            self.conn = psycopg.connect(**conn_params)
            self.db = self.conn  # Keep compatibility with original attribute name
            
            # Test connection
            with self.conn.cursor() as cursor:
                cursor.execute("SELECT 1")
                
        except Exception as e:
            logger.error("connect: Error during PostgreSQL connection: {}".format(str(e)), exc_info=1)
            return False

        return True

    def get_primary(self):
        """Get the primary server in PostgreSQL replication setup"""
        try:
            with self.conn.cursor() as cursor:
                # Check if we're in recovery mode (means we're a standby)
                cursor.execute("SELECT pg_is_in_recovery()")
                is_standby = cursor.fetchone()[0]
                
                if not is_standby:
                    # We are the primary
                    cursor.execute("SELECT inet_server_addr(), inet_server_port()")
                    result = cursor.fetchone()
                    return f"{result[0]}:{result[1]}"
                else:
                    # We're a standby, need to find primary
                    # This would require checking pg_stat_replication on primary
                    # or using external cluster management
                    logger.warning("Connected to standby server, primary detection requires cluster manager")
                    return None
                    
        except Exception as e:
            logger.error("get_primary: {}".format(str(e)))
            return False

    def connect_primary(self):
        """Connect to the primary PostgreSQL server"""
        if self.conn is None:
            self.connect()
        
        # Reconnect with read-write requirement
        return self.connect(primary=True)

    def get_version(self):
        """Get PostgreSQL version"""
        try:
            if self.conn is None:
                self.connect()
            
            with self.conn.cursor() as cursor:
                cursor.execute("SELECT version()")
                version_string = cursor.fetchone()[0]
                # Extract version number from string like "PostgreSQL 14.5 on x86_64..."
                import re
                match = re.search(r'PostgreSQL (\d+\.\d+)', version_string)
                if match:
                    return match.group(1)
                return version_string
                
        except Exception as e:
            logger.error(f"get_version: {str(e)}")
            return None

    def repl_state(self):
        """Get PostgreSQL replication state"""
        try:
            with self.conn.cursor(row_factory=dict_row) as cursor:
                # Check if we're primary or standby
                cursor.execute("SELECT pg_is_in_recovery() as is_standby")
                is_standby = cursor.fetchone()['is_standby']
                
                members = []
                
                if not is_standby:
                    # We're primary, get info about standbys
                    cursor.execute("""
                        SELECT 
                            client_addr as host,
                            state,
                            sync_state,
                            backend_start
                        FROM pg_stat_replication
                    """)
                    
                    for row in cursor.fetchall():
                        members.append({
                            '_id': len(members),
                            'name': f"{row['host']}:5432",
                            'stateStr': 'PRIMARY' if row['sync_state'] == 'sync' else 'SECONDARY',
                            'health': 1 if row['state'] == 'streaming' else 0
                        })
                    
                    # Add ourselves as primary
                    members.insert(0, {
                        '_id': 0,
                        'name': self.get_local_node(),
                        'stateStr': 'PRIMARY',
                        'health': 1
                    })
                else:
                    # We're standby
                    members.append({
                        '_id': 0,
                        'name': self.get_local_node(),
                        'stateStr': 'SECONDARY',
                        'health': 1
                    })
                
                return members
                
        except Exception as e:
            logger.error("repl_state: Error while getting PostgreSQL replication info: {}".format(str(e)), exc_info=1)
            return ""

    def repl_initiate(self):
        """
        Initialize PostgreSQL for replication (bootstrap process)
        This sets up the local instance as a primary server
        """
        try:
            with self.conn.cursor() as cursor:
                # Enable replication settings
                cursor.execute("""
                    ALTER SYSTEM SET wal_level = 'replica';
                    ALTER SYSTEM SET max_wal_senders = 10;
                    ALTER SYSTEM SET wal_keep_size = '1GB';
                    ALTER SYSTEM SET hot_standby = 'on';
                    ALTER SYSTEM SET archive_mode = 'on';
                    ALTER SYSTEM SET archive_command = '/bin/true';
                """)
                
                # Reload configuration
                cursor.execute("SELECT pg_reload_conf()")
                
                self.is_replica_setup = True
                return True
                
        except Exception as e:
            logger.error("repl_initiate: Error during PostgreSQL replication setup: {}".format(str(e)))
            return False

    def repl_destroy(self):
        """
        Destroy the local replication setup
        Warning: This will stop PostgreSQL and delete data!
        """
        logger.info("replDestroy: Stopping PostgreSQL")
        # Stop PostgreSQL service in jail
        logger.info(subprocess.check_output(
            ['/usr/sbin/jexec', 'postgresql', '/usr/sbin/service', 'postgresql', 'stop']
        ).rstrip().decode('utf-8'))

        logger.info("replDestroy: Destroying local databases")
        # Reset PostgreSQL data
        logger.info(subprocess.check_output(
            ['/home/vlt-os/scripts/reset_postgres.sh']
        ).rstrip().decode('utf-8'))

        logger.info("replDestroy: Starting PostgreSQL")
        # Start PostgreSQL service
        logger.info(subprocess.check_output(
            ['/usr/sbin/jexec', 'postgresql', '/usr/sbin/service', 'postgresql', 'start']
        ).rstrip().decode('utf-8'))

    def repl_add(self, node):
        """
        Add a node as a PostgreSQL standby server
        This requires setting up streaming replication
        
        Note: This is a complex operation that typically requires:
        1. pg_basebackup on the standby
        2. Configuration of recovery.conf or standby.signal
        3. Network/firewall configuration
        
        This is a simplified version - actual implementation would need more details
        """
        try:
            self.connect_primary()
            
            host, port = node.split(':') if ':' in node else (node, '5432')
            
            with self.conn.cursor() as cursor:
                # Create replication user if not exists
                cursor.execute("""
                    DO $$
                    BEGIN
                        IF NOT EXISTS (SELECT FROM pg_user WHERE usename = 'replicator') THEN
                            CREATE USER replicator WITH REPLICATION LOGIN PASSWORD 'repl_password';
                        END IF;
                    END $$;
                """)
                
                # Grant replication permissions
                cursor.execute(f"""
                    GRANT CONNECT ON DATABASE {settings.DATABASES['default'].get('NAME', 'vulture')} 
                    TO replicator;
                """)
                
                self.conn.commit()
                
                # Note: The actual standby setup would need to be done on the standby server itself
                # using pg_basebackup and configuration files
                
                return True, f"Replication user configured for {node}"
                
        except Exception as e:
            logger.error(f"repl_add: Error during PostgreSQL standby setup: {e}")
            return False, str(e)

    def repl_remove(self, node):
        """
        Remove a standby server from PostgreSQL replication
        This mainly involves stopping replication on the standby
        """
        try:
            self.connect_primary()
            
            host, port = node.split(':') if ':' in node else (node, '5432')
            
            with self.conn.cursor() as cursor:
                # Terminate replication connection from this standby
                cursor.execute("""
                    SELECT pg_terminate_backend(pid)
                    FROM pg_stat_replication
                    WHERE client_addr = %s
                """, [host])
                
                self.conn.commit()
                
                # Check if this was the last standby
                cursor.execute("SELECT COUNT(*) FROM pg_stat_replication")
                standby_count = cursor.fetchone()[0]
                
                if standby_count == 0:
                    logger.warning("replRemove: No more standby servers in replication")
                
                return True, f"Standby {node} removed from replication"
                
        except Exception as e:
            logger.error(f"repl_remove: Error during PostgreSQL standby removal: {e}")
            return False, str(e)

    def repl_rename(self, old_name, new_name):
        """
        Handle hostname change in PostgreSQL replication setup
        This mainly involves updating connection strings and restarting
        """
        try:
            # Update PostgreSQL configuration with new hostname
            with self.conn.cursor() as cursor:
                cursor.execute(f"""
                    ALTER SYSTEM SET listen_addresses = '{new_name}, localhost';
                """)
                
                # Reload configuration
                cursor.execute("SELECT pg_reload_conf()")
            
            # Restart PostgreSQL service
            logger.info("replRename: Restarting PostgreSQL")
            message = subprocess.check_output(
                ['/usr/sbin/jexec', 'postgresql', '/usr/sbin/service', 'postgresql', 'restart']
            ).rstrip().decode('utf-8')
            
            return True, message
            
        except Exception as e:
            logger.error("replRename: Error during PostgreSQL rename: {}".format(str(e)))
            return False, str(e)

    def repl_set_step_down(self):
        """
        PostgreSQL doesn't have automatic failover like MongoDB.
        This would require using tools like Patroni, repmgr, or pg_auto_failover.
        
        For manual promotion of a standby to primary:
        - On the standby: SELECT pg_promote()
        - On the old primary: Convert to standby or shut down
        
        This is a placeholder for the actual implementation
        """
        try:
            with self.conn.cursor() as cursor:
                # Check if we're primary
                cursor.execute("SELECT pg_is_in_recovery()")
                is_standby = cursor.fetchone()[0]
                
                if is_standby:
                    return False, "Cannot step down - this is already a standby server"
                
                # In a real implementation, we would:
                # 1. Signal a standby to promote
                # 2. Demote ourselves to standby
                # This requires external orchestration
                
                logger.warning("repl_set_step_down: Manual failover required - automatic stepdown not implemented")
                return False, "Automatic failover not implemented - use external tools like Patroni"
                
        except Exception as e:
            logger.error("repl_set_step_down: Error during PostgreSQL stepdown: {}".format(str(e)))
            return False, str(e)

    def repl_ensure_voting_count(self, config={}):
        """
        PostgreSQL uses synchronous_standby_names for synchronous replication.
        This function adapts the MongoDB voting concept to PostgreSQL sync replicas.
        
        PostgreSQL can have multiple synchronous standbys defined.
        """
        # In PostgreSQL, this would be handled by setting synchronous_standby_names
        # Example: synchronous_standby_names = 'FIRST 2 (standby1, standby2, standby3)'
        
        if len(config.get("members", [])) > 1:
            try:
                sync_standbys = []
                for i, member in enumerate(config['members'][:7]):  # Similar to MongoDB's 7 voting limit
                    if i > 0:  # Skip primary (index 0)
                        host = member.get('host', '').split(':')[0]
                        sync_standbys.append(host)
                
                if sync_standbys:
                    # Configure synchronous standbys
                    sync_config = f"FIRST {min(2, len(sync_standbys))} ({','.join(sync_standbys)})"
                    
                    with self.conn.cursor() as cursor:
                        cursor.execute(f"ALTER SYSTEM SET synchronous_standby_names = '{sync_config}'")
                        cursor.execute("SELECT pg_reload_conf()")
                        
            except Exception as e:
                logger.error(f"repl_ensure_voting_count: Error setting sync standbys: {e}")
        
        return config

    def set_index_ttl(self, db, collection, time_field, nb_seconds, index_filter=None):
        """
        PostgreSQL doesn't have built-in TTL like MongoDB.
        This creates a partial index and sets up a cron job or trigger for deletion.
        
        Alternative approaches:
        1. Use partitioning with automatic partition dropping
        2. Create a trigger that deletes old rows
        3. Use pg_cron extension for scheduled cleanup
        """
        try:
            self.connect_primary()
            
            with self.conn.cursor() as cursor:
                cursor.execute(f"SET search_path TO {db}")
                
                # Create an index on the time field
                index_name = f"idx_{collection}_{time_field}_ttl"
                
                # Build WHERE clause for partial index if filter provided
                where_clause = ""
                if index_filter:
                    where_conditions = self._build_where_conditions(index_filter)
                    if where_conditions:
                        where_clause = f"WHERE {where_conditions}"
                
                # Drop existing index if it exists
                cursor.execute(f"DROP INDEX IF EXISTS {index_name}")
                
                # Create new index
                create_index_sql = f"""
                    CREATE INDEX {index_name} 
                    ON {collection} ({time_field})
                    {where_clause}
                """
                cursor.execute(create_index_sql)
                
                # Create a function for cleanup (if not exists)
                cursor.execute(f"""
                    CREATE OR REPLACE FUNCTION cleanup_{collection}_ttl()
                    RETURNS void AS $$
                    BEGIN
                        DELETE FROM {db}.{collection}
                        WHERE {time_field} < NOW() - INTERVAL '{nb_seconds} seconds'
                        {f"AND {where_conditions}" if where_clause else ""};
                    END;
                    $$ LANGUAGE plpgsql;
                """)
                
                # Note: For actual TTL implementation, you would need:
                # 1. pg_cron extension to schedule the cleanup function
                # 2. OR a background worker/external scheduler
                # 3. OR triggers on INSERT/UPDATE
                
                self.conn.commit()
                
                logger.info(f"PostgresBase::set_index_ttl: Index '{index_name}' created with TTL function.")
                return True, index_name
                
        except Exception as e:
            if self.conn:
                self.conn.rollback()
            logger.error("PostgresBase::set_index_ttl: Error creating TTL index: {}".format(str(e)))
            return False, str(e)

    # Helper methods for SQL building
    def _build_where_clause(self, query_dict):
        """Build WHERE clause from dictionary"""
        if not query_dict:
            return ""
        
        conditions = self._build_where_conditions(query_dict)
        if conditions:
            return f"WHERE {conditions}"
        return ""

    def _build_where_conditions(self, query_dict):
        """Build WHERE conditions from dictionary"""
        conditions = []
        for key, value in query_dict.items():
            if value is None:
                conditions.append(f"{key} IS NULL")
            elif isinstance(value, (list, tuple)):
                # IN clause
                values_str = ', '.join([f"'{v}'" if isinstance(v, str) else str(v) for v in value])
                conditions.append(f"{key} IN ({values_str})")
            elif isinstance(value, dict):
                # Handle operators like $gt, $lt, etc.
                for op, val in value.items():
                    if op == '$gt':
                        conditions.append(f"{key} > {val}")
                    elif op == '$gte':
                        conditions.append(f"{key} >= {val}")
                    elif op == '$lt':
                        conditions.append(f"{key} < {val}")
                    elif op == '$lte':
                        conditions.append(f"{key} <= {val}")
                    elif op == '$ne':
                        conditions.append(f"{key} != {val}")
                    elif op == '$in':
                        values_str = ', '.join([f"'{v}'" if isinstance(v, str) else str(v) for v in val])
                        conditions.append(f"{key} IN ({values_str})")
                    elif op == '$exists':
                        if val:
                            conditions.append(f"{key} IS NOT NULL")
                        else:
                            conditions.append(f"{key} IS NULL")
            else:
                # Simple equality
                if isinstance(value, str):
                    conditions.append(f"{key} = '{value}'")
                else:
                    conditions.append(f"{key} = {value}")
        
        return ' AND '.join(conditions) if conditions else ""

    def _build_set_clause(self, newvalue_dict):
        """Build SET clause from dictionary (for UPDATE statements)"""
        if not newvalue_dict:
            return ""
        
        set_parts = []
        
        # Handle MongoDB-style $set operator
        if '$set' in newvalue_dict:
            update_data = newvalue_dict['$set']
        else:
            update_data = newvalue_dict
        
        for key, value in update_data.items():
            if isinstance(value, (dict, list)):
                # Convert to JSON for JSONB columns
                set_parts.append(f"{key} = '{json.dumps(value)}'::jsonb")
            elif isinstance(value, str):
                set_parts.append(f"{key} = '{value}'")
            elif value is None:
                set_parts.append(f"{key} = NULL")
            else:
                set_parts.append(f"{key} = {value}")
        
        if set_parts:
            return "SET " + ', '.join(set_parts)
        return ""


# Maintain backward compatibility with original class name
# MongoBase = PostgresBase