#!/home/vlt-os/env/bin/python
"""This file is part of Vulture OS.

Vulture OS is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Vulture OS is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Vulture OS.  If not, see http://www.gnu.org/licenses/.
"""
__author__ = "Olivier de Régis"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'API Parser'
__parser__ = 'API PARSER'

import logging
import socket
import time

from django.conf import settings
from services.frontend.models import Frontend
from system.config.models import Config
from vulture_os.toolkit.network.network import get_proxy
from vulture_os.toolkit.redis.redis_base import RedisBase
from vulture_os.toolkit.network.network import JAIL_ADDRESSES

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class NodeNotBootstraped(Exception):
    pass


class ApiParser:
    def __init__(self, data):
        self.data = data

        try:
            self.frontend = Frontend.objects.get(pk=self.data['id'])
        except (Frontend.DoesNotExist, KeyError):
            self.frontend = None

        self.socket = None

        try:
            # Can't execute on a non valid Vulture Node
            config = Config.objects.get()
        except Config.DoesNotExist:
            raise NodeNotBootstraped()

        self.tenant_name = self.frontend.tenants_config.name if self.frontend else "test"

        self.last_api_call = self.data.get("last_api_call")
        self.key_redis = "api_parser_{frontend_id}_running".format(
            frontend_id=str(self.data.get('id', ""))
        )

        self.proxies = None
        if self.data['api_parser_use_proxy']:
            self.proxies = self.get_system_proxy()

        self.redis_cli = RedisBase()

        assert self.connect(), "Failed to connect to Rsyslog"

    def connect(self):
        try:
            if self.frontend:
                self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self.socket.settimeout(30)
                self.socket.connect((JAIL_ADDRESSES['rsyslog']['inet'], self.frontend.api_rsyslog_port))
            return True
        except Exception as e:
            msg = f"Failed to connect to Rsyslog : {e}"
            logger.error(f"{[__parser__]}:{self.connect.__name__}: {msg}", extra={'frontend': str(self.frontend)})
            return False

    def get_system_proxy(self):
        proxy = get_proxy()
        if len(proxy) > 1:
            return proxy

        return None

    def can_run(self):
        """
        Check if the parser must run (avoid twice execution)
        """
        if self.redis_cli.redis.get(self.key_redis):
            return False

        self.redis_cli.redis.setex(self.key_redis, 300, 1)
        return True

    def update_lock(self):
        self.redis_cli.redis.setex(self.key_redis, 300, 1)

    def write_to_file(self, lines):
        if len(lines) != 0:
            msg = f"Writing {len(lines)} lines"
            logger.info(f"{[__parser__]}:{self.write_to_file.__name__}: {msg}", extra={'frontend': str(self.frontend)})
        cpt=0
        for line in lines:
            if cpt%500 == 0:
                self.update_lock()
            try:
                if isinstance(line, str):
                    line = line.encode('utf8')
                self.socket.send(line + b"\n")
                cpt += 1
            except Exception as e:
                msg = f"Failed to send to Rsyslog : {e}"
                logger.error(f"{[__parser__]}:{self.write_to_file.__name__}: {msg}", extra={'frontend': str(self.frontend)})
                # Connect will block until timeout has expired (30s)
                while not self.connect():
                    time.sleep(0.05)
                    # So refresh lock
                    self.update_lock()

    def finish(self):
        """
        Remove redis lock & save frontend
        """
        self.redis_cli.redis.delete(self.key_redis)
        self.frontend.save()

    def test(self):
        raise NotImplemented()

    def fetch_data(self):
        raise NotImplemented()

    def execute(self):
        raise NotImplemented()
