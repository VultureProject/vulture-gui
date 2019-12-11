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


import logging

from django.conf import settings
from services.frontend.models import Frontend
from system.config.models import Config
from toolkit.network.network import get_proxy
from toolkit.redis.redis_base import RedisBase

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


class NodeNotBootstraped(Exception):
    pass


class ApiParser:
    def __init__(self, data):
        self.data = data

        try:
            self.frontend = Frontend.objects.get(pk=self.data['id'])
        except (Frontend.DoesNotExist, KeyError):
            self.frontend = None

        try:
            # Can't execute on a non valid Vulture Node
            config = Config.objects.get()
        except Config.DoesNotExist:
            raise NodeNotBootstraped()

        self.customer_name = config.customer_name
        self.last_api_call = self.data.get("last_api_call")
        self.key_redis = "api_parser_{frontend_id}_running".format(
            frontend_id=str(self.data.get('id', ""))
        )

        self.proxies = None
        if self.data['api_parser_use_proxy']:
            self.proxies = self.get_system_proxy()

        self.redis_cli = RedisBase()

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
