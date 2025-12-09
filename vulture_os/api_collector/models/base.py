#!/usr/bin/env python
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

__author__ = "Fabien Amelinck"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = "API Collector model classes"
__parser__ = 'GENERIC COLLECTOR'

# Django system imports
from django.conf import settings
from django.utils.translation import gettext_lazy as _
from django.core.exceptions import ObjectDoesNotExist
from django.core.serializers.json import DjangoJSONEncoder
from django.db import DatabaseError, models
# from djongo import models

# Django project imports
from api_collector.utils import JSONDatetimeDecoder
from services.frontend.models import Frontend
from system.config.models import Config
from system.pki.models import X509Certificate
from toolkit.network.network import get_proxy, JAIL_ADDRESSES
from toolkit.redis.redis_base import RedisBase

# Extern modules imports
from redis import ReadOnlyError
from signal import signal, strsignal, SIGINT, SIGTERM
from socket import socket, AF_INET, SOCK_STREAM
from threading import Event, current_thread, main_thread
from time import sleep

# Required exceptions imports

# Logger configuration imports
import logging

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class FailedToLoadCollector(RuntimeError):
    pass


class ApiCollector(models.Model):
    class Meta:
        abstract = True

    # Django-model attributes
    frontend = models.ForeignKey(
        to=Frontend,
        null=True,
        on_delete=models.CASCADE,
        help_text=_("Frontend associated to this collector")
    )
    use_proxy = models.BooleanField(
        default=False,
        verbose_name=_("Use Proxy"),
        help_text=_("Use a proxy to connect to distant endpoint")
    )
    custom_proxy = models.TextField(
        default="",
        help_text=_("Custom Proxy to use when requesting logs"),
        verbose_name=_("Custom Proxy")
    )
    verify_ssl = models.BooleanField(
        default=True,
        help_text=_("Verify SSL"),
        verbose_name=_("Verify certificate")
    )
    custom_certificate = models.ForeignKey(
        to=X509Certificate,
        null=True,
        on_delete=models.SET_NULL,
        # related_name="api_collectors",
        verbose_name=_("Custom certificate"),
        help_text=_("Custom certificate to use.")
    )
    last_collected_timestamps = models.JSONField(
        default=dict,
        encoder=DjangoJSONEncoder,
        decoder=JSONDatetimeDecoder,
    )

    # internal/temporary attributes
    _socket = socket(AF_INET, SOCK_STREAM)
    _redis_cli = RedisBase()
    _session = None
    _proxies = {}
    _evt_stop = Event()
    _custom_certificate_name = None


    @property
    def key_redis(self):
        return f"api_parser_{self.pk}_running"

    @property
    def last_api_call(self):
        return self.last_collected_timestamps['default']

    @property
    def _custom_certificate_bundle(self):
        if self.verify_ssl and self.custom_certificate:
            return self.custom_certificate.bundle_filename
        return None


    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        if current_thread() is main_thread():
            signal(SIGINT, self._handle_stop)
            signal(SIGTERM, self._handle_stop)

        self._socket.settimeout(30)
        if self.frontend:
            self._socket.connect((JAIL_ADDRESSES['rsyslog']['inet'], self.frontend.api_rsyslog_port))

        if self.use_proxy:
            if self.custom_proxy:
                self._proxies = self.get_custom_proxy()
            else:
                self._proxies = self.get_system_proxy()

        try:
            self._redis_cli = RedisBase(
                node=settings.REDISIP,
                port=settings.REDISPORT,
                password=Config.objects.get().redis_password
            )
            assert self.connect(), "Failed to connect to Rsyslog"
        except (ObjectDoesNotExist, DatabaseError, AssertionError):
            raise FailedToLoadCollector("Could not instanciate Collector")


    def connect(self):
        try:
            if self.frontend:
                self._socket.connect((JAIL_ADDRESSES['rsyslog']['inet'], self.frontend.api_rsyslog_port))
            return True
        except Exception as e:
            msg = f"Failed to connect to Rsyslog : {e}"
            logger.error(f"[{__parser__}]:connect: {msg}", extra={'frontend': str(self.frontend)})
            return False


    def get_system_proxy(self) -> dict[str, str]:
        proxy = get_proxy()
        if proxy and len(proxy) > 1:
            return {
                'http': str(proxy.get('http', '')),
                'https': str(proxy.get('https', '')),
                'ftp': str(proxy.get('ftp', '')),
            }

        return {}


    def get_custom_proxy(self) -> dict[str, str]:
        """
        return custom proxy settings from frontend settings

        return: A ready-to-use dict for python request, or
            None in case of no proxy
        """
        proxy = {}
        if self.custom_proxy:
            proxy = {
                "http": self.custom_proxy,
                "https": self.custom_proxy,
                "ftp": self.custom_proxy
            }
        return proxy


    def can_run(self):
        """
        Check if the parser must run (avoid double execution)
        """
        if self._redis_cli.redis.get(self.key_redis):
            return False

        try:
            self._redis_cli.redis.setex(self.key_redis, 300, 1)
        except ReadOnlyError as e:
            logger.error(f"[{__parser__}]:can_run: {e}", extra={'frontend': str(self.frontend)})
            return False
        return True


    def update_lock(self):
        self._redis_cli.redis.setex(self.key_redis, 300, 1)


    def write_to_file(self, lines):
        if len(lines) != 0:
            msg = f"Writing {len(lines)} lines"
            logger.info(f"[{__parser__}]:write_to_file: {msg}", extra={'frontend': str(self.frontend)})
        cpt=0
        for line in lines:
            if cpt%500 == 0:
                self.update_lock()
            try:
                if isinstance(line, str):
                    line = line.encode('utf8')
                self._socket.sendall(line + b"\n")
                cpt += 1
            except Exception as e:
                msg = f"Failed to send to Rsyslog : {e}"
                logger.error(f"[{__parser__}]:write_to_file: {msg}", extra={'frontend': str(self.frontend)})
                # Connect will block until timeout has expired (30s)
                while not self.connect():
                    sleep(0.05)
                    # So refresh lock
                    self.update_lock()


    def _handle_stop(self, signum, frame):
        logger.info(f"[{__parser__}]:_handle_stop: caught signal {strsignal(signum)}({signum}), stopping...", extra={'frontend': str(self.frontend)})
        self._evt_stop.set()


    def finish(self):
        """
        Remove redis lock
        """
        self._redis_cli.redis.delete(self.key_redis)


    def test(self):
        raise NotImplementedError()

    def fetch_data(self):
        raise NotImplementedError()

    def execute(self):
        raise NotImplementedError()
