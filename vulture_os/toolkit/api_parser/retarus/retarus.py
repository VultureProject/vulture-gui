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
__author__ = "Gaultier Parain"
__credits__ = [""]
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'RETARUS API'
__parser__ = 'RETARUS'

import datetime
import json
import logging

import websocket
from urllib.parse import urlparse

from django.conf import settings
from django.utils import timezone
from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class RetarusAPIError(Exception):
    pass


class RetarusParser(ApiParser):
    HEADERS = {
        "Content-Type": "application/json",
        'Accept': 'application/json'
    }

    ENDPOINT = "wss://events.retarus.com/v1/websocket"

    def __init__(self, data):
        super().__init__(data)

        self.retarus_token = data["retarus_token"]
        self.retarus_channel = data["retarus_channel"]

        self.buffer = list()

    def _connect(self):
        try:
            extra_headers = {
                'header': [f"Authorization: Bearer {self.retarus_token}"],
            }
            url = f"{self.ENDPOINT}?channel={self.retarus_channel}"

            if self.proxies:
                proxy_ = urlparse(self.proxies.get('http'))
                proxy_split = proxy_.netloc.split(':')
                extra_headers['http_proxy_host'] = proxy_split[0]
                extra_headers['http_proxy_port'] = proxy_split[1] if len(proxy_split) > 1 else 80

            return websocket.create_connection(url, timeout=20, **extra_headers)
        except Exception as e:
            logger.error(f"[{__parser__}]:_connect: WebSocket connection error: {e}", extra={'frontend': str(self.frontend)})
            raise RetarusAPIError(f"Could not connect to API: {e}")

    def test(self):

        ws = websocket.create_connection(self.ENDPOINT, header=["Authorization: Bearer " + self.retarus_token])
        try:
            result = ws.recv()
            return {
                "status": True,
                "data": [result]
            }
        except Exception as e:
            logger.exception(f"{[__parser__]}:test: {str(e)}", extra={'frontend': str(self.frontend)})
            return {
                "status": False,
                "error": str(e)
            }

    @staticmethod
    def format_log(log):
        return json.dumps(log)

    def _flush_buffer(self):
        if self.buffer:
            self.write_to_file(self.buffer)
            self.buffer.clear()

    def execute(self):
        current_time = timezone.now()
        ws = self._connect()

        try:
            while not self.evt_stop.is_set():
                if msg := ws.recv():
                    self.buffer.append(self.format_log(msg))
                    if len(self.buffer) >= 128:
                        self._flush_buffer()

                if timezone.now() >= (current_time + datetime.timedelta(seconds=10)):
                    current_time = timezone.now()
                    self.update_lock()
        except websocket._exceptions.WebSocketConnectionClosedException:
            logger.info(f"[{__parser__}]:execute: Connection was closed, finalizing...", extra={'frontend': str(self.frontend)})
        except Exception as e:
            logger.error(f"[{__parser__}]:execute: WebSocket recv error -> {e}", extra={'frontend': str(self.frontend)})
            raise RetarusAPIError(f"Unknown error: {e}")

        if self.buffer:
            logger.debug(f"[{__parser__}]:execute: flushing remaining logs", extra={'frontend': str(self.frontend)})
            self._flush_buffer()
