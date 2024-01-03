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

import json
import logging
import time

import websocket
from threading import Thread

from django.conf import settings
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

    def get_logs(self):
        url = f"{self.ENDPOINT}?channel={self.retarus_channel}"
        ws = websocket.WebSocketApp(
            url,
            header=[f"Authorization: Bearer {self.retarus_token}"],
            on_open=self.on_open,
            on_message=self.on_message,
            on_error=self.on_error,
            on_close=self.on_close
        )
        ws.run_forever(ping_interval=60)

    def _update_lock(self):
        while not self.evt_stop.is_set():
            # Updating lock every 60s to prevent multiprocessing
            self.update_lock()
            time.sleep(60)

    def execute(self):
        thread_get_logs = Thread(target=self.get_logs)
        thread_update_lock = Thread(target=self._update_lock)

        thread_get_logs.start()
        thread_update_lock.start()

        thread_get_logs.join()
        thread_update_lock.join()

    def on_open(self, ws):
        logger.info(f"[{__parser__}]:get_logs: Connection established.", extra={'frontend': str(self.frontend)})

    def on_message(self, ws, message):
        ## WRITE TO FILE ##
        self.write_to_file([self.format_log(json.loads(message))])

    def on_error(self, ws, error):
        logger.error(f"[{__parser__}]:get_logs: {error}", extra={'frontend': str(self.frontend)})

    def on_close(self, ws, status_code, close_msg):
        logger.info(f"[{__parser__}]:get_logs: Connection closed.", extra={'frontend': str(self.frontend)})
