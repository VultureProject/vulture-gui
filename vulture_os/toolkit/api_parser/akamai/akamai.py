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
__doc__ = 'Akamai API Parser'
__parser__ = 'AKAMAI'

import base64
import datetime
import json
import logging
import time
import requests
import urllib.parse

from multiprocessing import Process, Event, Lock, Queue, Value
from akamai.edgegrid import EdgeGridAuth
from django.conf import settings
from django.utils import timezone
from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class AkamaiParseError(Exception):
    pass


class AkamaiAPIError(Exception):
    pass


def akamai_write(akamai):
    def get_bulk(size):
        res = []
        while len(res) < size and (not akamai.event_write.is_set() or akamai.queue_write.qsize() > 0):
            try:
                # Wait max 2 seconds for a log
                log = akamai.queue_write.get(block=True, timeout=2)
            except:
                msg = f"Exception in queue_write.get()"
                logger.info(f"[{__parser__}]:{get_bulk.__name__}: {msg}", extra={'frontend': str(akamai.frontend)})
                continue
            try:
                # Data to write must be bytes
                res.append(json.dumps(log).encode('utf8'))
            except:
                msg = f"Line {log} is not json formated"
                logger.info(f"[{__parser__}]:{get_bulk.__name__}: {msg}", extra={'frontend': str(akamai.frontend)})
                pass
                #            queue_write.task_done()
        return res

    while not akamai.event_write.is_set() or akamai.queue_write.qsize() > 0:
        akamai.write_to_file(get_bulk(10000))
        akamai.update_lock()

    msg = f"Writting worker finished"
    logger.info(f"[{__parser__}]:{akamai_write.__name__}: {msg}", extra={'frontend': str(akamai.frontend)})


def akamai_parse(akamai):
    while not akamai.event_parse.is_set() or akamai.queue_parse.qsize() > 0:
        try:
            # Wait max 2 seconds for a log
            log = json.loads(akamai.queue_parse.get(block=True, timeout=2).decode('utf-8'))
        except:
            continue

        timestamp_epoch = int(log['httpMessage']['start'])
        timestamp = timezone.make_aware(datetime.datetime.utcfromtimestamp(timestamp_epoch))

        tmp = {
            'time': timestamp.isoformat(),
            'httpMessage': log['httpMessage'],
            'geo': log['geo'],
            'attackData': {
                'clientIP': log['attackData'].get('clientIP', '0.0.0.1')
            }
        }

        # Urldecode and parse headers
        tmp_request_headers = tmp["httpMessage"].get('requestHeaders', "-")
        request_headers = urllib.parse.unquote(tmp_request_headers)
        all_request_headers = dict()
        for r in request_headers.split("\r\n"):
            if r and r != "{p}":
                try:
                    name, value = r.split(": ", maxsplit=1)
                except Exception:
                    name, value = r.split(":", maxsplit=1)[0], "-"
                all_request_headers[name] = value or "-"

        tmp_response_headers = tmp['httpMessage'].get('responseHeaders', '-')
        response_headers = urllib.parse.unquote(tmp_response_headers)
        all_response_headers = {'Set-Cookie': []}
        for r in response_headers.split("\r\n"):
            if r and r != "{p}":
                try:
                    name, value = r.split(": ", maxsplit=1)
                except Exception:
                    name, value = r.split(":", maxsplit=1)[0], "-"
                if name.lower().startswith("set-cookie"):
                    all_response_headers["Set-Cookie"].append(value)
                else:
                    all_response_headers[name] = value or '-'

        all_response_headers['Set-Cookie'] = "; ".join(all_response_headers['Set-Cookie']) or "-"

        tmp['httpMessage']['requestHeaders'] = all_request_headers
        tmp['httpMessage']['responseHeaders'] = all_response_headers

        # Unquote attackData fields and decode them in base64
        for key in akamai.ATTACK_KEYS:
            tmp_data = log['attackData'][key]
            tmp_data = urllib.parse.unquote(tmp_data).split(';')

            values = []
            for data in tmp_data:
                if data:
                    values.append(base64.b64decode(data).decode('utf-8'))

            tmp['attackData'][key] = values

        akamai.queue_write.put(tmp)

        # Update the last log time
        with akamai.data_lock:
            if timestamp_epoch > akamai.last_log_time.value:
                akamai.last_log_time.value = timestamp_epoch

    logger.info(f"[{__parser__}]:{akamai_write.__name__}: Worker parse finished",
                extra={'frontend': str(akamai.frontend)})


class AkamaiParser(ApiParser):
    ATTACK_KEYS = ["rules", "ruleMessages", "ruleTags", "ruleActions", "ruleData"]
    NB_WORKER = 8

    def __init__(self, data):
        super().__init__(data)

        self.first_log = False
        self.last_log = False
        self.offset = "a"
        self.akamai_host = data.get('akamai_host')
        self.akamai_client_secret = data.get('akamai_client_secret')
        self.akamai_access_token = data.get('akamai_access_token')
        self.akamai_client_token = data.get('akamai_client_token')
        self.akamai_config_id = data.get('akamai_config_id')

        self.version = "v1"

        if not self.akamai_host.startswith('https'):
            self.akamai_host = f"https://{self.akamai_host}"

        self.last_log_time = None
        self.event_parse = None
        self.event_write = None
        self.queue_parse = None
        self.queue_write = None
        self.data_lock = None
        self.session = None

    def _connect(self):
        try:
            if self.session is None:
                self.session = requests.Session()
                self.session.auth = EdgeGridAuth(
                    client_token=self.akamai_client_token,
                    client_secret=self.akamai_client_secret,
                    access_token=self.akamai_access_token
                )
            return True

        except Exception as err:
            raise AkamaiAPIError(err)

    def get_logs(self, test=False, since=None):
        self._connect()

        url = f"{self.akamai_host}/siem/{self.version}/configs/{self.akamai_config_id}"

        params = {
            'limit': 100000
        }
        if self.offset != "a":
            params['offset'] = self.offset
        else:
            params['from'] = since or int(self.last_log_time.value)

        if test:
            params['limit'] = 1

        self.offset = None
        result = []

        with self.session.get(url, params=params, proxies=self.proxies, stream=True) as r:
            r.raise_for_status()
            i = 0

            if test:
                return list(r.iter_lines())[-1].decode('utf-8')

            for line in r.iter_lines():
                if not line:
                    continue

                if b"\"httpMessage\"" in line:
                    self.queue_parse.put(line)
                    i = i + 1
                else:
                    try:
                        line = json.loads(line.decode('utf-8'))
                        msg = f"{line}"
                        logger.info(f"[{__parser__}]:get_logs: {msg}", extra={'frontend': str(self.frontend)})
                        self.offset = line['offset']
                    except:
                        continue

            logger.info(f"[{__parser__}]:get_logs: Fetched {i} lines", extra={'frontend': str(self.frontend)})

    def test(self):
        try:
            since = (timezone.now() - datetime.timedelta(minutes=15)).timestamp()
            data = self.get_logs(test=True, since=since)

            return {
                'status': True,
                'data': data
            }

        except AkamaiAPIError as e:
            return {
                'status': False,
                'error': str(e)
            }

    def execute(self):
        self.event_parse = Event()
        self.event_write = Event()
        self.queue_parse = Queue(maxsize=100000)
        self.queue_write = Queue(maxsize=100000)
        self.data_lock = Lock()
        self.last_log_time = Value('q', int(self.last_api_call.timestamp()))
        try:
            workers = []
            for i in range(self.NB_WORKER):
                t_parse = Process(target=akamai_parse, args=(self,))
                t_parse.start()
                workers.append(t_parse)

            t_write_1 = Process(target=akamai_write, args=(self,))
            t_write_1.start()
            workers.append(t_write_1)

            # t_write_2 = Process(target=akamai_write, args=(self,))
            # t_write_2.start()
            # workers.append(t_write_2)

            self.offset = "a"
            try:
                while not self.evt_stop.is_set() and self.last_log_time.value < (timezone.now() - datetime.timedelta(minutes=1)).timestamp() and self.offset:
                    self.get_logs()
                    self.update_lock()
                    self.frontend.last_api_call = timezone.make_aware(datetime.datetime.utcfromtimestamp(self.last_log_time.value))
                    self.frontend.save()
                    msg = f"{self.last_log_time.value}"
                    logger.info(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})
            except Exception as e:
                msg = f"Fail to download/update akamai logs: {e}"
                logger.error(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})

            self.event_parse.set()
            self.event_write.set()

            for t in workers:
                logger.info(f"[{__parser__}]:execute: Joining workers {t}", extra={'frontend': str(self.frontend)})
                t.join()
                logger.info(f"[{__parser__}]:execute: Workers joined {t}", extra={'frontend': str(self.frontend)})

            # Do not join because there can still be something in queues
            # queue_parse.join()
            # queue_write.join()

            logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})

        except Exception as e:
            raise AkamaiParseError(e)
