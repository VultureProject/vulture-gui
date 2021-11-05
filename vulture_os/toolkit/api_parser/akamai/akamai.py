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


import datetime
import json
import time
import logging
import requests
import base64
import urllib.parse
import queue

from threading import Thread, Event, Lock
from akamai.edgegrid import EdgeGridAuth
from django.conf import settings
from django.utils import timezone
from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


event_parse = Event()
event_write = Event()
queue_parse = queue.Queue(maxsize=100000)
queue_write = queue.Queue(maxsize=100000)
data_lock = Lock()


class AkamaiParseError(Exception):
    pass


class AkamaiAPIError(Exception):
    pass


def akamai_write(akamai):
    def get_bulk(size):
        res = []
        while len(res) < size and not queue_write.empty():
            try:
                # Wait max 2 seconds for a log
                log = queue_write.get(block=True, timeout=2)
            except:
                logger.info("akamai_write::get_bulk: Exception in queue_write.get()",
                            extra={'tenant': akamai.tenant_name})
                continue
            try:
                # Data to write must be bytes
                res.append(json.dumps(log).encode('utf8'))
            except:
                logger.error("Line {} is not json formated".format(log),
                             extra={'tenant': akamai.tenant_name})
                pass
#            queue_write.task_done()
        return res

    while not event_write.is_set() or not queue_write.empty():
        akamai.write_to_file(get_bulk(10000))
        akamai.update_lock()
        # logger.info("Parse queue size: {}".format(queue_parse.qsize()))
        # logger.info("Write queue size: {}".format(queue_write.qsize()))

    logger.info("Writting thread finished",
                extra={'tenant': akamai.tenant_name})


def akamai_parse(akamai):
    while not event_parse.is_set() or not queue_parse.empty():
        try:
            # Wait max 2 seconds for a log
            log = queue_parse.get(block=True, timeout=2)
        except:
            continue

        timestamp = int(log['httpMessage']['start'])
        timestamp = timezone.make_aware(datetime.datetime.utcfromtimestamp(timestamp))

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

        queue_write.put(tmp)

        # Update the last log time
        if timestamp > akamai.last_log_time:
            with data_lock:
                akamai.last_log_time = timestamp


class AkamaiParser(ApiParser):
    ATTACK_KEYS = ["rules", "ruleMessages", "ruleTags", "ruleActions", "ruleData"]
    NB_THREAD = 4

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

        self.last_log_time = self.last_api_call
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

    def get_logs(self, test=False):
        self._connect()

        url = f"{self.akamai_host}/siem/{self.version}/configs/{self.akamai_config_id}"

        params = {
            'limit': 100000
        }
        if self.offset != "a":
            params['offset'] = self.offset
        else:
            params['from'] = int(self.last_log_time.timestamp())

        if test:
            params['limit'] = 1

        self.offset = None
        result = []

        with self.session.get(url, params=params, proxies=self.proxies, stream=True) as r:
            r.raise_for_status()
            i = 0
            for line in r.iter_lines():
                if not line:
                    continue

                try:
                    line = json.loads(line.decode('utf-8'))
                except json.decoder.JSONDecodeError:
                    continue

                if "httpMessage" in line.keys():
                    queue_parse.put(line)
                    i = i + 1
                else:
                    logger.info(line, extra={'tenant': self.tenant_name})
                    self.offset = line['offset']
            
            logger.info("akamai::get_logs: Fetched {} lines".format(i), extra={'tenant': self.tenant_name})

    def test(self):
        try:
            t_parse = Thread(target=akamai_parse, args=(self,))
            t_parse.start()
            data = []
            self.last_log_time = timezone.now() - datetime.timedelta(minutes=15)
            self.get_logs(test=True)
            cpt = 0
            while cpt < 5:
                log = queue_write.get()
                if log:
                    data.append(log)
                    break
                else:
                    time.sleep(1)
                    cpt += 1

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
        try:
            threads = []
            for i in range(self.NB_THREAD):
                t_parse = Thread(target=akamai_parse, args=(self,))
                t_parse.start()
                threads.append(t_parse)


            t_write_1 = Thread(target=akamai_write, args=(self,))
            t_write_1.start()
            threads.append(t_write_1)

            t_write_2 = Thread(target=akamai_write, args=(self,))
            t_write_2.start()
            threads.append(t_write_2)

            self.offset = "a"
            try:
                while self.last_log_time < (timezone.now()-datetime.timedelta(minutes=1)) and self.offset:
                    self.get_logs()
                    self.update_lock()
                    self.frontend.last_api_call = self.last_log_time
                    logger.info(self.last_log_time, extra={'tenant': self.tenant_name})
            except Exception as e:
                logger.error("Fail to download/update akamai logs : {}".format(e), extra={'tenant': self.tenant_name})

            event_parse.set()
            event_write.set()

            # Wait for threads to finish
            for t in threads:
                t.join()

            # Do not join because there can still be something in queues
            #queue_parse.join()
            #queue_write.join()

            logger.info("Akamai parsing done.", extra={'tenant': self.tenant_name})

        except Exception as e:
            raise AkamaiParseError(e)
