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
__author__ = "Théo Bertin"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Proofpoint POD API Parser'
__parser__ = 'PROOFPOINT POD'


from datetime import timedelta
import json
import logging
import time
from urllib.parse import urlparse
import websocket

from django.conf import settings
from django.utils import timezone, dateparse
from toolkit.api_parser.api_parser import ApiParser
from toolkit.log.log_utils import get_obj_value_or_default

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')



class ProofpointPodParseError(Exception):
    pass


class ProofpointPodAPIError(Exception):
    pass


class ProofpointPodParser(ApiParser):

    def __init__(self, data):
        super().__init__(data)

        self.ws = None
        self.last_timestamp = None
        self.buffer = list()
        self.ignore_before = None

        proofpoint_pod_uri = data.get('proofpoint_pod_uri')
        proofpoint_pod_cluster_id = data.get('proofpoint_pod_cluster_id')
        proofpoint_pod_token = data.get('proofpoint_pod_token')

        if "https://" in proofpoint_pod_uri:
            proofpoint_pod_uri.replace("https://", "wss://")
        elif "http://" in proofpoint_pod_uri:
            proofpoint_pod_uri.replace("http://", "ws://")
        elif "ws://" not in proofpoint_pod_uri and "wss://" not in proofpoint_pod_uri:
            proofpoint_pod_uri = "wss://" + proofpoint_pod_uri

        self.extra_headers = {
            "Authorization": f"Bearer {proofpoint_pod_token}"
        }

        self.proofpoint_pod_url = f"{proofpoint_pod_uri}?cid={proofpoint_pod_cluster_id}&type=message"


    def __del__(self):
        if self.ws:
            self.ws.close(timeout=1)


    def test(self):
        current_time = time.time()
        sinceTime = timezone.now() - timedelta(hours=2)
        msg = None

        try:
            while time.time() < current_time + 10 and not msg:
                msg = self._websocket_fetch(sinceTime=sinceTime.isoformat())
                if msg:
                    msg = json.loads(msg)
        except Exception as e:
            return {
                'status': False,
                 'error': f'Error while fetching sample message from API: {e}'
            }

        return {
            'status': True,
            'data': [msg]
        }

    def parse_log(self, log):
        try:

            parsed = json.loads(log)
            parsed_ts = dateparse.parse_datetime(parsed['ts'])

            parsed.update({
                'additional': {
                    'related': {
                        'hash': set(),
                        'hosts': set(),
                        'url': set(),
                        'filename': set(),
                    },
                    'email': {
                        'attachments': []
                    },
                    'msgParts': []
                }
            })

            # pop dictionnary, to keep only required fields in result
            for part in parsed.pop('msgParts', []):
                parsed['additional']['related']['hash'].add(part.get('md5', ''))
                parsed['additional']['related']['hash'].add(part.get('sha256', ''))

                for url_obj in part.get('urls', []):
                    url = url_obj.get('url', '')
                    # remove urls that are simply action-links to send a mail
                    if "mailto:" in url:
                        continue
                    # clean url fields to keep only domain and path
                    if '://' in url:
                        url = url.split('://')[1]
                    url = url.split('?')[0]
                    parsed['additional']['related']['url'].add(url)

                parsed['additional']['email']['attachments'].append({
                    'file': {
                        'extension': part.get('detectedExt', '').lower(),
                        'mime_type': part.get('detectedMime', ''),
                        'name': part.get('detectedName', ''),
                        'size': part.get('detectedSizeBytes', ''),
                        'hash': {
                            'md5': part.get('md5', ''),
                            'sha256': part.get('sha256', ''),
                        }
                    }
                })

                parsed['additional']['related']['filename'].add(part.get('detectedName', ''))

                parsed['additional']['msgParts'].append({
                    'name': part.get('detectedName', ''),
                    'isVirtual': part.get('isVirtual', False),
                    'isTimedOut': part.get('isTimedOut', False),
                    'isProtected': part.get('isProtected', False),
                    'isDeleted': part.get('isDeleted', False),
                    'isCorrupted': part.get('isCorrupted', False),
                    'isArchive': part.get('isArchive', False),
                })

            if results := get_obj_value_or_default(parsed, 'filter.modules.dmarc.alignment.results'):
                for result in results:
                    # check if 'identity' exists (not required according to documentation)
                    if identity := result.get('identity'):
                        parsed['additional']['related']['hosts'].add(identity)
            if results := get_obj_value_or_default(parsed, 'filter.modules.dkimv'):
                for result in results:
                    # no need to check if 'domain' exists (required according to documentation)
                    # still be on the safe side and get() instead of direct index access
                    parsed['additional']['related']['hosts'].add(result.get('domain', ''))
            if result := get_obj_value_or_default(parsed, 'connection.helo'):
                parsed['additional']['related']['hosts'].add(result)

            parsed['additional']['related']['hash'] = list(parsed['additional']['related']['hash'])
            parsed['additional']['related']['hosts'] = list(parsed['additional']['related']['hosts'])
            parsed['additional']['related']['url'] = list(parsed['additional']['related']['url'])
            parsed['additional']['related']['filename'] = list(parsed['additional']['related']['filename'])

            return parsed_ts, parsed
        except (json.JSONDecodeError, KeyError, ValueError) as e:
            logger.warning(f"[{__parser__}]:parse_log: could not parse a log line -> {e}", extra={'frontend': str(self.frontend)})
            logger.debug(f"[{__parser__}]:parse_log: log is {log}", extra={'frontend': str(self.frontend)})
            return None


    def _websocket_fetch(self, sinceTime=None):
        if not self.ws:
            self._websocket_connect(sinceTime=sinceTime)

        try:
            return self.ws.recv()
        except websocket._exceptions.WebSocketTimeoutException:
            logger.debug(f"[{__parser__}]:_websocket_fetch: timeout waiting for log", extra={'frontend': str(self.frontend)})
            return None
        except websocket._exceptions.WebSocketConnectionClosedException:
            raise
        except websocket._exceptions.WebSocketException as e:
            logger.error(f"[{__parser__}]:_websocket_fetch: error while fetching next log -> {e}", extra={'frontend': str(self.frontend)})
            raise ProofpointPodAPIError(f"Could not get next log: {e}")


    def _websocket_connect(self, sinceTime=None):
        if self.ws:
            self.ws.close(timeout=1)
            self.ws = None
        try:
            if sinceTime:
                proofpoint_pod_url = self.proofpoint_pod_url + f"&sinceTime={sinceTime}"
            else:
                proofpoint_pod_url = self.proofpoint_pod_url
            logger.debug(f"[{__parser__}]:_websocket_connect: trying to connect to {proofpoint_pod_url}, with headers {self.extra_headers}", extra={'frontend': str(self.frontend)})
            # set proxy if configured
            if self.proxies:
                proxy_ = urlparse(self.proxies.get('http'))
                proxy_split = proxy_.netloc.split(':')
                http_proxy_host = proxy_split[0]
                if len(proxy_split) > 1:
                    http_proxy_port = proxy_split[1]
                else:
                    http_proxy_port = 80
                # timeout is set for connection
                self.ws = websocket.create_connection(proofpoint_pod_url, timeout=10, header=self.extra_headers, http_proxy_host=http_proxy_host, http_proxy_port=http_proxy_port)
            else:
                # timeout is set for connection
                self.ws = websocket.create_connection(proofpoint_pod_url, timeout=10, header=self.extra_headers)

        except websocket._exceptions.WebSocketConnectionClosedException:
            raise
        except websocket._exceptions.WebSocketException as e:
            logger.error(f"[{__parser__}]:_websocket_connect: WebSocket connection error -> {e}", extra={'frontend': str(self.frontend)})
            raise ProofpointPodAPIError(f"Could not connect to API: {e}")

        # lower (web)socket's timeout to set to non-blocking mode and allow quick interruptions
        self.ws.settimeout(1)


    def _flush_buffer(self):
        logger.debug(f"[{__parser__}]:parse_log: current timestamp cursor: {self.last_timestamp.isoformat()}", extra={'frontend': str(self.frontend)})
        if self.buffer:
            self.write_to_file(self.buffer)
            self.buffer.clear()


    def execute(self):
        start_time = time.monotonic()
        logger.info(f"[{__parser__}]:execute: Starting tasks", extra={'frontend': str(self.frontend)})
        stop_after = 50 # stop parser after 50 seconds (allows to refresh code during upgrades)

        current_time = time.time()
        if not self.frontend.last_api_call:
            self.frontend.last_api_call = timezone.now()
        self.last_timestamp = self.frontend.last_api_call

        # stop parser after 1 hour when last call was more that an hour ago (need time to get bundle of logs for past hours, and will stop once it's done)
        if self.last_timestamp.timestamp() + 3600 < current_time:
            logger.info(f"[{__parser__}]:execute: last call was more than an hour ago, parser will run for (max) 1 hour to catch up with current time", extra={'frontend': str(self.frontend)})
            stop_after = 3600

        try:
            logger.info(f"[{__parser__}]:execute_query: sinceTime: {self.frontend.last_api_call.isoformat()}", extra={'frontend': str(self.frontend)})
            while time.monotonic() < start_time + stop_after and not self.evt_stop.is_set():
                msg = self._websocket_fetch(sinceTime=self.frontend.last_api_call.isoformat())
                if msg:
                    timestamp, msg = self.parse_log(msg)
                    if msg:
                        self.buffer.append(json.dumps(msg))
                        self.last_timestamp = max(self.last_timestamp, timestamp)
                        if len(self.buffer) >= 128:
                            self._flush_buffer()
                else:
                    # no new log received during timeout, flush current buffer
                    logger.debug(f"[{__parser__}]:execute: no logs received for some time, flushing buffer", extra={'frontend': str(self.frontend)})
                    self._flush_buffer()
        except (ProofpointPodAPIError, ProofpointPodParseError):
            raise
        except websocket._exceptions.WebSocketConnectionClosedException:
            logger.info(f"[{__parser__}]:execute: Connection was closed, finalizing...", extra={'frontend': str(self.frontend)})
            pass
        except Exception as e:
            logger.critical(f"[{__parser__}]:execute: Error while processing logs -> {e}", extra={'frontend': str(self.frontend)})
            raise ProofpointPodAPIError("Unknown error: {e}")

        if self.buffer:
            logger.debug(f"[{__parser__}]:execute: flushing remaining logs", extra={'frontend': str(self.frontend)})
            self._flush_buffer()

        self.frontend.last_api_call = self.last_timestamp
        logger.info(f"[{__parser__}]:execute: Updated frontend timestamp is {self.frontend.last_api_call}", extra={'frontend': str(self.frontend)})

        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})
        self.finish()
