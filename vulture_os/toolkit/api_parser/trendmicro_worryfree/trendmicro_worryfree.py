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
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Trendmicro_Worryfree API Parser'
__parser__ = 'Trendmicro_Worryfree'

import json
import logging
import requests
import hmac
import base64
import hashlib
import uuid

from datetime import datetime, timedelta
from django.utils import timezone
from django.conf import settings
from toolkit.api_parser.api_parser import ApiParser
from urllib.parse import urlencode, unquote

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class TrendmicroWorryfreeError(Exception):
    pass


class TrendmicroWorryfreeParser(ApiParser):
    HEADERS = {
        "content-type": "application/json"
    }
    LOG_EXISTENCE_URI = "/SMPI/service/wfbss/customer/api/1.0/log_existence"
    QUERY_LOG_URI = "/SMPI/service/wfbss/customer/api/1.0/logfeeder/query_syslog"
    LOG_PAGE_LIMIT = 100
    retry = 3

    log_types = ["virus","spyware","wtp","url_filtering","behavior_monitoring","application_control","machine_learning","network_virus","dlp"]

    def __init__(self, data):
        super().__init__(data)

        self.trendmicro_worryfree_access_token = data["trendmicro_worryfree_access_token"]
        self.trendmicro_worryfree_secret_key = data["trendmicro_worryfree_secret_key"]
        self.trendmicro_worryfree_server_name = data["trendmicro_worryfree_server_name"]
        self.trendmicro_worryfree_server_port = data["trendmicro_worryfree_server_port"]

        if int(self.trendmicro_worryfree_server_port) == 443:
            self.scheme = "https"
        else:
            self.scheme = "http"

        self.session = None

    def __get_content_md5(self, content):
        '''
        Get hashed content
        '''
        m = hashlib.md5()
        m.update(content.encode("utf8"))
        digest = m.digest()
        digest = base64.b64encode(digest)
        return digest.decode('utf8')

    def __gen_x_signature(self, x_posix_time, request_method, request_uri, body):
        '''
        Generate x-signature
        '''
        payload = x_posix_time + request_method.upper() + request_uri
        if body:
            payload += self.__get_content_md5(body)
        print(payload)
        hm = hmac.new(self.trendmicro_worryfree_secret_key.encode("utf8"),
                      payload.encode("utf8"), hashlib.sha256)
        digest = hm.digest()
        digest = base64.b64encode(digest)
        return digest

    def __get_auth_headers(self, method, request_uri, body):
        '''
        Generate authentication herders
        '''
        posix_time = int(timezone.now().timestamp())

        headers = {}
        headers["content-type"] = "application/json"
        headers["x-access-token"] = self.trendmicro_worryfree_access_token
        headers["x-signature"] = self.__gen_x_signature(str(posix_time),
                            method, request_uri, body)
        headers["x-posix-time"] = str(posix_time)
        headers["x-traceid"] = str(uuid.uuid4())

        return headers

    def __connect(self):
        self.session = requests.Session()

    def send_request(self, http_method, request_uri, body=None, retry=3):
        '''
        Send request to access CSPI
        '''
        retry_time = 0
        while retry_time < retry:
            headers = self.__get_auth_headers(http_method, request_uri, body)
            url = "%s://%s%s" % (self.scheme, self.trendmicro_worryfree_server_name, request_uri)
            resp = self.session.request(http_method, url, data=body, headers=headers, proxies=self.proxies)
            if resp.status_code == 200:
                break
            else:
                retry_time += 1
        return resp.status_code, resp.headers, resp.content

    def close(self):
        self.session.close()

    def _run(self, method, uri, body=None):
        self.__connect()
        try:
            res_status, headers, res_data = self.send_request(method, uri, body=body)
            if res_status != 200:
                print("Response status: \n%r" % res_status)
                print("Response data: \n%r" % res_data)
        finally:
            self.close()
        try:
            res_dict = json.loads(res_data)
        except ValueError as e:
            res_dict = {}
        return res_status, res_dict

    def __execute_query(self, query=None, timeout=10):
        if query is None:
            query = {}
        request_body = query
        uri = self.LOG_EXISTENCE_URI
        res_status, res_data = self._run("POST", self.LOG_EXISTENCE_URI, json.dumps(request_body))

        result = {}
        if res_status == 200 and res_data["result"]:
            # Show the converted Epoch time
            print(u'|%50s | %140s|' % ('customer id', 'log_types'))
            for i in res_data["result"]:
                result[i.get("cid", "endpoint")] = i["log_types"]
                print(u'|%50s | %140s|' % (i.get("cid"), ', '.join(i["log_types"])))
        else:
            print("There is no log in time range in Epoch %d ~ %d" % (query["range_from"], query["range_to"]))

        print(result.items)
        result_logs = []
        for cid, log_types in result.items():
            for log_type in log_types:
                if log_type in self.log_types:
                    params = {
                        'event_type': log_type,
                        'range_from': query['range_from'],
                        'range_to': query['range_to'],
                        'limit': self.LOG_PAGE_LIMIT
                    }

                    uri = self.QUERY_LOG_URI + '?' + urlencode(params)
                    sub_status, sub_data = self._run("GET", uri)
                    print(sub_data)

                    if sub_status == 200:
                        result_logs.extend(sub_data['result'])
                        page_id = sub_data['params']['params']['record_range']['page_id']
                        total_pages = sub_data['params']['params']['record_range']['total_pages']
                        total_records = sub_data['params']['params']['record_range']['total_records']
                        print('There are total %d logs(total pages: %d)' % (total_records, total_pages))
                        print('%d/%d' % (page_id, total_pages))
                        while total_pages > page_id:
                            params['page'] = page_id + 1
                            uri = self.QUERY_LOG_URI + '?' + urlencode(params)
                            sub_status, sub_data = self._run("GET", uri)
                            result_logs.extend(sub_data['result'])
                            page_id = sub_data['params']['params']['record_range']['page_id']
                            total_pages = sub_data['params']['params']['record_range']['total_pages']
                            print('%d/%d' % (page_id, total_pages))
                        print("query_logs_realtime successfully.")
                    else:
                        err = True
                        print("query_logs_realtime return error.")
        return result_logs

    def test(self):

        since = datetime.now(timezone.utc) - timedelta(hours=1)
        to = datetime.now(timezone.utc)
        query = {'range_from': int(since.timestamp()), 'range_to': int(to.timestamp())}

        try:
            result = self.__execute_query(query)

            return {
                "status": True,
                "data": result
            }
        except Exception as e:
            logger.exception(f"[{__parser__}]:test: {e}", extra={'frontend': str(self.frontend)})
            return {
                "status": False,
                "error": str(e)
            }

    def execute(self):

        since = self.frontend.last_api_call or (datetime.now(timezone.utc) - timedelta(hours=1))
        to = datetime.now(timezone.utc)
        query = {'range_from': int(since.timestamp()), 'range_to': int(to.timestamp())}
        msg = f"Parser starting from {since} to {to}"
        logger.info(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})

        result = self.__execute_query(query)

        self.write_to_file(result)

        # Writting may take some while, so refresh token in Redis
        self.update_lock()

        self.frontend.last_api_call = to
        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})
