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
__author__ = "Julien Pollet"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'WAF CLOUD PROTECTOR API'
__parser__ = 'WAF CLOUD PROTECTOR'

from json import dumps as json_dumps
import logging
import time
import hmac
import hashlib
import urllib.parse
import base64
import gzip
from io import BytesIO, StringIO
import requests
import csv
from sys import maxsize as sys_maxsize

from datetime import datetime, timedelta
from django.utils import timezone
from django.conf import settings
from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')

class WAFCloudProtectorAPIError(Exception):
    pass

class WAFCloudProtectorParser(ApiParser):

    TO_SPLIT_FIELDS = ["description"]

    HEADERS = {
        "Content-Type": "application/json",
        'Accept': 'application/json'
    }

    def __init__(self, data):
        super().__init__(data)

        self.waf_cloud_protector_host = data["waf_cloud_protector_host"]
        self.waf_cloud_protector_api_key_pub = data["waf_cloud_protector_api_key_pub"]
        self.waf_cloud_protector_api_key_priv = data["waf_cloud_protector_api_key_priv"]
        self.waf_cloud_protector_provider = data["waf_cloud_protector_provider"]
        self.waf_cloud_protector_tenant = data["waf_cloud_protector_tenant"]
        self.waf_cloud_protector_servers = data["waf_cloud_protector_servers"]

        self.waf_cloud_protector_host = self.waf_cloud_protector_host.replace("https://", "").replace("http://", "")

        self.session = None

    def _connect(self):
        try:
            if self.session is None:
                self.session = requests.Session()

                headers = self.HEADERS
                self.session.headers.update(headers)

            return True

        except Exception as err:
            raise WAFCloudProtectorAPIError(err)

    def __execute_query(self, host_url, log_type, server, query=None, timeout=20):

        self._connect()

        query_encoded = urllib.parse.urlencode(query)
        url, headers = self.make_request(host_url, log_type, server, query_encoded)

        msg = "URL : " + url + " Query : " + str(query) + " Headers : " + str(headers) 
        logger.info(f"[{__parser__}] Request API : {msg}", extra={'frontend': str(self.frontend)})

        response = self.session.get(
            url,
            params=query,
            headers=headers,
            timeout=timeout,
            proxies=self.proxies,
            verify=False
        )

        # Get gzip file
        if response.status_code == 200:
            logger.info(f"[{__parser__}]:execute: API Request Successfull, gzip file downloaded", extra={'frontend': str(self.frontend)})
            return response.content

        # Epoch out of range
        if response.status_code == 401:
            if 'Epoch out of range' in response.text:
                logger.info(f"[{__parser__}]:execute: API Epoch out of range, waiting 1 seconds...", extra={'frontend': str(self.frontend)})
                time.sleep(1)
                return self.__execute_query(host_url=host_url, log_type=log_type, server=server, query=query, timeout=timeout)

        # Other error
        if response.status_code != 200:
            raise WAFCloudProtectorAPIError(
                f"Error at WAF CloudProtector API Call URL: {url} Code: {response.status_code} Content: {response.content}")

        return response.json()

    def make_request(self, host_url, log_type, server, query_encoded=""):

        uri = "/logs/"+ log_type + "/" + self.waf_cloud_protector_provider + "/" + self.waf_cloud_protector_tenant + '/' + server
        url = host_url + uri

        epoch = str(datetime.now().timestamp()).replace(".", "")[:-3]

        payload = 'GET' + '\n' \
        + self.waf_cloud_protector_host + '\n' \
        + '/latest' + uri + '\n' \
        + self.waf_cloud_protector_api_key_pub + '\n' \
        + epoch + '\n' \
        + query_encoded + '\n' \
        + ''
        signature_digest = hmac.new(
            key=self.waf_cloud_protector_api_key_priv.encode(),
            msg=payload.encode(),
            digestmod=hashlib.sha256
        ).digest() 
        signature = base64.b64encode(signature_digest).decode()
 
        headers = {
            "Accept": "application/json",
            "Host": self.waf_cloud_protector_host,
            "Authorization": f'DAAUTH apikey="{self.waf_cloud_protector_api_key_pub}", epoch="{epoch}", signature="{signature}"'    
        }
        return url, headers

    def test(self):

        current_time = timezone.now()
        try:
            logs = self.get_logs(since=(current_time - timedelta(hours=24)), nb_days=1, log_type="traffic", server=self.waf_cloud_protector_servers.split(',')[0])

            return {
                "status": True,
                "data": gzip.decompress(logs).decode("utf-8")
            }
        except Exception as e:
            logger.exception(f"{[__parser__]}:test: {str(e)}", extra={'frontend': str(self.frontend)})
            return {
                "status": False,
                "error": str(e)
            }

    def get_logs(self, since=None, nb_days=1, log_type="alert", server=None):

        host_url = "https://" + self.waf_cloud_protector_host + "/latest"

        query = {}
        query['limit'] = nb_days
        query['start_date'] = since.strftime("%Y-%m-%d")                

        return self.__execute_query(host_url, log_type, server, query)

    def parse_file(self, file_content):

        gzip_file = BytesIO(file_content)
        with gzip.GzipFile(fileobj=gzip_file, mode="rb") as gzip_file_content:
            return gzip_file_content.readlines()

    def parse_line(self, mapping, orig_line):

        result = {}
        # Convert line to BytesIO to use csv
        stream_line = StringIO(orig_line.decode('utf-8'))

        # Needed to prevent error : _csv.Error: field larger than field limit (131072)
        csv.field_size_limit(sys_maxsize)
        r = csv.reader(stream_line, delimiter=",", doublequote=True, lineterminator="\n", quoting=csv.QUOTE_ALL)
        # Loop other the fields of the only line
        try:
            for cpt, value in enumerate(list(r)[0]):
                field = mapping[cpt]
                if field in self.TO_SPLIT_FIELDS:
                    result[field] = {}
                    for under_field in value.split(' and '):
                        # Change the format of the field to be able to use it in the json 
                        # From -> "module_name == 'xxx' and event.desc == 'xxx ' and tokens['http_xxx'] == 'xxx'"
                        # To -> "module_name": "xxx", "event.desc": "xxx", "tokens.http_xxx": "xxx"
                        under_field_values = [under_field_value.replace("['", ".").replace("']", "").replace("'", "") for under_field_value in  under_field.split(' == ')]
                        if len(under_field_values) > 1:
                            # If the field is a key value pair, we add the value to the key
                            # It's for : "event.desc": "xxx", "tokens.http_xxx": "xxx"
                            if '.' in under_field_values[0]:
                                double_under_field_values = under_field_values[0].split('.')
                                if  double_under_field_values[0] not in result[field]:
                                    result[field][double_under_field_values[0]] = {}
                                result[field][double_under_field_values[0]][double_under_field_values[1]] = under_field_values[1]
                            # It's for : "module_name": "xxx"
                            else:
                                result[field][under_field_values[0]] = under_field_values[1]
                        # If the field is not a key value pair, we just add the value to the key                           
                        else:
                            result[field][under_field_values[0]] = under_field_values[0]
                else :
                    result[field] = value
            return json_dumps(result)
        except Exception as e:
            msg = f"Failed to parse line: {r}"
            logger.error(f"[{__parser__}]:parse_line: {msg}", extra={'frontend': str(self.frontend)})
            raise WAFCloudProtectorAPIError(msg)

    def execute(self):

        # Set datetime to take old logs, and new logs between a time scope
        since = self.frontend.last_api_call or (timezone.now() - timedelta(days=2))
        to = min(timezone.now(), since + timedelta(hours=24))
        delta = ((to - since) + timedelta(days=1)).days

        # Update last_api_call time to have ONE time for all servers
        self.frontend.last_api_call = to

        # Récup log
        for server in self.waf_cloud_protector_servers.split(','):            
            for log_type in ['alert', 'traffic']:
                try: 
                    file_content = self.get_logs(since, delta, log_type, server)
                    self.update_lock()
                    lines_byte = self.parse_file(file_content)
                    # Extract mapping in first line
                    ## Keys of json must be string, not bytes
                    ## Remove quotes and spaces in keys + split by comma
                    ## Remove '&' in keys, not valid for Rsyslog
                    mapping = [line.replace('"','').replace(' ','').replace('&','').replace('.','').replace('/','') for line in lines_byte.pop(0).decode('utf8').strip().split(',')]
                    
                    json_lines = []
                    # Start from the end, leave when the date is passed
                    for line in reversed(lines_byte):

                        # Get datetime to find logs in the time scope
                        date_log = ""
                        if log_type == 'alert':
                            date_log = datetime.strptime(line.decode().split(',')[1], '%Y-%m-%dT%H:%M:%S.%fZ')
                        elif log_type == 'traffic':
                            date_log = datetime.strptime(line.decode().split(',')[2], '%Y-%m-%dT%H:%M:%S.%fZ')

                        # Time scope : Between time of old "getlogs" (last execution) and time of first "getlogs" (current execution)
                        # It's to have one scope for all servers
                        last_api_call_without_tz = self.frontend.last_api_call.replace(tzinfo=None).replace(microsecond=0)
                        since_without_tz = since.replace(tzinfo=None).replace(microsecond=0)

                        if date_log < last_api_call_without_tz and date_log > since_without_tz:
                            # Use mapping to convert lines to json format 
                            json_lines.append(self.parse_line(mapping, line.strip()))
                        else:
                            # If the date is passed, we stop the loop, because the rest of lines are older
                            break

                    # Send those lines to Rsyslog
                    self.write_to_file(json_lines)
                    # And update lock after sending lines to Rsyslog
                    self.update_lock()

                except Exception as e:
                    msg = f"Failed to server {server} on log type {log_type}, between time of {since_without_tz} and {last_api_call_without_tz} : {e} "
                    logger.error(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})
                    logger.exception(f"[{__parser__}]:execute: {e}", extra={'frontend': str(self.frontend)})

        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})