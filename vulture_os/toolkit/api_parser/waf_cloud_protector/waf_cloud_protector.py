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

    def __execute_query(self, host_url, log_type, server, query=None, timeout=20, count=0):

        self._connect()

        query_encoded = urllib.parse.urlencode(query)
        url, headers = self.make_request(host_url, log_type, server, query_encoded)

        msg = "URL : " + url + " Query : " + str(query)
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
                if count < 5:
                    logger.info(f"[{__parser__}]:execute: API Epoch out of range, waiting 0.1 seconds...", extra={'frontend': str(self.frontend)})
                    time.sleep(0.1)
                    return self.__execute_query(host_url=host_url, log_type=log_type, server=server, query=query, timeout=timeout, count=count+1)
                else:
                    raise WAFCloudProtectorAPIError(
                        f"API Epoch out of range, too many retries, API Call URL: {url} Code: {response.status_code} Content: {response.content}")

        # Other error
        if response.status_code != 200:
            raise WAFCloudProtectorAPIError(
                f"Error at WAF CloudProtector API Call URL: {url} Code: {response.status_code} Content: {response.content}")

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

    def read_reversed_lines(self, buffer, cursor_first_line):
        """Take a csv file in bytes, read and yield line by line in reverse order without take the first line of csv file, the lines are not sorted"""
        # Go to the end of the file
        buffer.seek(0, 2)
        line = ""
        cursor = 0
        # ASSUMING THAT A LINE CANNOT BE LARGER THAN 2000bytes !!!
        cpt = 2000
        while buffer.tell()-(len(line) + 2 + (cpt-2)) > 0:

            buffer.seek(-(len(line) + 2 + (cpt-2)), 1)
            # Read 2000 bytes minus last 2 bytes \r\n
            tmp = buffer.read(cpt-2)
            # Search for last \r\n (beginning of last line in tmp)
            cursor = tmp.rfind("\r\n".encode('utf-8')) + 2
            line = tmp[cursor:]
            yield line

        # Cursor equals 0 when the file is smaller than 2000 bytes
        if cursor != 0:

            # Skip the first line
            buffer.seek(cursor_first_line, 0)
            buffer_end = cursor - (len(line) + 2 + cursor_first_line)               
            tmp = buffer.read(buffer_end)

            # Yield from the last line to the first line
            for line in reversed(tmp.split("\r\n".encode('utf-8'))):
                yield line


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

        # Init the dict of timestamps if not exist
        if self.frontend.waf_cloud_protector_timestamps.get('alert') is None:
            self.frontend.waf_cloud_protector_timestamps = { 'alert': {}, 'traffic': {} }
            self.frontend.save()

        for server in self.waf_cloud_protector_servers.split(','):

            # Init the timestamp for the server if not exist
            if server not in self.frontend.waf_cloud_protector_timestamps.get('alert'):                
                self.frontend.waf_cloud_protector_timestamps['alert'][server] = ""
                self.frontend.waf_cloud_protector_timestamps['traffic'][server] = ""                
                self.frontend.save()

            for log_type in ['alert', 'traffic']:
                try:
                    
                    ## GET LOGS ##
                    since = self.frontend.waf_cloud_protector_timestamps[log_type].get(f"{server}") or (timezone.now() - timedelta(days=2))
                    to = min(timezone.now(), since + timedelta(hours=24))
                    delta = ((to - since) + timedelta(days=1)).days

                    file_content = self.get_logs(since, delta, log_type, server)
                    self.update_lock()
                    
                    ## DECOMPRESS LOGS ##
                    gzip_file = BytesIO(file_content)
                    buffer_file = gzip.GzipFile(fileobj=gzip_file, mode="rb")

                    ## GET MAPPING : The first line ##
                    first_line = buffer_file.readline()
                    cursor_first_line = buffer_file.tell()
                    mapping = [column.replace('"','').replace(' ','').replace('&','').replace('.','').replace('/','') for column in first_line.decode('utf8').strip().split(',')]

                    json_lines = []
                    
                    since_without_tz = since.replace(tzinfo=None).replace(microsecond=0)
                    to_without_tz = to.replace(tzinfo=None).replace(microsecond=0)

                    ## FOR EACH LINE : start from the end ##
                    for line_byte in self.read_reversed_lines(buffer_file, cursor_first_line):
                        
                        line = line_byte.decode('utf8')

                        # Choose the right column to take the date
                        date_log = ""
                        if log_type == 'alert':
                            date_log = datetime.strptime(line.split(',')[1], '%Y-%m-%dT%H:%M:%S.%fZ')
                        else:
                            date_log = datetime.strptime(line.split(',')[2], '%Y-%m-%dT%H:%M:%S.%fZ')

                        # The line of log is too yound for our request
                        if date_log > to_without_tz:
                            continue
                        
                        # The line of log is too old for our request, and it's same for the rest of the file
                        if date_log < since_without_tz:
                            break

                        # Use mapping to convert lines to json format 
                        json_lines.append(self.parse_line(mapping, line.strip().encode('utf8')))

                    # Send those lines to Rsyslog
                    self.write_to_file(json_lines)
                    # And update lock after sending lines to Rsyslog
                    self.update_lock()
                    self.frontend.waf_cloud_protector_timestamps[log_type][server] = to
                    self.frontend.save()

                except Exception as e:
                    msg = f"Failed to server {server} on log type {log_type}, between time of {since} and {to} : {e} "
                    logger.error(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})
                    logger.exception(f"[{__parser__}]:execute: {e}", extra={'frontend': str(self.frontend)})

        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})