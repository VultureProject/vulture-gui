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
__doc__ = 'Forcepoint Console API Parser'
__parser__ = 'FORCEPOINT'


import csv
from sys import maxsize as sys_maxsize
import gzip
import logging
import requests
import defusedxml.ElementTree as ET

from django.conf import settings
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from io import BytesIO, StringIO
from json import dumps as json_dumps
from toolkit.api_parser.api_parser import ApiParser


logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')

MAX_DELETE_ATTEMPTS = 3


class ForcepointParseError(Exception):
    pass


class ForcepointAPIError(Exception):
    pass


class ForcepointParser(ApiParser):
    FORCEPOINT_API_VERSION = '1.3.1'

    CSV_KEYS = [
        "dt_date", "dt_time", "http_uri", "af_action", "af_category", "af_direction", "af_group",
        "af_category", "af_policy", "af_risk", "af_search_term", "user_name", "net_src_workstation",
        "http_filtering_source", "http_status", "net_dst_port", "http_method", "http_tls_version",
        "http_auth_method", "af_threat_category", "net_data_center", "http_user_agent_type",
        "http_user_agent", "http_user_agent_br_type", "http_user_agent_br", "http_referer_path",
        "http_referer_port", "http_referer_query", "http_referer_url", "http_referer_full",
        "http_referer_domain", "http_referer_host", "af_threat_file", "af_threat_filetype",
        "af_threat_fullfilemimetype", "af_threat_filemimesubtype", "af_threat_filemimetype",
        "af_threat_type", "af_analytic_name", "src_ip", "net_dst_country", "src_ip", "net_src_city",
        "af_cloud_app_risk_level", "af_cloud_app", "af_could_app_category", "dst_ip", "net_name",
        "net_src_country", "af_domain", "af_subdomain", "af_topdomain", "http_host", "http_path",
        "http_request_uri", "http_query", "http_proto"
    ]
    TO_SPLIT_FIELDS = ["EmbDomain", "EmbFullURL", "EmbHost"]

    def __init__(self, data):
        super().__init__(data)

        self.forcepoint_host = data["forcepoint_host"]
        self.forcepoint_username = data["forcepoint_username"]
        self.forcepoint_password = data["forcepoint_password"]

        self.user_agent = {
            'User-agent': f'FTL_Download/{self.FORCEPOINT_API_VERSION}'
        }

    def test(self):
        try:
            url = f"{self.forcepoint_host}/siem/logs"
            self.get_logs(url)
            return {
                "status": True,
                "data": _('Success')
            }
        except ForcepointAPIError as e:
            return {
                "status": False,
                "error": str(e)
            }

    def get_logs(self, url, allow_redirects=False):
        logger.info(f"[{__parser__}]:get_logs: URL: {url}", extra={'frontend': str(self.frontend)})
        try:
            response = requests.get(
                url,
                auth=(self.forcepoint_username, self.forcepoint_password),
                allow_redirects=allow_redirects,
                headers=self.user_agent,
                proxies=self.proxies,
                timeout=30,
                verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl
            )

            response.raise_for_status()
        except Exception as e:
            error = f"Error at Forcepoint API Call: {e}"
            logger.error(f"[{__parser__}]:get_logs: {error}", extra={'frontend': str(self.frontend)})
            raise ForcepointAPIError(error)
        else:
            return response.content

    def parse_xml(self, logs):
        for child in ET.fromstring(logs):
            url = child.attrib['url']
            stream = child.attrib['stream']
            yield url, stream

    def parse_line(self, mapping_keys, orig_line, stream):
        res = {}
        # Convert line to BytesIO to use csv
        stream_line = StringIO(orig_line.decode('utf-8'))
        # Needed to prevent error : _csv.Error: field larger than field limit (131072)
        csv.field_size_limit(sys_maxsize)
        r = csv.reader(stream_line, delimiter=",", doublequote=True, lineterminator="\n", quoting=csv.QUOTE_ALL)
        # Loop other the fields of the only line
        try:
            for cpt, value in enumerate(list(r)[0]):
                field = mapping_keys[cpt]
                res[field] = value.split(',') if field in self.TO_SPLIT_FIELDS else value
            res['stream'] = stream
            return json_dumps(res)
        except Exception as e:
            msg = f"Failed to parse line: {r} -> Error: {e}"
            logger.error(f"[{__parser__}]:parse_line: {msg}", extra={'frontend': str(self.frontend)})
            raise ForcepointAPIError()

    def parse_file(self, file_content, gzipped=False):
        if gzipped:
            gzip_file = BytesIO(file_content)

            with gzip.GzipFile(fileobj=gzip_file, mode="rb") as gzip_file_content:
                return gzip_file_content.readlines()
        else:
            return file_content.split(b"\r\n")

    def delete_file(self, file_url):
        attempt = 0
        while attempt < MAX_DELETE_ATTEMPTS:
            try:
                response = requests.delete(
                    file_url,
                    auth=(self.forcepoint_username, self.forcepoint_password),
                    headers=self.user_agent,
                    proxies=self.proxies,
                    timeout=30,
                    verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl
                )

                response.raise_for_status()
                break
            except Exception as e:
                msg = f"Failed to delete file {file_url} : {e}"
                logger.error(f"[{__parser__}]:delete_file: {msg}", extra={'frontend': str(self.frontend)})
                attempt += 1

    @staticmethod
    def format_log(line):
        chars_to_delete = ['"', ' ', '&', '.', '/']
        line = "".join(c for c in line if c not in chars_to_delete)
        return line

    def execute(self):
        url = f"{self.forcepoint_host}/siem/logs"
        tmp_logs = self.get_logs(url)
        self.update_lock()

        for file_url, file_type in self.parse_xml(tmp_logs):
            try:
                # Parse file depending on extension
                file_content = self.get_logs(file_url)
                lines = self.parse_file(file_content, file_url[-3:] == ".gz")

                self.update_lock()

                # Extract mapping in first line
                ## Keys of json must be string, not bytes
                ## Remove quotes and spaces in keys + split by comma
                ## Remove '&' in keys, not valid for Rsyslog
                mapping_keys = [self.format_log(line) for line in lines.pop(0).decode('utf8').strip().split(',')]
                # Use mapping to convert lines to json format
                json_lines = [self.parse_line(mapping_keys, line.strip(), file_type) for line in lines]

                # Send those lines to Rsyslog
                self.write_to_file(json_lines)

                # And update lock after sending lines to Rsyslog
                self.update_lock()
                # When logs are sent to Rsyslog, delete file on external host
                self.delete_file(file_url)
                # And update last_api_call time
                self.frontend.last_api_call = timezone.now()
                self.frontend.save(update_fields=["last_api_call"])
            except Exception as e:
                msg = f"Failed to retrieve file {file_url} : {e}"
                logger.error(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})
                logger.exception(f"[{__parser__}]:execute: {e}", extra={'frontend': str(self.frontend)})

        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})
