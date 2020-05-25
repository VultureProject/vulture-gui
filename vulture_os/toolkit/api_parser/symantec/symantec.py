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
__doc__ = 'Symantec API Parser'

import datetime
import gzip
import logging
import requests
import time

import zipfile

from io import BytesIO

from django.conf import settings
from django.utils import timezone
from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('crontab')


class SymantecParseError(Exception):
    pass


class SymantecAPIError(Exception):
    pass


class SymantecParser(ApiParser):
    def __init__(self, data):
        super().__init__(data)

        self.start_console_uri = "https://portal.threatpulse.com/reportpod/logs/sync?"
        self.username = data['symantec_username']
        self.password = data['symantec_password']

        self.HEADERS = {
            "X-APIUsername": self.username,
            "X-APIPassword": self.password
        }

    def test(self):
        try:
            startDate = timezone.now()
            startDate = startDate.replace(minute=0, second=0, microsecond=0)
            startDate = startDate.timestamp() * 1000

            url = f"{self.start_console_uri}startDate={int(startDate)}&endDate=0&token=none"

            r = requests.get(
                url,
                headers=self.HEADERS,
                proxies=self.proxies,
                allow_redirects=False,
                timeout=10,
                stream=True
            )

            if "Retry-After" in r.headers.keys():
                return {
                    "status": False,
                    "error": r.content.decode('UTF-8')
                }

            return {
                "status": True,
                "data": "Response OK"
            }
        except SymantecAPIError as e:
            return {
                'status': False,
                'error': str(e)
            }

    def execute(self, token="none"):
        self.update_lock()

        # If it is time to retrieve last hour of logs
        if self.last_api_call.replace(minute=0, second=0, microsecond=0) > timezone.now().replace(minute=0, second=0, microsecond=0)-datetime.timedelta(hours=1):
            return

        try:
            last_api_call = self.last_api_call.replace(minute=0, second=0, microsecond=0)
            timestamp = int(last_api_call.timestamp() * 1000)
            params = f"startDate={timestamp}&endDate=0&token={token}"
            url = f"{self.start_console_uri}{params}"

            logger.debug("[SYMANTEC API PARSER] Retrieving symantec logs from api")

            r = requests.get(
                url,
                headers=self.HEADERS,
                proxies=self.proxies,
                allow_redirects=False,
                stream=True,
                timeout=60
            )

            try:
                r.raise_for_status()
            except Exception as err:
                raise SymantecAPIError(err)

            if r.headers.get('Retry-After'):
                retry = int(r.headers['Retry-After']) + 2
                if retry > 300:
                    raise SymantecAPIError(f"Retry After {r.headers['Retry-After']}")

                logger.debug(f"[SYMANTEC API PARSER] Waiting for {retry}s")

                self.update_lock()
                time.sleep(retry)
                logger.debug('[SYMANTEC API PARSER] Resuming API calls')

                self.execute()
            else:
                if "filename" in r.headers['Content-Disposition']:
                    tmp_file = BytesIO()
                    for chunk in r.iter_content(chunk_size=8192):
                        if chunk:
                            self.update_lock()
                            tmp_file.write(chunk)

                    tmp_file.seek(0)
                    if not len(tmp_file.read()):
                        logger.info('[SYMANTEC API PARSER] No logs found')
                        self.frontend.last_api_call = timezone.now()
                        self.finish()
                    else:
                        try:
                            data = []
                            with zipfile.ZipFile(tmp_file) as zip_file:
                                for gzip_filename in zip_file.namelist():
                                    self.update_lock()
                                    gzip_file = BytesIO(zip_file.read(gzip_filename))

                                    with gzip.GzipFile(fileobj=gzip_file, mode="rb") as gzip_file_content:
                                        for line in gzip_file_content.readlines():
                                            line = line.strip()
                                            if not line[0] == "#":
                                                data.append(line)

                            self.write_to_file(data, bytes_mode=True)
                            self.frontend.last_api_call = timezone.now()
                            self.finish()
                        except zipfile.BadZipfile as err:
                            raise SymantecParseError(err)

                else:
                    logger.info(f'[SYMANTEC API PARSER] No filename found in headers {r.headers}')

        except Exception as e:
            raise SymantecParseError(e)
