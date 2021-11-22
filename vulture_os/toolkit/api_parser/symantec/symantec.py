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
__parser__ = 'SYMANTEC'

import datetime
import gzip
import logging
import requests
import time
import zipfile

from django.conf import settings
from django.utils import timezone
from io import BytesIO
from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class SymantecParseError(Exception):
    pass


class SymantecAPIError(Exception):
    pass


class SymantecParser(ApiParser):
    CHUNK_SIZE = 20000

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

            status = True
            if r.status_code != 200:
                status = False

            return {
                "status": status,
                "data": "Response : {}".format("OK" if status else r.status_code)
            }
        except SymantecAPIError as e:
            return {
                'status': False,
                'error': str(e)
            }

    def execute(self, token="none"):
        self.update_lock()

        last_api_call = self.last_api_call.replace(minute=0, second=0, microsecond=0)
        now = timezone.now().replace(minute=0, second=0, microsecond=0)
        if last_api_call > now - datetime.timedelta(hours=1):
            return

        # If we have less than one hour
        if (now - last_api_call).total_seconds() <= 60*60 and timezone.now().minute < 30:
            return

        try:
            last_api_call = self.last_api_call.replace(minute=0, second=0, microsecond=0)
            # Begin date is in milisecond
            begin_timestamp = int(last_api_call.timestamp() * 1000)
            # End date = start date + 1h (in milisecond)
            end_timestamp = int(last_api_call.timestamp() * 1000) + 3600000
            params = f"startDate={begin_timestamp}&endDate={end_timestamp}&token={token}"
            url = f"{self.start_console_uri}{params}"
            msg = f"Retrieving symantec logs from {url}"
            logger.debug(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})

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
                msg = f"Waiting for {retry}s"
                logger.debug(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})

                self.update_lock()
                time.sleep(retry)
                msg = f"Resuming API calls"
                logger.debug(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})

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
                        msg = f"No logs found"
                        logger.debug(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})
                        self.frontend.last_api_call = timezone.now()
                        self.finish()
                    else:
                        try:
                            gzip_file = BytesIO()
                            data = []
                            with zipfile.ZipFile(tmp_file) as zip_file:
                                # Pnly retrieve the DIRST
                                gzip_filename = zip_file.namelist()[0]
                                msg = f"Parsing archive {gzip_filename}"
                                logger.debug(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})
                                self.update_lock()
                                gzip_file = BytesIO(zip_file.read(gzip_filename))

                            with gzip.GzipFile(fileobj=gzip_file, mode="rb") as gzip_file_content:
                                i = 0
                                line = gzip_file_content.readline()
                                while line:
                                    i += 1
                                    line = line.strip()
                                    if not line[0] == "#":
                                        data.append(b"<15>"+line)
                                    
                                    if i > self.CHUNK_SIZE:
                                        self.write_to_file(data)
                                        self.update_lock()
                                        data = []
                                        i = 0

                                    line = gzip_file_content.readline()

                                self.write_to_file(data)

                                try:
                                    self.last_api_call = datetime.datetime.strptime(gzip_filename.split("_")[2].split(".")[0], "%Y%m%d%H%M%S")+datetime.timedelta(hours=1)
                                except:
                                    self.last_api_call += datetime.timedelta(hours=1)

                                self.frontend.last_api_call = self.last_api_call
                                self.frontend.save()
                            self.finish()

                        except zipfile.BadZipfile as err:
                            raise SymantecParseError(err)

                else:
                    msg = f"No filename found in headers {r.headers}"
                    logger.info(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})

        except Exception as e:
            raise SymantecParseError(e)
