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
import re

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
        self.token = data.get('symantec_token', 'none')

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

            if "Retry-After" in r.headers.keys() or r.status_code != 200:
                return {
                    "status": False,
                    "error": r.content.decode('UTF-8')
                }
            else:
                return {
                    "status": True,
                    "data": "Response : OK"
                }
        except SymantecAPIError as e:
            logger.exception(f"[{__parser__}]:execute: {e}", extra={'frontend': str(self.frontend)})
            return {
                'status': False,
                'error': str(e)
            }

    def execute(self):
        self.update_lock()

        try:
            # If token is defined AND not older than 24h
            # Otherwise token seems to be too old
            if self.token != "none" and not (self.last_api_call < timezone.now()-datetime.timedelta(hours=24)):
                begin_timestamp = 0
                end_timestamp = 0
                msg = f"Get logs from startDate 0 to 0 with token {self.token}"
            else:
                last_api_call = self.last_api_call.replace(minute=0, second=0, microsecond=0)
                # Begin date is in milisecond
                begin_timestamp = int(last_api_call.timestamp() * 1000)
                # End date = start date + 1h (in milisecond)
                end_time = last_api_call + datetime.timedelta(hours=1)
                # If end_time > now, API returned 400
                if end_time > timezone.now():
                    end_timestamp = 0
                    msg = f"Get logs from startDate {last_api_call} to now"
                else:
                    end_timestamp = int(last_api_call.timestamp() * 1000) + 3600000
                    msg = f"Get logs from startDate {last_api_call} to {end_time}"

            logger.info(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})

            params = f"startDate={begin_timestamp}&endDate={end_timestamp}&token={self.token}"
            url = f"{self.start_console_uri}{params}"
            msg = f"Retrieving symantec logs from {url}..."
            logger.info(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})

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
                retry = int(r.headers['Retry-After'])
                msg = f"Parser must retry after waiting for {retry}s"
                logger.info(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})

            else:
                if "filename" in r.headers['Content-Disposition']:
                    logger.info(f"[{__parser__}]:execute filenames: {r.headers['Content-Disposition']}",
                                extra={'frontend': str(self.frontend)})

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
                            tmp_file.seek(-150, 2)
                            logger.info(f"[{__parser__}]:execute Search new token", extra={'frontend': str(self.frontend)})
                            new_token = re.search("X-sync-token: (?P<token>.+)'", str(tmp_file.readline().strip()))
                            symantec_token = new_token.group('token') if new_token else "none"

                            msg = f"New token is: {symantec_token}"
                            logger.info(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})
                            if symantec_token == "none":
                                raise Exception("Cannot find token in archive tail, aborting.")
                            else:
                                self.frontend.symantec_token = symantec_token
                            data = []
                            with zipfile.ZipFile(tmp_file) as zip_file:
                                for gzip_filename in zip_file.namelist():
                                    msg = f"Parsing archive {gzip_filename}"
                                    logger.info(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})
                                    self.update_lock()

                                    with gzip.GzipFile(fileobj=BytesIO(zip_file.read(gzip_filename)), mode="rb") as gzip_file_content:
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
                                            logger.error(f"[{__parser__}]:execute: Fail to parse {gzip_filename} to set last_api_call, "
                                                         f"setting it to {self.last_api_call}",
                                                         extra={'frontend': str(self.frontend)})

                                        self.frontend.last_api_call = self.last_api_call
                                        self.frontend.save()
                            self.finish()

                        except zipfile.BadZipfile as err:
                            raise SymantecParseError(err)
                        except Exception as e:
                            logger.exception(f"[{__parser__}]:Unknown exception {e}", extra={'frontend': str(self.frontend)})



                else:
                    msg = f"No filename found in headers {r.headers}"
                    logger.info(f"[{__parser__}]:execute: {msg}", extra={'frontend': str(self.frontend)})

        except Exception as e:
            raise SymantecParseError(e)
