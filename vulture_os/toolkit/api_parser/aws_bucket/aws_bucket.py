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
__doc__ = 'Cisco Umbrella API Parser'


import boto3
import logging

from botocore.config import Config
from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from toolkit.api_parser.api_parser import ApiParser


logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class AWSBucketBucketEmpty(Exception):
    pass


class AWSBucketConnectError(Exception):
    pass


class AWSBucketParseError(Exception):
    pass


class AWSBucketAPIError(Exception):
    pass


class AWSBucketParser(ApiParser):
    def __init__(self, data):
        super().__init__(data)

        self.aws_access_key_id = data.get('aws_access_key_id')
        self.aws_secret_access_key = data.get('aws_secret_access_key')
        self.aws_bucket_name = data.get('aws_bucket_name')

    def __connect(self):
        try:
            self.s3_client = boto3.client(
                's3',
                aws_access_key_id=self.aws_access_key_id,
                aws_secret_access_key=self.aws_secret_access_key,
                config=Config(proxies=self.proxies)
            )

        except Exception as e:
            raise AWSBucketConnectError("Authentencation failed: {}".format(e))

    def test(self):
        try:
            self.__connect()

            files = []
            try:
                for file in self._fetch_files():
                    files.append(file['Key'])
            except AWSBucketBucketEmpty:
                files = "No files in this bucket"

            return {
                'status': True,
                'data': files
            }

        except Exception as e:
            return {
                'status': False,
                'error': str(e)
            }

    def fetch_data(self):
        try:
            self.__connect()

            buckets = []
            for bucket in self.s3_client.list_buckets()['Buckets']:
                buckets.append(bucket['Name'])

            if not len(buckets):
                return {
                    'status': False,
                    'error': _('No buckets available')
                }

            return {
                'status': True,
                'data': buckets
            }
        except (AWSBucketAPIError, AWSBucketConnectError) as e:
            return {
                'status': False,
                'error': str(e)
            }

    def _fetch_files(self):
        try:
            for file in self.s3_client.list_objects(Bucket=self.aws_bucket_name)['Contents']:
                yield file

        except KeyError:
            raise AWSBucketBucketEmpty(f"Bucket {self.aws_bucket_name} is empty")

    def _download_file(self, filename):
        file_object = self.s3_client.get_object(Bucket=self.aws_bucket_name, Key=filename)
        return file_object['Body'].read()

    def execute(self):
        try:
            self.__connect()

            for filename in self._fetch_files():
                self.update_lock()
                file_data = self._download_file(filename)
                print(file_data)

        except AWSBucketBucketEmpty:
            pass

        except Exception as e:
            raise AWSBucketParseError(e)
