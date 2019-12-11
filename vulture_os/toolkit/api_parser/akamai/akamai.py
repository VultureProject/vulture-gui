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
import logging
import requests

from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('crontab')


class AkamaiParseError(Exception):
    pass


class AkamaiAPIError(Exception):
    pass


class AkamaiParser(ApiParser):
    def __init__(self, data):
        super().__init__(data)

    def test(self):
        try:
            pass
        except AkamaiAPIError as e:
            return {
                'status': False,
                'error': str(e)
            }

    def execute(self):
        try:
            pass
        except Exception as e:
            raise AkamaiParseError(e)
