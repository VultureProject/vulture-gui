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
__doc__ = 'Cybereason API Parser'


import logging

from django.conf import settings
from elasticsearch import Elasticsearch, exceptions
from toolkit.api_parser.api_parser import ApiParser

from django.utils.translation import ugettext_lazy as _


logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('crontab')


class ElasticsearchParseError(Exception):
    pass


class ElasticsearchAPIError(Exception):
    pass


class ElasticsearchParser(ApiParser):
    def __init__(self, fontend):
        super().__init__()

        self.api_host = fontend['elasticsearch_host']
        self.username = fontend['elasticsearch_username']
        self.password = fontend['elasticsearch_password']

    @staticmethod
    def test(data):
        els_host = data.get('els_host').split(',')
        els_verify_ssl = data.get('els_verify_ssl') == "true"
        els_auth = data.get('els_auth') == "true"
        els_username = data.get('els_username')
        els_password = data.get('els_password')
        els_index = data.get('els_index')

        if els_auth and not (els_username and els_password):
            return {
                'status': False,
                'error': _('You need to fullfill username & password if authentication is enabled')
            }

        if not els_index:
            return {
                'status': False,
                'error': _('An index is mandatory')
            }

        try:
            if els_auth:
                els_client = Elasticsearch(
                    els_host,
                    http_auth=(els_username, els_password),
                    verify_certs=els_verify_ssl
                )
            else:
                els_client = Elasticsearch(
                    els_host,
                    verify_certs=els_verify_ssl
                )

            stats = els_client.indices.stats(index=els_index)

            return {
                'status': True,
                'stats': stats
            }

        except exceptions.TransportError as e:
            if e.status_code == 302:
                error = _("302 found on URL " + ",".join(els_host))
            else:
                error = str(e)

            return {
                'status': False,
                'error': error
            }

        except Exception as e:
            return {
                'status': False,
                'error': str(e)
            }

    def execute(self):
        pass
