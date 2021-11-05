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
__doc__ = 'Elasticsearch API Parser'


import logging
import datetime

from django.conf import settings
from elasticsearch import Elasticsearch
from elasticsearch import exceptions
from toolkit.api_parser.api_parser import ApiParser

from django.utils.translation import ugettext_lazy as _


logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class ElasticsearchParseError(Exception):
    pass


class ElasticsearchAPIError(Exception):
    pass


class ElasticsearchParser(ApiParser):
    def __init__(self, data):
        super().__init__(data)

        self.els_host = data['elasticsearch_host']
        self.els_username = data['elasticsearch_username']
        self.els_password = data['elasticsearch_password']
        self.els_verify_ssl = data['elasticsearch_verify_ssl']
        self.els_auth = data['elasticsearch_auth']
        self.els_index = data['elasticsearch_index']

    def connect(self):
        if self.els_auth:
            return Elasticsearch(
                self.els_host,
                http_auth=(self.username, self.password),
                verify_certs=self.els_verify_ssl,
                proxies=self.proxies
            )

        return Elasticsearch(
            self.els_host,
            verify_certs=self.els_verify_ssl,
            proxies=self.proxies
        )

    def test(self):
        if self.els_auth and not (self.els_username and self.els_password):
            return {
                'status': False,
                'error': _('You need to fullfill username & password if authentication is enabled')
            }

        if not self.els_index:
            return {
                'status': False,
                'error': _('An index is mandatory')
            }

        try:
            els_client = self.connect()
            stats = els_client.indices.stats(index=self.els_index)

            return {
                'status': True,
                'data': stats
            }

        except exceptions.TransportError as e:
            if e.status_code == 302:
                error = _("302 found on URL " + self.els_host)
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

    def __parse_json(self, data):
        for d in data:
            log_line = d['_source']
            self.last_api_call = log_line['@timestamp']

    def construct_query(self):
        query = {
            "query": {
                "match_all": {}
            }
        }

        if not self.last_api_call:
            self.last_api_call = datetime.datetime.now()

        query = {
            "query": {
                "bool": {
                    "must": {
                        "range": {
                            "@timestamp": {
                                "gt": self.last_api_call,
                            }
                        }
                    }
                }
            }
        }

        query["sort"] = {
            "@timestamp": {
                "order": "asc"
            }
        }

        return query

    def execute(self):
        if not self.can_run():
            return

        try:
            els_client = self.connect()

            data = els_client.search(
                index=self.els_index,
                scroll="2m",
                size=1000,
                body=self.construct_query()
            )

            sid = data['_scroll_id']
            scroll_size = len(data['hits']['hits'])

            self.__parse_json(data['hits']['hits'])

            while scroll_size > 0:
                self.update_lock()
                data = els_client.scroll(scroll_id=sid, scroll="2m")
                self.__parse_json(data['hits']['hits'])

                sid = data['_scroll_id']
                scroll_size = len(data['hits']['hits'])

            self.frontend.last_api_call = self.last_api_call
            self.finish()

        except Exception as e:
            logger.critical(e, exc_info=1, extra={'tenant': self.tenant_name})
