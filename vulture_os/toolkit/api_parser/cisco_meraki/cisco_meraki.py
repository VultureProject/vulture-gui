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
__author__ = "Kevin Guillemot"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Cisco Meraki API Parser'


import logging
import requests

from django.conf import settings
from toolkit.api_parser.api_parser import ApiParser
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _

from datetime import datetime, timedelta
import json
import meraki

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')



class CiscoMerakiAPIError(Exception):
    pass


class CiscoMerakiParser(ApiParser):

    def __init__(self, data):
        super().__init__(data)

        self.cisco_meraki_apikey = data["cisco_meraki_apikey"]

        self.session = None

    def _connect(self):
        try:
            if self.session is None:

                kwargs = {'output_log':False}
                if self.proxies is not None:
                    kwargs['requests_proxy'] = self.proxies['https']

                self.session = meraki.DashboardAPI(self.cisco_meraki_apikey, **kwargs)

            return True

        except Exception as err:
            raise CiscoMerakiAPIError(err)

    def get_organizations(self):
        self._connect()
        try:
            return self.session.organizations.getOrganizations()
        except Exception as e:
            raise CiscoMerakiAPIError(e)

    def get_organization_networks(self, orga_id):
        self._connect()
        try:
            return self.session.organizations.getOrganizationNetworks(orga_id)
        except Exception as e:
            raise CiscoMerakiAPIError(e)


    def test(self):
        try:
            orga = self.get_organizations()[0]
            logger.info("CiscoMeraki:: Getting organisation {} networks".format(orga['name']),
                        extra={'frontend': self.frontend.name})
            data = self.get_organization_networks(orga['id'])

            # If we successfully retrieved organizations & networks, it's ok

            return {
                "status": True,
                "data": data
            }
        except Exception as e:
            logger.exception(e, extra={'frontend': self.frontend.name})
            return {
                "status": False,
                "error": str(e)
            }

    def get_logs(self, network_id, product_type, since):
        self._connect()

        logger.debug("CiscoMeraki api::Get user events request params: startingAfter={}".format(since),
                     extra={'frontend': self.frontend.name})

        try:
            response = self.session.networks.getNetworkEvents(network_id,
                                                              productType=product_type,
                                                              startingAfter=since,
                                                              perPage=1000)

        except Exception as e:
            return False, e

        return True, response

    def execute(self):

        for orga in self.get_organizations():

            logger.info("CiscoMeraki:: Getting organisation {}".format(orga['name']),
                        extra={'frontend': self.frontend.name})

            for network in self.get_organization_networks(orga['id']):

                logger.info("CiscoMeraki:: Getting organisation network {}".format(network['name']),
                            extra={'frontend': self.frontend.name})

                for product_type in network['productTypes']:

                    logger.info("CiscoMeraki:: Getting organisation network {} product {}".format(network['name'], product_type),
                                extra={'frontend': self.frontend.name})

                    nb_events = 1
                    while nb_events > 0:
                        status, tmp_logs = self.get_logs(network['id'],
                                                         product_type,
                                                         self.frontend.cisco_meraki_timestamp.get(f"{network['id']}_{product_type}") or \
                                                         (timezone.now()-timedelta(days=1)).isoformat())

                        if not status:
                            logger.error(f"CiscoMeraki::Orga {orga['name']}:Network {network['name']}: Error getting events : {tmp_logs}",
                                         extra={'frontend': self.frontend.name})
                            break

                        # Parsing 1k lines may take some while, so refresh token in Redis before
                        self.update_lock()

                        nb_events = len(tmp_logs['events'])
                        logs = tmp_logs['events']

                        def format_log(log):
                            log['organization_id'] = orga['id']
                            log['organization_name'] = orga['name']
                            log['network'] = network['name']
                            log['product'] = product_type
                            log['timestamp'] = log['occurredAt']
                            return json.dumps(log)

                        self.write_to_file([format_log(l) for l in logs])
                        # Writting may take some while, so refresh token in Redis
                        self.update_lock()

                        if nb_events > 0:
                            # No need to make_aware, date already contains timezone
                            self.frontend.cisco_meraki_timestamp[f"{network['id']}_{product_type}"] = tmp_logs['pageEndAt']

        logger.info("CiscoMeraki parser ending.", extra={'frontend': self.frontend.name})
