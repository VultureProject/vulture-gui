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
__parser__ = 'CISCO MERAKI'


import json
import logging
import meraki

from datetime import timedelta
from django.conf import settings
from django.utils import timezone
from toolkit.api_parser.api_parser import ApiParser


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
            logger.info(f"{[__parser__]}:{self.test.__name__}: Getting organisation {orga['name']} networks", 
                        extra={'frontend': str(self.frontend)})
            # retreive organisation & networks
            data = self.get_organization_networks(orga['id'])
            return {
                "status": True,
                "data": data
            }
        except Exception as e:
            logger.exception(f"{[__parser__]}:{self.test.__name__}: {e}", extra={'frontend': str(self.frontend)})
            return {
                "status": False,
                "error": str(e)
            }

    def get_logs(self, network_id, product_type, since):
        self._connect()
        logger.debug(f"{[__parser__]}:{self.get_logs.__name__}: Get user events request params: startingAfter={since}", 
                     extra={'frontend': str(self.frontend)})
        try:
            response = self.session.networks.getNetworkEvents(network_id, productType=product_type,
                                                              startingAfter=since, perPage=1000)
        except Exception as e:
            return False, e

        return True, response

    def execute(self):

        for orga in self.get_organizations():

            logger.info(f"{[__parser__]}:{self.execute.__name__}: Getting organisation {orga['name']}", extra={'frontend': str(self.frontend)})
            for network in self.get_organization_networks(orga['id']):

                logger.info(f"{[__parser__]}:{self.execute.__name__}: Getting organisation network {network['name']}",
                            extra={'frontend': str(self.frontend)})
                for product_type in network['productTypes']:

                    logger.info(f"{[__parser__]}:{self.execute.__name__}: Getting organisation network {network['name']} "
                                f"product {product_type}",
                                extra={'frontend': str(self.frontend)})
                    nb_events = 1
                    while nb_events > 0:
                        status, tmp_logs = self.get_logs(network['id'],
                                                         product_type,
                                                         self.frontend.cisco_meraki_timestamp.get(f"{network['id']}_{product_type}") or \
                                                         (timezone.now()-timedelta(days=1)).isoformat())

                        if not status:
                            logger.error(f"{[__parser__]}:{self.execute.__name__}: "
                                         f"Orga {orga['name']}: "
                                         f"Network {network['name']}: "
                                         f"Error getting events : {tmp_logs}",
                                        extra={'frontend': str(self.frontend)})
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

        logger.info(f"{[__parser__]}:{self.execute.__name__}: Parser ending", extra={'frontend': str(self.frontend)})
