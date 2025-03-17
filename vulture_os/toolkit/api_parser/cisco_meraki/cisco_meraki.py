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
        self.cisco_meraki_get_security_logs = bool(data.get("cisco_meraki_get_security_logs"))

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

    def get_organization_appliance_security_events(self, since, orga_id):
        self._connect()
        try:
            return self.session.appliance.getOrganizationApplianceSecurityEvents(orga_id, t0=since,
                                                                                 perPage=1000, total_pages='all')
        except Exception as e:
            raise CiscoMerakiAPIError(e)

    def test(self):
        try:
            orga = self.get_organizations()[0]
            logger.info(f"[{__parser__}]:test: Getting organisation {orga['name']} networks",
                        extra={'frontend': str(self.frontend)})
            # retreive organisation & networks
            data = self.get_organization_networks(orga['id'])

            if self.cisco_meraki_get_security_logs:
                since = (timezone.now()-timedelta(days=1)).isoformat()
                data.extend(self.get_organization_appliance_security_events(since, orga['id']))
            return {
                "status": True,
                "data": data
            }
        except Exception as e:
            logger.exception(f"[{__parser__}]:test: {e}", extra={'frontend': str(self.frontend)})
            return {
                "status": False,
                "error": str(e)
            }

    def get_logs(self, network_id, product_type, since):
        self._connect()
        logger.info(f"[{__parser__}]:get_logs: Get user events for network ID {network_id}, product type {product_type}, starting after {since}",
            extra={'frontend': str(self.frontend)})
        try:
            response = self.session.networks.getNetworkEvents(network_id, productType=product_type,
                                                              startingAfter=since, perPage=1000)
        except Exception as e:
            return False, e

        return True, response

    def execute(self):

        for orga in self.get_organizations():
            if self.evt_stop.is_set():
                break

            logger.info(f"[{__parser__}]:execute: Getting organisation {orga['name']}", extra={'frontend': str(self.frontend)})
            for network in self.get_organization_networks(orga['id']):
                if self.evt_stop.is_set():
                    break

                logger.info(f"[{__parser__}]:execute: Getting organisation network {network['name']}",
                            extra={'frontend': str(self.frontend)})
                for product_type in network['productTypes']:
                    if self.evt_stop.is_set():
                        break

                    since = self.frontend.cisco_meraki_timestamp.get(f"{network['id']}_{product_type}",
                                                                     (timezone.now()-timedelta(days=1)).isoformat())
                    logger.info(f"[{__parser__}]:execute: Getting organisation network {network['name']} "
                                f"product {product_type}, from {since}",
                                extra={'frontend': str(self.frontend)})
                    nb_events = 1
                    total_nb_events = 0
                    while nb_events > 0 and not self.evt_stop.is_set():
                        status, tmp_logs = self.get_logs(network['id'],
                                                         product_type,
                                                         since)

                        if not status:
                            # API bug handling
                            ## Sometimes, "productType" cannot be "xxxxx", & must be set to one of [xxxx]
                            ## Yet, productTypes is returned by the API itself
                            if "must be set to one of" in str(tmp_logs):
                                logger.warning(f"[{__parser__}]:execute: "
                                         f"Orga {orga['name']}: "
                                         f"Network {network['name']}: "
                                         f"Cannot retrieve events : {tmp_logs}",
                                        extra={'frontend': str(self.frontend)})
                            else:
                                logger.error(f"[{__parser__}]:execute: "
                                         f"Orga {orga['name']}: "
                                         f"Network {network['name']}: "
                                         f"Error getting events : {tmp_logs}",
                                        extra={'frontend': str(self.frontend)})
                            break

                        # Parsing 1k lines may take some while, so refresh token in Redis before
                        self.update_lock()

                        nb_events = len(tmp_logs['events'])
                        total_nb_events += nb_events
                        logs = tmp_logs['events']

                        def format_network_log(log):
                            log['log_type'] = "network"
                            log['organization_id'] = orga['id']
                            log['organization_name'] = orga['name']
                            log['network'] = network['name']
                            log['product'] = product_type
                            log['timestamp'] = log['occurredAt']
                            return json.dumps(log)

                        self.write_to_file([format_network_log(log) for log in logs])
                        # Writting may take some while, so refresh token in Redis
                        self.update_lock()

                        if nb_events > 0:
                            # No need to make_aware, date already contains timezone
                            self.frontend.cisco_meraki_timestamp[f"{network['id']}_{product_type}"] = tmp_logs['pageEndAt']
                            since = tmp_logs['pageEndAt']

                    if total_nb_events:
                        logger.info(f"[{__parser__}]:execute: Got {total_nb_events} logs for organisation {orga['name']}, "
                                    f"network {network['name']}, "
                                    f"product {product_type}",
                                    extra={'frontend': str(self.frontend)})


            if self.cisco_meraki_get_security_logs and not self.evt_stop.is_set():
                logger.info(f"[{__parser__}]:execute: Getting organisation {orga['name']} security events", extra={'frontend': str(self.frontend)})

                since = self.frontend.cisco_meraki_timestamp.get(f"org{orga['id']}_security_events", (timezone.now()-timedelta(days=1)).isoformat())
                security_events = self.get_organization_appliance_security_events(since, orga['id'])
                # Parsing 1k lines may take some while, so refresh token in Redis before
                self.update_lock()

                def format_security_log(log):
                    log['log_type'] = "security"
                    log['organization_id'] = orga['id']
                    log['organization_name'] = orga['name']
                    log['timestamp'] = log['ts']
                    return json.dumps(log)

                self.write_to_file([format_security_log(log) for log in security_events])
                # Writting may take some while, so refresh token in Redis
                self.update_lock()

                if len(security_events) > 0:
                    # No need to make_aware, date already contains timezone
                    self.frontend.cisco_meraki_timestamp[f"org{orga['id']}_security_events"] = security_events[-1]['ts']


        logger.info(f"[{__parser__}]:execute: Parser ending", extra={'frontend': str(self.frontend)})
