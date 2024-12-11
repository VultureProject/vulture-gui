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
__author__ = "Gaultier PARAIN"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Cisco Umbrella managed org API Parser'
__parser__ = 'CISCO-UMBRELLA_MANAGED_ORG'


import json
import logging
import requests
from copy import deepcopy

from datetime import datetime, timedelta
from django.conf import settings
from django.utils import timezone
from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class CiscoUmbrellaManagedOrgAPIError(Exception):
    pass


class CiscoUmbrellaManagedOrgParser(ApiParser):
    TOKEN_URL = 'https://api.umbrella.com/auth/v2/token'
    BASE_URL = 'https://api.umbrella.com/reports/v2/activity/'
    ORGANIZATIONS_URL = 'https://api.umbrella.com/admin/v2/managed/customers'
    LIMIT_MAX = 5000
    OFFSET_MAX = 10000

    HEADERS = {
        "Content-Type": "application/json",
        'Accept': 'application/json'
    }

    def __init__(self, data):
        super().__init__(data)

        self.cisco_umbrella_managed_org_api_key = data["cisco_umbrella_managed_org_api_key"]
        self.cisco_umbrella_managed_org_secret_key = data["cisco_umbrella_managed_org_secret_key"]
        self.cisco_umbrella_managed_org_customers_id = data["cisco_umbrella_managed_org_customers_id"]

        self.cisco_umbrella_managed_org_get_proxy = data["cisco_umbrella_managed_org_get_proxy"]
        self.cisco_umbrella_managed_org_get_dns = data["cisco_umbrella_managed_org_get_dns"]

        self.cisco_umbrella_managed_org_parent_access_token = data.get("cisco_umbrella_managed_org_parent_access_token", None)
        self.cisco_umbrella_managed_org_parent_expires_at = data.get("cisco_umbrella_managed_org_parent_expires_at", None)

        self.cisco_umbrella_managed_org_customers_tokens = data.get("cisco_umbrella_managed_org_customers_tokens", {})

        self.session = None

    def _get_parent_token(self):
        logger.info(f"[{__parser__}]: Getting a new authentication token...", extra={'frontend': str(self.frontend)})
        response = requests.get(
            url=self.TOKEN_URL,
            auth=(self.cisco_umbrella_managed_org_api_key, self.cisco_umbrella_managed_org_secret_key),
            proxies=self.proxies,
            timeout=10,
            verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl
        )
        if response.status_code != requests.codes.ok:
            logger.error(f"[{__parser__}]: _get_parent_token: Error {response.status_code} while trying to get token: {response.content}", extra={'frontend': str(self.frontend)})
            raise CiscoUmbrellaManagedOrgAPIError("Failed to get a new parent access token")
        token = response.json()
        self.cisco_umbrella_managed_org_parent_access_token = token["access_token"]
        self.cisco_umbrella_managed_org_parent_expires_at = timezone.now() + timedelta(seconds=int(token["expires_in"]))

    def _connect(self, access_token):
        self.session = requests.Session()
        headers = self.HEADERS
        headers.update({'Authorization': f"Bearer {access_token}"})
        self.session.headers.update(headers)

    def _get_customers_id(self, timeout=10):
        if not self.cisco_umbrella_managed_org_parent_access_token or not self.cisco_umbrella_managed_org_parent_expires_at or (self.cisco_umbrella_managed_org_parent_expires_at - timedelta(seconds=10) < timezone.now()):
            self._get_parent_token()
        self._connect(self.cisco_umbrella_managed_org_parent_access_token)
        logger.info(f"[{__parser__}]: Getting the list of organisation id", extra={'frontend': str(self.frontend)})

        response = self.session.get(self.ORGANIZATIONS_URL,
            timeout=timeout,
            proxies=self.proxies,
            verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl
        )
        if response.status_code != requests.codes.ok:
            raise CiscoUmbrellaManagedOrgAPIError(f"Error at Cisco-Umbrella API Call URL: {self.ORGANIZATIONS_URL} Code: {response.status_code} Content: {response.content}")
        return [str(customer.get("customerId")) for customer in response.json()]

    def _get_customer_token(self, customer_id):
        logger.info(f"[{__parser__}]: Getting a new authentication token for customer {customer_id}", extra={'frontend': str(self.frontend)})
        headers = {
            'X-Umbrella-OrgID': str(customer_id),
            'Content-Type': 'application/x-www-form-urlencoded'
        }
        response = requests.get(
            url=self.TOKEN_URL,
            auth=(self.cisco_umbrella_managed_org_api_key, self.cisco_umbrella_managed_org_secret_key),
            headers=headers,
            proxies=self.proxies,
            verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl
        )
        if response.status_code != requests.codes.ok:
            logger.error(f"[{__parser__}]: _get_customer_token: Error {response.status_code} while trying to get customer {customer_id}'s token: {response.content}", extra={'frontend': str(self.frontend)})
            raise CiscoUmbrellaManagedOrgAPIError(f"Failed to get customer {customer_id}'s token")
        token = response.json()
        self.cisco_umbrella_managed_org_customers_tokens[customer_id] = {}
        self.cisco_umbrella_managed_org_customers_tokens[customer_id]["access_token"] = token["access_token"]
        self.cisco_umbrella_managed_org_customers_tokens[customer_id]["expires_at"] = timezone.now() + timedelta(seconds=int(token["expires_in"]))

    def test(self):
        try:
            log_types = []
            if self.cisco_umbrella_managed_org_get_dns:
                log_types.append("dns")
            if self.cisco_umbrella_managed_org_get_proxy:
                log_types.append("proxy")
            customer_ids_available = self._get_customers_id()
            logger.info(f"[{__parser__}]:test: Available customers ids are {customer_ids_available}", extra={'frontend': str(self.frontend)})
            if self.cisco_umbrella_managed_org_customers_id:
                customer_ids = set(self.cisco_umbrella_managed_org_customers_id.split(",")).intersection(set(customer_ids_available))
            else:
                customer_ids = customer_ids_available
            result = []
            logger.info(f"[{__parser__}]:test: Customers ids are {customer_ids}", extra={'frontend': str(self.frontend)})
            for customer_id in customer_ids:
                self._get_customer_token(customer_id)
                for log_type in log_types:
                    data = self.get_logs(timezone.now()-timedelta(hours=1), timezone.now(), customer_id, log_type)
                    result.extend(data)

            return {
                "status": True,
                "data": result
            }
        except Exception as e:
            logger.exception(f"[{__parser__}]:test: {e}", extra={'frontend': str(self.frontend)})
            return {
                "status": False,
                "error": str(e)
            }

    def __execute_query(self, url, query, timeout=30):
        '''
        raw request doesn't handle the pagination natively
        '''
        response = self.session.get(url,
            params=query,
            timeout=timeout,
            proxies=self.proxies,
            verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl
        )
        if response.status_code != requests.codes.ok:
            raise CiscoUmbrellaManagedOrgAPIError(f"Error at Cisco-Umbrella managed org API Call URL: {url} Code: {response.status_code} Content: {response.content}")

        return response.json()

    def get_logs(self, since, to, customer_id, log_type, index=0):
        payload = {
            'offset': index,
            'limit': self.LIMIT_MAX,
            'from': int(since.timestamp() * 1000),
            'to': int(to.timestamp() * 1000),
        }
        url = self.BASE_URL + log_type
        self.session = requests.Session()
        self.session.headers.update({'X-Umbrella-OrgID': str(customer_id)})
        self.session.headers.update({'Authorization': f"Bearer {self.cisco_umbrella_managed_org_customers_tokens[customer_id]['access_token']}"})
        logger.info(f"[{__parser__}]:get_logs: Cisco-Umbrella query parameters : {payload}, log type : {log_type}",
                     extra={'frontend': str(self.frontend)})
        return self.__execute_query(url, payload)['data']

    def format_log(self, log):
        log["related_users"] = []
        for identity in log.get("identities", []):
            if identity.get("type", {}).get("type") == "directory_user" and "label" in identity:
                log["related_users"].append(identity["label"])
        return json.dumps(log)

    def execute(self):
        log_types = []
        if self.cisco_umbrella_managed_org_get_dns:
            log_types.append("dns")
        if self.cisco_umbrella_managed_org_get_proxy:
            log_types.append("proxy")

        customer_ids_available = self._get_customers_id()
        logger.info(f"[{__parser__}]:execute: Available customers ids are {customer_ids_available}", extra={'frontend': str(self.frontend)})
        self.frontend.cisco_umbrella_managed_org_parent_access_token = self.cisco_umbrella_managed_org_parent_access_token
        self.frontend.cisco_umbrella_managed_org_parent_expires_at = self.cisco_umbrella_managed_org_parent_expires_at
        self.frontend.save()

        if self.cisco_umbrella_managed_org_customers_id:
            customer_ids = set(self.cisco_umbrella_managed_org_customers_id).intersection(set(customer_ids_available))
        else:
            customer_ids = set(customer_ids_available)

        for customer_id in customer_ids:
            if not self.cisco_umbrella_managed_org_customers_tokens.get(customer_id) or not self.cisco_umbrella_managed_org_customers_tokens[customer_id].get("expires_at") or not self.cisco_umbrella_managed_org_customers_tokens[customer_id].get("access_token") or (self.cisco_umbrella_managed_org_customers_tokens[customer_id]["expires_at"] - timedelta(seconds=10) > timezone.now()):
                self._get_customer_token(customer_id)
                self.frontend.cisco_umbrella_managed_org_customers_tokens[customer_id] = deepcopy(self.cisco_umbrella_managed_org_customers_tokens[customer_id])
                self.frontend.save()
            for log_type in log_types:
                timestamp_field_name = f"app{customer_id}_{log_type}"
                since = self.last_collected_timestamps.get(timestamp_field_name) or (timezone.now() - timedelta(days=1))
                to = min(timezone.now(), since + timedelta(hours=24))
                logger.info(f"[{__parser__}]:execute: getting {log_type} logs from {since} to {to}, for organization {customer_id}", extra={'frontend': str(self.frontend)})
                index = 0
                logs_count = self.LIMIT_MAX
                while logs_count == self.LIMIT_MAX and index <= self.OFFSET_MAX:
                    logs = self.get_logs(since, to, customer_id, log_type)
                    # Downloading may take some while, so refresh token in Redis
                    self.update_lock()
                    logs_count = len(logs)
                    logger.info(f"[{__parser__}]:execute: got {logs_count} new lines", extra={'frontend': str(self.frontend)})
                    index += logs_count
                    logger.info(f"[{__parser__}]:execute: retrieved a total of {index} lines", extra={'frontend': str(self.frontend)})
                    self.write_to_file([self.format_log(log) for log in logs])
                    # Writting may take some while, so refresh token in Redis
                    self.update_lock()
                # When there are more than 15000 logs, last_api_call is the timestamp of the last log
                if logs_count == self.LIMIT_MAX and index == self.OFFSET_MAX + self.LIMIT_MAX:
                    timestamp = logs[-1]['timestamp']/1000
                    self.last_collected_timestamps[timestamp_field_name] = datetime.fromtimestamp(timestamp, tz=timezone.utc)
                elif index > 0:
                    # All logs have been recovered, the parser can be stopped  
                    self.last_collected_timestamps[timestamp_field_name] = to  
                    break
                elif since < timezone.now() - timedelta(hours=24):  
                    self.last_collected_timestamps[timestamp_field_name] = since + timedelta(hours=1)
                self.frontend.save()

        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})