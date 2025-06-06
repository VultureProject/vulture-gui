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

        #Handle data coming from the GUI
        if isinstance(self.cisco_umbrella_managed_org_customers_id, str):
            self.cisco_umbrella_managed_org_customers_id = self.cisco_umbrella_managed_org_customers_id.split(",")

        self.cisco_umbrella_managed_org_get_proxy = data["cisco_umbrella_managed_org_get_proxy"]
        self.cisco_umbrella_managed_org_get_dns = data["cisco_umbrella_managed_org_get_dns"]

        self.cisco_umbrella_managed_org_parent_access_token = data.get("cisco_umbrella_managed_org_parent_access_token", None)
        self.cisco_umbrella_managed_org_parent_expires_at = data.get("cisco_umbrella_managed_org_parent_expires_at", None)

        self.cisco_umbrella_managed_org_customers_tokens = data.get("cisco_umbrella_managed_org_customers_tokens", {})
        for customer_data in self.cisco_umbrella_managed_org_customers_tokens.values():
            if "expires_at" in customer_data and not customer_data['expires_at'].tzinfo:
                customer_data['expires_at'] = timezone.make_aware(customer_data['expires_at'])

    def _execute_query(self, url: str, query : dict = {}, additional_headers : dict = {}, auth=None, timeout=30) -> dict:
        '''
        raw request doesn't handle the pagination natively
        '''
        logger.info(f"[{__parser__}]: _execute_query: Fetching {url} with parameters {query}", extra={'frontend': str(self.frontend)})
        response = requests.get(
            url=url,
            params=query,
            auth=auth,
            headers={**self.HEADERS, **additional_headers},
            timeout=timeout,
            proxies=self.proxies,
            verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl
        )
        response.raise_for_status()

        return response.json()

    def _update_parent_token(self) -> None:
        logger.info(f"[{__parser__}]: Getting a new authentication token...", extra={'frontend': str(self.frontend)})
        try:
            token = self._execute_query(
                url=self.TOKEN_URL,
                auth=(self.cisco_umbrella_managed_org_api_key, self.cisco_umbrella_managed_org_secret_key),
                timeout=10,
            )
        except requests.HTTPError as e:
            error_code = ""
            error_str = str(e)
            if e.response:
                error_code = str(e.response.status_code)
                error_str = e.response.content

            logger.error(f"[{__parser__}]: _update_parent_token: Error{error_code} while trying to get token: {error_str}", extra={'frontend': str(self.frontend)})
            raise CiscoUmbrellaManagedOrgAPIError("Failed to get a new parent access token")

        self.cisco_umbrella_managed_org_parent_access_token = token["access_token"]
        self.cisco_umbrella_managed_org_parent_expires_at = timezone.now() + timedelta(seconds=int(token["expires_in"]))
        if self.frontend:
            self.frontend.cisco_umbrella_managed_org_parent_access_token = self.cisco_umbrella_managed_org_parent_access_token
            self.frontend.cisco_umbrella_managed_org_parent_expires_at = self.cisco_umbrella_managed_org_parent_expires_at
            self.frontend.save(update_fields=[
                'cisco_umbrella_managed_org_parent_access_token',
                'cisco_umbrella_managed_org_parent_expires_at'
            ])


    def _get_customers(self, timeout : int = 10) -> list:
        if not self.cisco_umbrella_managed_org_parent_access_token or not self.cisco_umbrella_managed_org_parent_expires_at or (self.cisco_umbrella_managed_org_parent_expires_at - timedelta(seconds=10) < timezone.now()):
            logger.info(f"[{__parser__}]: Updating main access token...", extra={'frontend': str(self.frontend)})
            self._update_parent_token()

        logger.info(f"[{__parser__}]: Getting the list of organisation id", extra={'frontend': str(self.frontend)})
        try:
            response = self._execute_query(
                url = self.ORGANIZATIONS_URL,
                timeout = timeout,
                additional_headers = {'Authorization': f"Bearer {self.cisco_umbrella_managed_org_parent_access_token}"}
            )
        except requests.HTTPError as e:
            error_code = ""
            error_str = str(e)
            if e.response:
                error_code = str(e.response.status_code)
                error_str = e.response.content

            logger.error(f"[{__parser__}]:[_get_customers]: Error {error_code} while trying to get IDs: {error_str}", extra={'frontend': str(self.frontend)})
            raise CiscoUmbrellaManagedOrgAPIError("Failed to get customer's IDs")

        available_customers = list()
        for customer in response:
            available_customers.append({"id": str(customer.get("customerId", "")), "name": str(customer.get("customerName", ""))})
        logger.info(f"[{__parser__}]:[_get_customers]: Available Customers ids are {[customer['id'] for customer in available_customers]}", extra={'frontend': str(self.frontend)})

        if self.cisco_umbrella_managed_org_customers_id:
            return list(filter(lambda customer: customer['id'] in self.cisco_umbrella_managed_org_customers_id, available_customers))
        else:
            return available_customers


    def _update_customer_token(self, customer_id: str) -> None:
        logger.info(f"[{__parser__}]: Getting a new authentication token for customer {customer_id}", extra={'frontend': str(self.frontend)})

        try:
            token = self._execute_query(
                url=self.TOKEN_URL,
                timeout=10,
                auth=(self.cisco_umbrella_managed_org_api_key, self.cisco_umbrella_managed_org_secret_key),
                additional_headers={
                    'X-Umbrella-OrgID': customer_id,
                    'Content-Type': 'application/x-www-form-urlencoded'
                },
            )
        except requests.HTTPError as e:
            error_code = ""
            error_str = str(e)
            if e.response:
                error_code = str(e.response.status_code)
                error_str = e.response.content

            logger.error(f"[{__parser__}]: _update_customer_token: Error{error_code} while trying to get customer {customer_id}'s token: {error_str}", extra={'frontend': str(self.frontend)})
            raise CiscoUmbrellaManagedOrgAPIError(f"Failed to get customer {customer_id}'s token")

        self.cisco_umbrella_managed_org_customers_tokens[customer_id] = {}
        self.cisco_umbrella_managed_org_customers_tokens[customer_id]["access_token"] = token["access_token"]
        self.cisco_umbrella_managed_org_customers_tokens[customer_id]["expires_at"] = timezone.now() + timedelta(seconds=int(token["expires_in"]))

        if self.frontend:
            self.frontend.cisco_umbrella_managed_org_customers_tokens[customer_id] = deepcopy(self.cisco_umbrella_managed_org_customers_tokens[customer_id])
            self.frontend.save(update_fields=['cisco_umbrella_managed_org_customers_tokens'])

    def test(self) -> dict:
        result = []
        try:
            log_types = []
            if self.cisco_umbrella_managed_org_get_dns:
                log_types.append("dns")
            if self.cisco_umbrella_managed_org_get_proxy:
                log_types.append("proxy")

            if not log_types:
                return {
                    "status": False,
                    "error": "no log type activated"
                }
            customers = self._get_customers()
            customer_ids_available = [customer['id'] for customer in customers]

            if self.cisco_umbrella_managed_org_customers_id:
                if difference := set(self.cisco_umbrella_managed_org_customers_id).difference(customer_ids_available):
                    result.append(f"WARNING: The following customer IDs are currently not available on the account: {list(difference)}")
                    result.append(f"Available customer IDs: {customer_ids_available}")

            for customer in customers:
                self._update_customer_token(customer['id'])
                for log_type in log_types:
                    data = self.get_logs(timezone.now()-timedelta(hours=1), timezone.now(), customer['id'], log_type, limit=10)
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

    def get_logs(self, since: datetime, to: datetime, customer_id: str, log_type: str, index : int = 0, limit=None) -> list:
        payload = {
            'offset': index,
            'limit': limit or self.LIMIT_MAX,
            'from': int(since.timestamp() * 1000),
            'to': int(to.timestamp() * 1000),
        }
        logger.info(f"[{__parser__}]:get_logs: Cisco-Umbrella querying customer ID {customer_id} with parameters: {payload}, log type: {log_type}, index: {index}",
                     extra={'frontend': str(self.frontend)})
        return self._execute_query(
            self.BASE_URL + log_type,
            payload,
            additional_headers={
                'X-Umbrella-OrgID': customer_id,
                'Authorization': f"Bearer {self.cisco_umbrella_managed_org_customers_tokens[customer_id]['access_token']}",
            })['data']

    def format_log(self, log: dict, customer: dict) -> str:
        # related_users
        log["related_users"] = []
        for identity in log.get("identities", []):
            if identity.get("type", {}).get("type") == "directory_user" and "label" in identity:
                log["related_users"].append(identity["label"])

        # organization
        log['organization'] = {}
        log['organization']['id'] = customer['id']
        log['organization']['name'] = customer['name']

        return json.dumps(log)

    def execute(self) -> None:
        log_types = []
        if self.cisco_umbrella_managed_org_get_dns:
            log_types.append("dns")
        if self.cisco_umbrella_managed_org_get_proxy:
            log_types.append("proxy")

        customers = self._get_customers()

        for customer in customers:
            if not self.cisco_umbrella_managed_org_customers_tokens.get(customer['id']) or not self.cisco_umbrella_managed_org_customers_tokens[customer['id']].get("expires_at") or not self.cisco_umbrella_managed_org_customers_tokens[customer['id']].get("access_token") or (self.cisco_umbrella_managed_org_customers_tokens[customer['id']]["expires_at"] - timedelta(seconds=10) < timezone.now()):
                self._update_customer_token(customer['id'])

            for log_type in log_types:
                timestamp_field_name = f"app{customer['id']}_{log_type}"
                since = self.last_collected_timestamps.get(timestamp_field_name) or (timezone.now() - timedelta(hours=1))
                to = min(timezone.now(), since + timedelta(hours=24))

                logger.info(f"[{__parser__}]:execute: getting {log_type} logs from {since} to {to}, for organization {customer['id']}", extra={'frontend': str(self.frontend)})

                index = 0
                logs_count = self.LIMIT_MAX
                while logs_count == self.LIMIT_MAX and index <= self.OFFSET_MAX:
                    logs = self.get_logs(since, to, customer['id'], log_type, index)
                    self.update_lock()
                    logs_count = len(logs)

                    logger.info(f"[{__parser__}]:execute: got {logs_count} new lines", extra={'frontend': str(self.frontend)})
                    index += logs_count
                    
                    logger.info(f"[{__parser__}]:execute: retrieved a total of {index} lines", extra={'frontend': str(self.frontend)})
                    self.write_to_file([self.format_log(log, customer) for log in logs])
                    self.update_lock()

                # When there are more than 15000 logs, last_api_call is the timestamp of the last log
                if logs_count == self.LIMIT_MAX and index == self.OFFSET_MAX + self.LIMIT_MAX:
                    timestamp = logs[-1]['timestamp']/1000
                    self.last_collected_timestamps[timestamp_field_name] = datetime.fromtimestamp(timestamp, tz=timezone.utc)
                elif index == 0 and since < timezone.now() - timedelta(hours=24):
                    self.last_collected_timestamps[timestamp_field_name] = since + timedelta(hours=1)
                else:
                    # All logs have been recovered
                    self.last_collected_timestamps[timestamp_field_name] = to
                logger.info(f"[{__parser__}]:execute: New current timestamp is {self.last_collected_timestamps[timestamp_field_name]} (customer {customer['id']}, type {log_type})", extra={'frontend': str(self.frontend)})

        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={'frontend': str(self.frontend)})
