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

__author__ = "Gaultier Parain"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = "Varonis API Parser toolkit"
__parser__ = "VARONIS"

import json
import logging
import requests
from datetime import timedelta, datetime, timezone

from django.utils import timezone
from django.conf import settings
from toolkit.api_parser.api_parser import ApiParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger("api_parser")


class VaronisAPIError(Exception):
    pass


class VaronisParser(ApiParser):

    ALL_COLUMNS_EVENT = ["Event.StatusReason.Name","Event.StatusReason.ID","Event.Location.BlacklistedLocation","Event.Location.Subdivision.Name","Event.Location.Subdivision.ID","Event.Location.Country.Name","Event.Location.Country.ID","Event.Filer.Platform.Name","Event.Filer.Platform.ID","Event.OnResource.Stats.ExposureLevel.Name","Event.OnResource.Stats.ExposureLevel.ID","Event.ByAccount.Identity.Followup.Flag.Name","Event.ByAccount.Identity.Followup.Flag.ID","Event.ByAccount.SamAccountName","Event.ByAccount.SidID","Event.ByAccount.Type.Name","Event.ByAccount.Type.ID","Event.ByAccount.DistinguishedName","Event.OnAccount.Domain.Name","Event.OnAccount.Domain.ID","Event.OnAccount.Identity.Followup.Flag.Name","Event.OnAccount.Identity.Followup.Flag.ID","Event.Time","Event.Operation.Name","Event.Operation.ID","Event.EndTime","Event.Type.Name","Event.Type.ID","Event.ByAccount.Identity.Name","Event.ByAccount.Identity.ID","Event.OnAccount.DNSDomain.Name","Event.OnAccount.DNSDomain.ID","Event.OnAccount.Identity.Name","Event.OnAccount.Identity.ID","Event.OnObjectName","Event.OnResource.Path","Event.OnResource.EntityIdx","Event.ByAccount.Domain.Name","Event.ByAccount.Domain.ID","Event.ByAccount.DNSDomain.Name","Event.ByAccount.DNSDomain.ID","Event.OnResource.IsSensitive","Event.Status.Name","Event.Status.ID","Event.Filer.Name","Event.Filer.ID","Event.OnResource.ObjectType.Name","Event.OnResource.ObjectType.ID","Event.Device.UserAgent","Event.CorrelationId","Event.ByAccount.Identity.Followup.Notes","Event.OnAccount.Identity.Followup.Notes","Event.OnResource.Followup.Flag.Name","Event.OnResource.Followup.Flag.ID","Event.ByAccount.Identity.Department","Event.OnAccount.Identity.Department","Event.IP","Event.ByAccount.Identity.Manager.Name","Event.ByAccount.Identity.Manager.ID","Event.OnAccount.Identity.Manager.Name","Event.OnAccount.Identity.Manager.ID","Event.ByAccount.IsDisabled","Event.ByAccount.IsStale","Event.OnAccount.IsStale","Event.Device.Name","Event.ByAccount.LastLogonTime","Event.OnAccount.LastLogonTime","Event.OnResource.File.Type","Event.OnResource.AccessDate","Event.OnResource.ModifyDate","Event.OnResource.FSOwner.Name","Event.OnResource.FSOwner.SidID","Event.OnResource.Classification.TotalHitCount","Event.OnMail.ItemType.Name","Event.OnMail.ItemType.ID","Event.OnMail.Recipient","Event.OnResource.CreateDate","Event.OnMail.Source","Event.OnResource.PathDepth","Event.OnResource.NumberOfNestedFiles","Event.Alert.Rule.Name","Event.Alert.Rule.ID","Event.OnResource.SizeFolder","Event.Alert.Rule.Category.Name","Event.Alert.Rule.Category.ID","Event.OnResource.SizeFolderAndSubFolders","Event.Alert.Rule.Severity.Name","Event.Alert.Rule.Severity.ID","Event.OnResource.NumberOfFiles","Event.Alert.Time","Event.Alert.TimeUTC","Event.TimeUTC","Event.OnResource.NumberOfFilesInSubFolders","Event.Alert.ID","Event.OnResource.NumberOfNestedFolders","Event.Description","Event.OnResource.SizePhysicalSDTFile","Event.EventsCount","Event.OnResource.SizePhysicalNestedFoldersFiles","Event.ByAccount.PasswordStatus.Name","Event.ByAccount.PasswordStatus.ID","Event.OnResource.SizePhysicalFiles","Event.ByAccount.AccountExpirationDate","Event.OnResource.SizeSubFolders","Event.OnAccount.IsDisabled","Event.OnResource.NumberOfNestedObjects","Event.OnAccount.IsLockout","Event.UploadSize","Event.DownloadSize","Event.OnAccount.PasswordStatus.Name","Event.OnAccount.PasswordStatus.ID","Event.SessionDuration","Event.OnAccount.AccountExpirationDate","Event.ConnectionType.Name","Event.ConnectionType.ID","Event.ClientType.Name","Event.ClientType.ID","Event.AgentVersion","Event.ByAccount.VPNGroups","Event.ByAccount.IsLockout","Event.DC.HostName","Event.Direction.Name","Event.Direction.ID","Event.OnAccount.SamAccountName","Event.OnAccount.SidID","Event.ByAccount.PrivilegedAccountType.Name","Event.ByAccount.PrivilegedAccountType.ID","Event.DNSFlags","Event.CollectionMethod.Name","Event.CollectionMethod.ID","Event.OnAccount.AccountType.Name","Event.OnAccount.AccountType.ID","Event.DNSRecordType","Event.OnResource.Classification.CategorySummary","Event.ByAccount.Identity.Affiliation.Name","Event.ByAccount.Identity.Affiliation.ID","Event.OnAccount.Application.ID","Event.TransportLayer.Name","Event.TransportLayer.ID","Event.OnAccount.Application.Name","Event.OnAccount.Identity.Affiliation.Name","Event.OnAccount.Identity.Affiliation.ID","Event.Destination.URL.Reputation.Name","Event.Destination.URL.Reputation.ID","Event.HttpMethod.Name","Event.HttpMethod.ID","Event.OnAccount.PublisherName","Event.Destination.IP","Event.Destination.URL.Categorization.Name","Event.Destination.URL.Categorization.ID","Event.OnAccount.IsPublisherVerified","Event.Destination.DeviceName","Event.ByAccount.Application.ID","Event.Destination.Domain","Event.ByAccount.Application.Name","Event.Device.ExternalIP.IP","Event.ByAccount.PublisherName","Event.ByAccount.IsPublisherVerified","Event.Device.OperatingSystem","Event.SourcePort","Event.SourceZone","Event.App","Event.Device.ExternalIP.ThreatTypes.Name","Event.Device.ExternalIP.ThreatTypes.ID","Event.Destination.Port","Event.Destination.Zone","Event.NAT.Source.Address","Event.NAT.Destination.Address","Event.NAT.Source.Port","Event.NAT.Destination.Port","Event.Protocol.Name","Event.Protocol.ID","Event.ApplicationProtocol.Name","Event.ApplicationProtocol.ID","Event.Device.ExternalIP.IsMalicious","Event.Device.ExternalIP.Reputation.Name","Event.Device.ExternalIP.Reputation.ID","Event.ByAccount.IsMailboxOwner","Event.StatusReasonCodeName","Event.StatusReasonCode","Event.Authentication.TicketEncryption.Name","Event.Authentication.TicketEncryption.ID","Event.OnGPO.NewVersion","Event.Authentication.PreAuthenticationType","Event.OnGPO.Settings.NewValue","Event.Authentication.Protocol.Name","Event.Authentication.Protocol.ID","Event.OnGPO.Settings.OldValue","Event.OrgOpCode","Event.OnGPO.Settings.Name","Event.ByAccount.ExpirationStatus.Name","Event.ByAccount.ExpirationStatus.ID","Event.OnGPO.Settings.Path","Event.OnAccount.ExpirationStatus.Name","Event.OnAccount.ExpirationStatus.ID","Event.OnGPO.ConfigurationType.Name","Event.OnGPO.ConfigurationType.ID","Event.Trustee.Identity.Name","Event.Trustee.Identity.ID","Event.OnMail.Mailbox.Type.Name","Event.OnMail.Mailbox.Type.ID","Event.Trustee.DNSDomain.Name","Event.Trustee.DNSDomain.ID","Event.Trustee.Type.Name","Event.Trustee.Type.ID","Event.Trustee.Application.ID","Event.Trustee.Application.Name","Event.Trustee.PublisherName","Event.Trustee.IsPublisherVerified","Event.Permission.IsDirectChange","Event.Permission.ChangedPermissionFlags","Event.Trustee.Identity.Affiliation.Name","Event.Trustee.Identity.Affiliation.ID","Event.LogonType","Event.Authentication.Package","Event.ImpersonationLevel","Event.OnMail.AttachmentName","Event.OnMail.WithAttachments","Event.OnResource.ClassificationLabels.Summary","Event.OnMail.HasOutOfOrganizationReciever","Event.Type.Activity.Name","Event.Type.Activity.ID","Event.InfoTags.Name","Event.InfoTags.ID","Event.Authentication.TicketOptions","Event.OnMail.Headers.SentDate","Event.OnMail.Headers.AuthenticationResults.Spf.Passed","Event.OnMail.Headers.AuthenticationResults.Dkim.Passed","Event.OnMail.Headers.AuthenticationResults.Dmarc.Passed","Event.OnMail.Headers.XOriginalSender","Event.OnMail.Headers.ReceivedServerIP","Event.OnResource.Classification.Summary","Event.OnMail.Date","Event.OnResource.ShareAccessPaths","Event.Permission.Before","Event.Permission.After","Event.Permission.Type","Event.OnResource.LocalMappedPath","Event.Session.BrowserType","Event.Session.TrustDomain.Type","Event.Session.AzureAuthentication.Requirement","Event.Session.AzureAuthentication.ConditionalAccessStatus","Event.Session.AzureAuthentication.TokenIssuerType","Event.Session.AzureAuthentication.Method","Event.Session.AzureAuthentication.MethodDetail","Event.Session.AzureAuthentication.Step","Event.Session.AzureAuthentication.ResultDetail","Event.Session.AzureAuthentication.ReasonDetails","Event.Device.TrustType","Event.Session.AzureAuthentication.Status.Name","Event.Session.AzureAuthentication.Status.ID","Event.Device.ManagedStatus.Name","Event.Device.ManagedStatus.ID","Event.ID","Event.IsAlerted"]
    ALL_COLUMNS_ALERT = ["Alert.Filer.Name","Alert.Filer.ID","Alert.Time","Alert.Filer.Platform.Name","Alert.Filer.Platform.ID","Alert.ID","Alert.Rule.Severity.Name","Alert.Rule.Severity.ID","Alert.Rule.Name","Alert.Rule.ID","Alert.User.Name","Alert.User.SidID","Alert.Device.HostName","Alert.Asset.Path","Alert.Asset.ID","Alert.Status.Name","Alert.Status.ID","Alert.EventsCount","Alert.Rule.Category.Name","Alert.Rule.Category.ID","Alert.Device.IsMaliciousExternalIP","Alert.TimeUTC","Alert.User.Identity.ID","Alert.User.Identity.Name","Alert.User.AccountType.ID","Alert.Initial.Event.TimeUTC"]

    HEADERS = {
        "Content-Type": "application/json"
    }
    TOKEN_ENDPOINT = "/api/authentication/api_keys/token"

    def __init__(self, data):
        super().__init__(data)
        self.varonis_host = data["varonis_host"].rstrip("/")
        self.varonis_api_key = data["varonis_api_key"]

        self.session = None
        self.access_token = None

        self._connect()

    def _get_token(self):
        params = { "grant_type": "varonis_custom" }

        headers_token = {
            "x-api-key" : self.varonis_api_key,
            "Content-Type" : "application/json"
        }
        url = self.varonis_host + self.TOKEN_ENDPOINT
        res = requests.post(
            url,
            data=params,
            headers=headers_token,
            proxies=self.proxies,
            verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl,
            timeout=30
        )
        if res.status_code != 200:
            logger.error(f"[{__parser__}]: Error with API authentication : {res.status_code}, {res.text}", extra={"frontend": str(self.frontend)})
            raise VaronisAPIError(f"Authentication error : {res.status_code}, {res.text}")

        try:
            content = res.json()
            self.access_token = content["access_token"]
        except json.JSONDecodeError:
            logger.error(f"[{__parser__}]:The response of token request is not in JSON format")
            raise VaronisAPIError("The response of token request is not in JSON format")
        except KeyError:
            logger.error(f"[{__parser__}]:No access_token present in the reply")
            raise VaronisAPIError("Could not get a new Access Token")

    def _connect(self):
        try:
            if self.session is None:
                self.session = requests.Session()

            headers = self.HEADERS
            self.session.headers.update(headers)
        except Exception as err:
            raise VaronisAPIError(err)
        if self.access_token is None:
            self._get_token()
        self.session.headers.update({"Authorization": f"bearer {self.access_token}"})

    def test(self):
        logger.info(f"[{__parser__}]:test: Launching test", extra={"frontend": str(self.frontend)})

        try:
            since = timezone.now() - timedelta(hours=24)
            to = timezone.now()
            (alerts, events) = self.get_logs(since, to)
            alerts.extend(events)
            return {
                "status": True,
                "data": alerts
            }
        except Exception as e:
            logger.error(f"[{__parser__}]:test: {e}", extra={"frontend": str(self.frontend)})
            return {
                "status": False,
                "error": str(e)
            }

    def _execute_query(self, method, endpoint, params=None):

        url = self.varonis_host + endpoint
        logger.info(f"[{__parser__}]:Request to {url}, method={method}, params={params}", extra={"frontend": str(self.frontend)})
        if method == "GET":
            res = self.session.get(
                url,
                headers=self.HEADERS,
                proxies=self.proxies,
                verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl,
                timeout=30)
        elif method == "POST":
            res = self.session.post(
                url,
                data=params,
                headers=self.HEADERS,
                proxies=self.proxies,
                verify=self.api_parser_custom_certificate or self.api_parser_verify_ssl,
                timeout=30)
        else:
            raise VaronisAPIError(f"Error at Varonis request, unknown method : {method}")
        return res

    def varonis_api_search(self, rows, query):
        (e_rows, e_terminate) = self.varonis_api_search_create(rows, query)
        content = self.varonis_api_search_rows(e_rows)

        return (e_terminate, content)

    def varonis_api_search_create(self, rows, query):
        params = {
            "rows": rows,
            "query": query,
            "facets": []
        }
        json_data = json.dumps(params)
        res = self._execute_query("POST", "/app/dataquery/api/search/v2/search", json_data)

        if res.status_code != 201:
            logger.error(f"[{__parser__}] Error while retrieving alerts {res.status_code}, {res.text}", extra={"frontend": str(self.frontend)})
            raise  VaronisAPIError(res.text)
        try:
            content = res.json()
        except json.JSONDecodeError:
            logger.error(f"[{__parser__}]:The response of token request is not in JSON format")
            raise VaronisAPIError("The response of token request is not in JSON format")
        (e_rows, e_terminate) = (content[0]["location"], content[1]["location"])

        if not e_rows:
            raise VaronisAPIError("Search has not been created")

        return (e_rows, e_terminate)

    def varonis_api_search_rows(self, rows):
        res = self._execute_query("GET", f"/app/dataquery/api/search/{rows}?from=0&to=999")

        # Sometimes we hit this instruction with a status_code == 304 (Content Not Modified),
        # I don't have any insights or hints to understand what's happening but we should consider to retry a request whenever we received a 304 status code
        retry = 0
        while res.status_code == 304 and not self.evt_stop.is_set() and retry < 5:
            res = self._execute_query("GET", f"/app/dataquery/api/search/{rows}?from=0&to=999")
            self.evt_stop.wait(1.0)
            retry += 1
        if res.status_code != 200:
            logger.error(f"[{__parser__}] Error while retrieving rows from search, {res.status_code}, {res.text}", extra={"frontend": str(self.frontend)})
            raise VaronisAPIError("Error while retrieving rows from search")
        try:
            return res.json()
        except json.JSONDecodeError:
            logger.error(f"[{__parser__}]:The response of the search is not in JSON format")
            raise VaronisAPIError("The response of the search is not in JSON format")

    def varonis_api_search_terminate(self, terminate):
        res = self._execute_query("POST", f"/app/dataquery/api/search/{terminate}")
        return res.status_code == 200

    def camel_to_snake(self, value):
        result = value[0].lower()
        for i in range(len(value) - 2):
            if value[i+1].islower() and value[i+2].isupper():
                result += (value[i+1].lower() + "_")
            # Case when there are at least 3 uppercases at the beginning of the value
            elif i < len(value) - 3 and value[i+1].isupper() and value[i+2].isupper() and value[i+3].islower():
                result += (value[i+1].lower() + "_")
            else:
                result += value[i+1].lower()
        result += value[-1].lower()
        return result

    def content_to_dict(self, content):
        logs = []
        for row in content["rows"]:
            log = {}
            for i in range(len(row)):
                if row[i]:
                    path = content["columns"][i].split(".")
                    len_path = len(path)

                    depth_dict = log
                    for key_depth,key in enumerate(path):
                        key = self.camel_to_snake(key)
                        if key not in depth_dict.keys():
                            if key_depth == len_path - 1:
                                # At the end of the path, we set the value
                                depth_dict[key] = row[i]
                            else:
                                # We set the next key of the path
                                depth_dict[key] = {}
                        depth_dict = depth_dict[key]
            logs.append(log)
        return logs

    def get_alerts(self, since, to):
        rows = {
            "columns": self.ALL_COLUMNS_ALERT,
            "filter":[],
            "grouping":"",
            "ordering":[]
        }

        query = {
            "entityName": "Alert",
            "filter": {
                "filterOperator": 0,
                "filters": [
                    {
                        "path":"Alert.TimeUTC",
                        "operator":"Between",
                        "values":[ { "startDate": since.strftime("%Y-%m-%dT%H:%M:%SZ"), "endDate": to.strftime("%Y-%m-%dT%H:%M:%SZ") } ]
                    },
                    {
                        "path":"Alert.Status.ID",
                        "operator":"In",
                        "values":[
                            {"Alert.Status.ID": "1", "displayValue": "New"},
                            {"Alert.Status.ID": "2", "displayValue": "Under Investigation"},
                            {"Alert.Status.ID": "3", "displayValue": "Closed"},
                            {"Alert.Status.ID": "4", "displayValue": "Escalated"},
                            {"Alert.Status.ID": "5", "displayValue": "Auto-Resolved"}
                        ]
                    },
                    {
                        "path":"Alert.AggregationFilter",
                        "operator":"Equals",
                        "values":[ { "Alert.AggregationFilter": 1 } ]
                    }
                ]
            }
        }

        (e_terminate, content) = self.varonis_api_search(rows, query)

        alerts = self.content_to_dict(content)

        # Destroying the search
        self.varonis_api_search_terminate(e_terminate)

        return alerts

    def get_alerted_events(self, alert_id):
        rows = {
            "columns": self.ALL_COLUMNS_EVENT,
            "filter":[],
            "grouping":"",
            "ordering":[]
        }

        query = {
            "entityName": "Event",
            "filter": {
                "filterOperator": 0,
                "filters": [
                    {
                        "path": "Event.TimeUTC",
                        "operator": "LastDays",
                        "values": [ { "Event.TimeUTC": 365, "displayValue": 365 } ]
                    },
                    {
                        "path": "Event.Alert.ID",
                        "operator": "IncludesAny",
                        "values": [ { "Event.Alert.ID": alert_id, "displayValue": alert_id } ]
                    },
                ]
            }
        }

        (e_terminate, content) = self.varonis_api_search(rows, query)

        # Destroying the search
        self.varonis_api_search_terminate(e_terminate)

        events = self.content_to_dict(content)

        return events

    def retrieve_events_from_alerts(self, alerts_ids: list[str]):
        events = []
        for alert_id in alerts_ids:
            events.extend(self.get_alerted_events(alert_id))
        return events

    def get_logs(self, since, to):
        alerts = self.get_alerts(since, to)
        logger.info(f"{alerts}", extra={"frontend": str(self.frontend)})
        events = []
        if alerts:
            alert_ids = [alert["alert"]["id"] for alert in alerts]
            events = self.retrieve_events_from_alerts(alert_ids)
        return (alerts, events)

    def format_log(self, log):
        return json.dumps(log)

    def execute(self):
        try:
            since = self.frontend.last_api_call or (timezone.now() - timedelta(days=1))
            to = min(timezone.now(), since + timedelta(hours=24))

            logger.info(f"[{__parser__}]:execute: getting logs from {since} to {to}", extra={"frontend": str(self.frontend)})
            (alerts, events) = self.get_logs(since, to)
            self.update_lock()
            self.write_to_file([self.format_log(log) for log in alerts])
            self.update_lock()
            self.write_to_file([self.format_log(log) for log in events])
            self.update_lock()
            # increment by 1s to avoid repeating a line if its timestamp happens to be the exact timestamp 'to'
            if alerts:
                self.last_api_call = datetime.strptime(alerts[-1]["alert"]["time_utc"], "%Y-%m-%dT%H:%M:%S").astimezone(timezone.utc)
                self.frontend.last_api_call = self.last_api_call + timedelta(seconds=1)
                self.frontend.save()
                logger.info(f"[{__parser__}]:execute: new last_api_call is {self.frontend.last_api_call}", extra={"frontend": str(self.frontend)})
        except Exception as e:
            logger.exception(f"[{__parser__}]:execute: {e}", extra={"frontend": str(self.frontend)})
        logger.info(f"[{__parser__}]:execute: Parsing done.", extra={"frontend": str(self.frontend)})
