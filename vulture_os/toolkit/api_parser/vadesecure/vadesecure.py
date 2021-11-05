import logging
import requests

from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from django.utils import timezone

from toolkit.api_parser.api_parser import ApiParser

from datetime import datetime, timedelta
from time import time, sleep
import json
from pprint import pprint

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class VadesecureAPIError(Exception):
    pass


class VadesecureParser(ApiParser):
    VERSION = "rest/v3.0"
    LOGIN = "login/login"
    EVENTLOG = "eventlog/list"
    GETREPORT = "filteringlog/getReport"
    GETDETAIL = "filteringlog/getDetail"
    ENDPOINTS = [EVENTLOG, GETREPORT]

    HEADERS = {
        "Content-Type": "application/json",
        'Accept': 'application/json'
    }

    def __init__(self, data):
        """
            vadesecure_host
            vadesecure_login
            vadesecure_password
        """
        super().__init__(data)


        self.vadesecure_host = data["vadesecure_host"].rstrip("/")
        if not self.vadesecure_host.startswith('https://'):
            self.vadesecure_host = f"https://{self.vadesecure_host}"

        self.vadesecure_login = data["vadesecure_login"]
        self.vadesecure_password = data["vadesecure_password"]

        self.session = None
        self.accountID = None   

        self.isTest = False


    def _connect(self):
        try:
            if self.session is None:
                self.session = requests.Session()

                headers = self.HEADERS

                self.session.headers.update(headers)

                response = self.session.post(
                    f'{self.vadesecure_host}/{self.VERSION}/{self.LOGIN}',
                    timeout=10,
                    json={
                        "login": self.vadesecure_login,
                        "password": self.vadesecure_password
                    },
                    proxies=self.proxies
                )
                assert response.status_code == 200

                self.session.headers.update({
                    "x-vrc-authorization": self.vadesecure_login + ":" + response.headers["x-vrc-authorization"]
                })

                try:
                    response = response.json()
                    self.userId = int(response["accounts"][0]["accountId"])
                except:
                    return False
            return True

        except Exception as err:
            raise VadesecureAPIError(err)


    def __execute_query(self, method, url, query, timeout=10):
        """
        raw request dosent handle the pagination natively
        """

        if method == "POST":
            response = self.session.post(
                url,
                json=query,
                headers=self.HEADERS,
                timeout=timeout,
                proxies=self.proxies
            )
        else:
            raise VadesecureAPIError(f"Error at Vadesecure request, unknown method : {method}")

        # response.raise_for_status()
        if response.status_code != 200:
            raise VadesecureAPIError(f"Error at Vadesecure API Call URL: {url} Code: {response.status_code} Content: {response.content}")

        return response.json()


    def format_log(self, log):
        """
            Stringifies the line of log.
        """
        log['url'] = f"{self.vadesecure_host}"
        return json.dumps(log)


    def fetch_details(self, payload, logs):        
        url = f"{self.vadesecure_host}/{self.VERSION}/{self.GETDETAIL}"
        payload = {
            "userId": self.userId,
        }
        # detailed_logs = []        
        for log in logs:
            msgId = log["messageId"]
            logger.debug(f"Vadesecure API: Fetching details of log with messageId: {msgId}",
                         extra={'tenant': self.tenant_name})
            try:
                payload.update({
                    "date": log["date"],
                    "messageId": log["messageId"],
                    "hostname": log["hostname"]
                })
                response = self.__execute_query("POST", url, payload)
                
                try:
                    log["details"] = json.dumps([l for l in response["detail"].split("\r\n") if l != ""])
                except:
                    logger.warning(f"Vadesecure API: No details for log: {payload}",
                                   extra={'tenant': self.tenant_name})
                    continue
            except:
                logger.warning(f"Vadesecure API: Couldn't fetch the details of a log (might be empty?)",
                               extra={'tenant': self.tenant_name})
        return [self.format_log(l) for l in logs]


    def fetch_endpoint(self, endpoint, to, since, payload):

        logger.debug(f"Vadesecure API: parser starting from {since} to {to}.",
                     extra={'tenant': self.tenant_name})

        alert_url = f"{self.vadesecure_host}/{self.VERSION}/{endpoint}"
        index = 0
        total = 1
        logs_pages = []
        while index < total:   
        
            # Should be moved?
            # Right now it's a call every query
            self._connect()

            payload.update({
                'pageToGet': index,
                'userId': self.userId
            })
            response = self.__execute_query("POST", alert_url, payload)         

            # Downloading may take a while, so refresh token in Redis
            try:
                self.update_lock()
            except:
                pass

            logs = response['logs']
            
            total = response['availablePages']

            if total == 0:
                # Means that there are no logs available. It may be for two
                # reasons: no log during this period or logs not available at
                # request time.
                # If there are no logs, no need to write them and we should not
                # set the last_api_call.
                break

            # Turn to the next page
            index += 1 
            logger.debug(f"Vadesecure API parser: retrieved page n°{index}/{total}",
                         extra={'tenant': self.tenant_name})

            if endpoint == self.GETREPORT and not self.isTest:
                # We need to call getdetail for each logs 
                logs_pages += self.fetch_details(payload, logs)
            else:
                logs_pages += [self.format_log(l) for l in logs]

            # We do not want to timeout, it's only a test
            if self.isTest:
                break

        return logs_pages


    def execute(self):
        """
            Needs to be forced every 5min MAX
        """

        logs_endpoints = []

        # POSIX Timestamps in milliseconds
        if self.isTest:
            self.last_api_call = None    
    
        since = int( (self.last_api_call or timezone.now()-timedelta(minutes=5 )).timestamp() ) * 1000
        
        to_tz = timezone.now()
        to = int(to_tz.timestamp() * 1000)
        
        period_payload = "MINUTES_05"
        logger.warning(f"DELTA: {to - since}", extra={'tenant': self.tenant_name})
        if self.last_api_call and round((timezone.now() - self.last_api_call).total_seconds()/60) < 5:
            logger.warning(f"Vadesecure API: Canceled API calls. Called at 4min 59s and 999ms intervals.",
                           extra={'tenant': self.tenant_name})
            return

        for endpoint in self.ENDPOINTS:
            logger.debug(f"Vadesecure API: fetching {endpoint}.",
                         extra={'tenant': self.tenant_name})


            # Init the payload
            payload = {
                'pageSize': 100, # Mandatory
                'startDate': since,
                'endDate': to
            }

            # We need to wait 5min between each call of GETREPORT

            if endpoint == self.GETREPORT:
                del payload["endDate"]
                for stream in ["inbound", "outbound"]:
                    payload.update({
                        "streamType": stream,
                        "period": period_payload
                    })
                    logs_endpoints += self.fetch_endpoint(endpoint, to, since, payload)
            else:
                logs = self.fetch_endpoint(endpoint, to, since, payload)
                logger.warning(json.dumps(logs), extra={'tenant': self.tenant_name})
                logs_endpoints += logs

        if self.isTest:
            return logs_endpoints
        else:
            self.write_to_file(logs_endpoints)

            # Writting may take a while, so refresh token in Redis
            self.update_lock()

            # increment by 1ms to avoid repeating a line if its timestamp happens to be the exact timestamp 'to'
            self.frontend.last_api_call = to_tz + timedelta(milliseconds=1)
            self.frontend.save()

        logger.info("Vadesecure API: parser ending.", extra={'tenant': self.tenant_name})


    def test(self):
        self.isTest = True
        logger.debug(f"Vadesecure API: inititating the TEST.", extra={'tenant': self.tenant_name})
        try:
            result = self.execute()

            return {
                "status": True,
                "data": result
            }
        except Exception as e:
            logger.exception(e, extra={'tenant': self.tenant_name})
            return {
                "status": False,
                "error": str(e)
            }
