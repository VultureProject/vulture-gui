#!/home/vlt-os/env/bin/python
"""This file is part of Vulture 3.

Vulture 3 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Vulture 3 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Vulture 3.  If not, see http://www.gnu.org/licenses/.
"""

__author__ = "Olivier de Régis"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Log Viewer view'


import datetime
import errno
import ipaddress
import json
import logging
import os
import re
import requests
import shodan
import tldextract

from darwin.log_viewer import const
from django.conf import settings
from django.utils.translation import ugettext as _
from requests.exceptions import ConnectionError
from system.config.models import Config
from toolkit.mongodb.mongo_base import MongoBase
from toolkit.network.network import get_proxy
from urllib import parse

from daemons.reconcile import MONGO_COLLECTION as DARWIN_MONGO_COLLECTION

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


class LogViewerMongo:

    COLLECTIONS_NAME = {
        'pf': 'pf',
        'internal': 'internal',
        'access': 'haproxy',
        'access_tcp': 'haproxy_tcp',
        'impcap': 'impcap',
        'darwin': DARWIN_MONGO_COLLECTION,
        'message_queue': 'system_messagequeue'
    }

    TIME_FIELD = {
        'pf': 'time',
        'access': 'time',
        'access_tcp': 'time',
        'internal': 'timestamp',
        'impcap': 'time',
        'darwin': 'time',
        'message_queue': 'date_add'
    }

    TYPE_SORTING = {
        'asc': 1,
        'desc': -1
    }

    def __init__(self, params):
        super().__init__()

        self.type_logs = params['type_logs']
        self.rules = params['rules']
        self.frontend_name = params.get('frontend_name')
        self.frontend = params.get('frontend')
        self.columns = params.get('columns')

        self.start = params.get('start')
        self.length = params.get('length')

        self.sorting = "time"
        self.type_sorting = 1
        if self.columns:
            self.sorting = self.columns[params['sorting']]
            self.type_sorting = self.TYPE_SORTING[params['type_sorting']]

        self.startDate = datetime.datetime.strptime(
            params['startDate'],
            "%Y-%m-%dT%H:%M:%S%z"
        )

        self.endDate = datetime.datetime.strptime(
            params['endDate'],
            "%Y-%m-%dT%H:%M:%S%z"
        )

        self.time_field = self.TIME_FIELD[self.type_logs]

        type_logs = self.type_logs
        if self.frontend:
            if self.frontend.mode == 'tcp':
                type_logs += "_" + self.frontend.mode

        if type_logs == "message_queue":
            self.DATABASE = const.MESSAGE_QUEUE_DATABASE
        else:
            self.DATABASE = const.LOGS_DATABASE

        self.COLLECTION = self.COLLECTIONS_NAME[type_logs]
        self.client = MongoBase()

    def _prepare_search(self):
        startDate = self.startDate
        endDate = self.endDate

        query = {
            self.time_field: {
                '$gte': startDate,
                '$lte': endDate
            }
        }

        if self.frontend_name:
            query.update({'frontend_name': self.frontend_name})

        if self.rules and (len(self.rules.get('$and', [])) or len(self.rules.get('$or', []))):
            query.update(self.rules)

        logger.debug(query)
        return query

    def search(self):
        self.query = self._prepare_search()

        nb_res, results = self.client.execute_request(
            database=self.DATABASE,
            collection=self.COLLECTION,
            query=self.query,
            start=self.start,
            length=self.length,
            sorting=self.sorting,
            type_sorting=self.type_sorting
        )

        data = []
        for i, res in enumerate(results):
            res['_id'] = str(res['_id'])

            if 'timestamp_app' in res.keys():
                res['timestamp_app'] = datetime.datetime.utcfromtimestamp(float(res['timestamp_app']))

            if 'unix_timestamp' in res.keys():
                res['unix_timestamp'] = datetime.datetime.utcfromtimestamp(float(res['unix_timestamp']))

            # FIXME Temporary darwin details aggregation
            for darwin_filter_details in ['yara_match', 'anomaly', 'connection', 'domain', 'host']:
                if darwin_filter_details in res.keys():
                    res['details'] = res[darwin_filter_details]
                    break

            # FIXME Temporary aggregation for DGA certitude
            if "dga_prob" in res.keys():
                res['certitude'] = res['dga_prob']

            for c in self.columns:
                if not res.get(c):
                    res[c] = ""

            data.append(res)

        return nb_res, data

    def graph(self):
        self.query = self._prepare_search()

        match = {
            "$match": self.query
        }

        src_ip = "$" + const.MAPPING_GRAPH[self.type_logs]['src_ip']
        dst_ip = "$" + const.MAPPING_GRAPH[self.type_logs]['dst_ip']

        agg = {
            "$group": {
                "_id": {
                    "src_ip": src_ip,
                    "dst_ip": dst_ip,
                },
                "count": {'$sum': 1}
            }
        }

        tmp_data = self.client.execute_aggregation(
            database=self.DATABASE,
            collection=self.COLLECTION,
            agg=[match, agg]
        )

        data = []
        for d in tmp_data:
            try:
                data.append({
                    'src_ip': d['_id']['src_ip'],
                    'dst_ip': d['_id']['dst_ip'],
                    'count': d['count'],
                })
            except KeyError:
                pass

        return data

    def timeline(self):
        delta = self.endDate - self.startDate
        nb_min = delta.seconds / 60
        nb_hour = nb_min / 60

        logger.debug("days: {}".format(delta.days))
        logger.debug("hour: {}".format(nb_hour))
        logger.debug("min: {}".format(nb_min))
        logger.debug("seconds: {}".format(delta.seconds))

        match = {
            "$match": self.query
        }

        agg = {
            '$group': {
                "_id": {
                    'year': {'$year': '${}'.format(self.time_field)},
                    'month': {'$month': '${}'.format(self.time_field)},
                    'dayOfMonth': {'$dayOfMonth': '${}'.format(self.time_field)}
                },
                "count": {"$sum": 1}
            }
        }

        if delta.days > 1:
            agg_by = "day"
        else:
            if nb_min > 1000:
                agg_by = "hour"
                agg['$group']['_id']['hour'] = {'$hour': '${}'.format(self.time_field)}
            else:
                agg_by = "minute"
                agg['$group']['_id']['hour'] = {'$hour': '${}'.format(self.time_field)}
                agg['$group']['_id']['minute'] = {'$minute': '${}'.format(self.time_field)}

        tmp_data = self.client.execute_aggregation(
            database=self.DATABASE,
            collection=self.COLLECTION,
            agg=[match, agg]
        )

        data = {}
        for tmp in tmp_data:
            tmp = dict(tmp)

            if agg_by == "day":
                date = "{}-{}-{}".format(
                    tmp['_id']['year'],
                    tmp['_id']['month'],
                    tmp['_id']['dayOfMonth'],
                )

                date = datetime.datetime.strptime(date, "%Y-%m-%d").strftime('%Y-%m-%dT%H:%M')
            elif agg_by == "hour":
                date = "{}-{}-{} {}".format(
                    tmp['_id']['year'],
                    tmp['_id']['month'],
                    tmp['_id']['dayOfMonth'],
                    tmp['_id']['hour'],
                )
                date = datetime.datetime.strptime(date, "%Y-%m-%d %H").strftime('%Y-%m-%dT%H:%M')
            elif agg_by == "minute":
                date = "{}-{}-{} {}:{}".format(
                    tmp['_id']['year'],
                    tmp['_id']['month'],
                    tmp['_id']['dayOfMonth'],
                    tmp['_id']['hour'],
                    tmp['_id']['minute']
                )
                date = datetime.datetime.strptime(date, "%Y-%m-%d %H:%M").strftime('%Y-%m-%dT%H:%M')

            data[date] = tmp['count']

        return fill_data(self.startDate, self.endDate, data, agg_by), agg_by


def fill_data(start_date, end_date, tmp_data, agg_by):
    data = {}

    if agg_by == "day":
        strftime = "%Y-%m-%dT00:00"
    elif agg_by == "hour":
        strftime = "%Y-%m-%dT%H:00"
    elif agg_by == "minute":
        strftime = "%Y-%m-%dT%H:%M"

    while start_date <= end_date:
        try:
            sum_alert = tmp_data[start_date.strftime(strftime)]
        except KeyError:
            sum_alert = 0

        data[start_date.isoformat()] = sum_alert
        if agg_by == "day":
            start_date += datetime.timedelta(days=1)
        elif agg_by == "hour":
            start_date += datetime.timedelta(hours=1)
        elif agg_by == "minute":
            start_date += datetime.timedelta(seconds=60)

    return data


def check_enrich_info(data):
    # IPv4
    ips = re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", data)
    for ip in set(ips):
        data = data.replace(ip, "<a class='enrich_info' data-column='ip' data-info='{ip}'>{ip}</a>".format(ip=ip))

    # IPv6
    ips = re.findall(r"\A(?:[A-F0-9]{1,4}:){7}[A-F0-9]{1,4}\Z", data)
    for ip in set(ips):
        data = data.replace(ip, "<a class='enrich_info' data-column='ip' data-info='{ip}'>{ip}</a>".format(ip=ip))

    return data


class Predator:
    def __init__(self, column, info):
        self.column = column
        self.info = info

        config = Config.objects.get()

        self.predator_api_key = config.predator_apikey
        self.shodan_api_key = config.shodan_apikey
        self.predator_host = settings.PREDATOR_HOST
        self.predator_version = settings.PREDATOR_VERSION

    def __execute_query(self, uri, data={}):
        uri = "{}{}{}".format(self.predator_host, self.predator_version, uri)

        try:
            logger.info('[PREDATOR] Calling {}'.format(uri))

            r = requests.get(
                uri,
                data=data,
                proxies=get_proxy(),
                headers={
                    'Authorization': self.predator_api_key
                }
            )

            if r.status_code != 200:
                if settings.DEV_MODE:
                    return False, r.text

                return False, _("An error has occurred")

            return True, r.json()

        except json.decoder.JSONDecodeError:
            logger.error('Error JSON while calling {}'.format(uri))
            return False, _('An error has occurred')

        except ConnectionError as e:
            logger.critical(e, exc_info=1)
            return False, _("Unable to contact API")

        except Exception as e:
            if settings.DEV_MODE:
                raise

            logger.critical(e, exc_info=1)
            return False, _('An error has occurred')

    def submit_ip(self):
        uri = "{}{}{}".format(self.predator_host, self.predator_version, "/reputation/vulture/{}/".format(self.info))

        r = requests.put(
            uri,
            proxies=get_proxy(),
            headers={
                'Authorization': self.predator_api_key
            }
        )

        if r.status_code != 200:
            if settings.DEV_MODE:
                return False, r.text

            return False, _('An error has occurred')

        return True, r.json()

    def execute_shodan_request(self):
        if not self.shodan_api_key:
            return False

        api = shodan.Shodan(self.shodan_api_key)

        try:
            infos = api.host(self.info)
            tmp = json.dumps(infos)
            tmp = tmp.replace('_shodan', 'shodan_info')
            # tmp = tmp.replace('\\r\\n', '<br/>')
            # tmp = tmp.replace('\\n', '<br/>')

            tmp = check_enrich_info(tmp)

            infos = json.loads(tmp)

        except shodan.exception.APIError:
            return False
        except Exception:
            raise
            return False

        if infos == "Invalid IP":
            return False

        return infos

    def fetch_reputation(self):

        ip = ipaddress.ip_address(self.info)

        if isinstance(ip, ipaddress.IPv4Address):
            reputations = {}

            status, reputation = self.__execute_query("/reputation/firehol_level1/{}".format(self.info))
            if status:
                reputations['firehol_level1'] = reputation['reputation_info']
            else:
                reputations['firehol_level1'] = False

            status, reputation_webscanner = self.__execute_query("/reputation/webscanner/{}".format(self.info))
            if status:
                reputations['webscanner'] = reputation_webscanner['reputation_info']
            else:
                reputations['webscanner'] = False

            status, reputation_vulture = self.__execute_query("/reputation/vulture/{}".format(self.info))
            if status:
                reputations['vulture'] = reputation_vulture['reputation_info']
            else:
                reputations['vulture'] = False

            return reputations

        elif isinstance(ip, ipaddress.IPv6Address):
            status, reputation = self.__execute_query("/reputation/dropv6/{}".format(self.info))
            if not status:
                return {'dropv6': False}

            return {
                'dropv6': reputation['reputation_info']
            }

    def fetch_reputation_blacklisted(self):
        status, blacklisted = self.__execute_query("/host/drop_hosts/{}".format(self.info))

        if not status:
            return False

        return {
            'blacklisted': "blacklisted" if blacklisted['host_info']['is_blacklisted'] else True
        }

    def fetch_whois(self):
        status, whois = self.__execute_query("/dns_whois/{}".format(self.info))

        if not status:
            return False

        if whois['dns_whois'] == "No result" or not whois['success']:
            return False

        return whois['dns_whois']

    def fetch_typo(self):
        info = tldextract.extract(self.info)
        info = "{}.{}".format(info.domain, info.suffix)

        status, typo = self.__execute_query("/dns_typo/{}".format(info))
        if not status:
            return False

        data = {}

        if typo['dns_typo'] == "Error during API Call":
            return False

        for k, v in typo['dns_typo'].items():
            data[k] = []

            for ip in v[1]:
                data[k].append(ip)

        return data

    def fetch_cve(self):
        status, cve = self.__execute_query("/cve/{}".format(self.info))

        if not status:
            return False

        return cve['cve_query']

    def _enrich_ip(self):
        return {
            'status': True,
            'reputation': self.fetch_reputation(),
            'shodan': self.execute_shodan_request()
        }

    def _enrich_host(self):
        return {
            'status': True,
            'whois': self.fetch_whois(),
            'typo': self.fetch_typo(),
            'blacklisted': self.fetch_reputation_blacklisted()
        }

    def enrich_cve(self):
        return {
            "status": True,
            "cve": self.fetch_cve()
        }

    def fetch_info(self):
        if self.column == "cve":
            return self.enrich_cve()

        try:
            ip = ipaddress.ip_address(self.info)
            if ip.is_private:
                return {
                    'status': False,
                    'error': _("Private IP Address")
                }

            data = self._enrich_ip()
            return data
        except ValueError:
            return self._enrich_host()


class ModDefenderRulesFetcher:
    # ATTRIBUTES
    # rules: List(rules)
    # Theses rules can be called by their id and contains some usefull data
    # rule: {id: {'pattern':<ReGex>, 'activated':<bool>, 'locations':<str>, 'score':{score_type: <int>}}}
    rules = None
    # zones: List(<str>)
    # Element from a HTTP request which will used as dictionaries key value
    zones = None
    # zones: List(<str>)
    # Element from a HTTP request which will used as string
    raw_zones = None
    # zones: List(<str>)
    # Selected header keys
    header_keys = None
    # <int>
    # Minimum score for a rule to get noticed
    threshold = None
    # <str>
    # Path to the Naxsi configuration file
    conf_file_path = None

    def _load_config_file(self):
        """  Load rules from Naxsi config file """

        def rreplace(s, old, new, occurrence):
            """ Replace element from the end a string"""
            li = s.rsplit(old, occurrence)
            return new.join(li)

        new_rules = {}
        self.zones = []
        with open(os.path.abspath(self.conf_file_path)) as fp:
            line = fp.readline()
            key_words = ["str:", "rx:", "mz:", "id:", "s:"]
            while line:
                # Get main data
                data = line.split(" ")
                if data[0] == "MainRule":
                    # Keep only fileds in key_words
                    tmp = []
                    for i in data:
                        for j in key_words:
                            if j in i:
                                tmp.append(i)
                    data = tmp

                    # Clear data and format it
                    data_rule = {}
                    for i in data:
                        i = i.split(":", 1)
                        i[0] = i[0].replace("\"", "", 1)
                        if i[0] == 'str':
                            # Escaped pattern (from string)
                            data_rule['pattern'] = re.escape(rreplace(i[1], "\"", "", 1))
                        elif i[0] == 'rx':
                            # ReGex pattern (from regex)
                            data_rule['pattern'] = rreplace(i[1], "\"", "", 1)
                        elif i[0] == 'mz':
                            # Zones
                            data_rule['locations'] = rreplace(":".join(i[1:]), "\"", "", 1).replace("$", "").replace(
                                "_VAR", "")
                            locations = data_rule['locations'].split("|")
                            for zone in locations:
                                # Raw data cases
                                if zone in self.raw_zones:
                                    continue
                                # Header case
                                if "HEADERS" in zone:
                                    self.header_keys = re.split(r'[:,]', zone, flags=re.IGNORECASE)[1:]
                                    zone = "HEADERS"
                                # Else
                                if zone not in self.zones:
                                    self.zones.append(zone)

                        elif i[0] == 'id':
                            # ID rule
                            id_rule = int(re.search(r'\d+', i[1]).group())
                        elif i[0] == 's':
                            # Score
                            score_dict = {}
                            i = [item for sublist in [re.split(r'[:,]', j, flags=re.IGNORECASE) for j in i] for item in
                                 sublist]
                            for j in range(1, len(i) - 1, 2):
                                score_dict[i[j]] = int(rreplace(i[j + 1], "\"", "", 1))
                            data_rule['score'] = score_dict
                        data_rule['activated'] = True

                    # Rule loaded
                    new_rules[id_rule] = data_rule
                line = fp.readline()
        self.rules = new_rules

    def _apply_rules(self, zone, arg_type, key, value, url):
        """ Use ReGex to detect malicious elements """

        element = {
            'zone': zone.lower(),
            'ids': [],
            'matched': arg_type.lower(),
            'key': key,
            'value': value,
            'url': url,
            'score': 0
        }
        # For each valid rule, we use its id
        for id_rule in {i: self.rules[i] for i in self.rules if
                        self.rules[i]['activated'] and zone in self.rules[i]['locations']}:
            # We get the occurrence number from the selected ReGex rule
            occ = len(re.findall(self.rules[id_rule]['pattern'], element[arg_type.lower()]))
            if occ > 0:
                element['ids'].append(id_rule)
                # Score calculus
                for score_type in self.rules[id_rule]['score']:
                    element['score'] += self.rules[id_rule]['score'][score_type] * occ

        # URL case
        if zone == "URL":
            element['key'] = None
            element['value'] = None

        # logger.debug('Processed score for rule {{zone: {zone}, ids: {ids}, matched: {matched}, key: {key}, value: {value}, url: {url}, score: {score}}}'.format(
        #     zone=element['zone'], ids=element['ids'], matched=element['matched'], key=element['key'], value=element['value'], url=element['url'], score=element['score']
        # ))

        # Return element only if score is above the threshold
        if element['score'] >= self.threshold:
            return element

        return None

    def _get_response(self, request):
        """ Get a dict of malicious parameters from a request """

        response = []
        cookie_pattern = re.compile(r'\s*=\s*')

        def add_response(response, zone, arg_type, key, value, url):
            """ Add response to the main list """
            resp = self._apply_rules(zone, arg_type, key, value, url)
            if resp is not None:
                response.append(resp)

        # Raw content cases
        for zone in [i for i in self.raw_zones if request.get(i, {})]:
            if request.get(zone, "") is not None:
                add_response(response, zone, "VALUE", zone, request[zone], request['URL'])

        # Dict cases
        for zone in [i for i in self.zones if request.get(i, {})]:
            for k in request[zone]:
                # Header case (dirty way)
                if zone == "HEADERS" and k not in self.header_keys:
                    continue
                # Header:Cookie (xxdirty way)
                if zone == "HEADERS":
                    # For each Cookie, evaluate its key and value
                    cookie_dict = {}

                    for cookie in re.split(r'\s*;\s*', request[zone][k]):
                        try:
                            cookie_descr = cookie_pattern.split(cookie)
                            cookie_dict[cookie_descr[0]] = cookie_descr[1]
                        except IndexError:
                            logger.debug("Bad cookie given: \"{}\"".format(cookie))

                    for cookie_key in cookie_dict:
                        for arg_type in ["KEY", "VALUE"]:
                            add_response(response, str(zone) + ":" + str(k), arg_type, cookie_key,
                                         cookie_dict[cookie_key], request['URL'])
                    continue

                for arg_type in ["KEY", "VALUE"]:
                    add_response(response, zone, arg_type, k, request[zone][k], request['URL'])

        return response

    def _parse_request(self, request):
        """ URL parsing to get arguments, headers and body """

        # Set URL as raw data (See _get_response()) by default
        self.raw_zones = ["URL"]

        headers_pattern = re.compile(r'\s*:\s*')
        new_request_headers = {}

        for header_name in re.split(r'\s*\r\n\s*', request["HEADERS"]):
            header_descr = headers_pattern.split(header_name)

            try:
                new_request_headers[header_descr[0]] = header_descr[1]
            except IndexError:
                continue

        # Build request with parsed elements
        new_request = {}
        data_parse = parse.urlsplit(request["URL"])
        new_request["URL"] = data_parse.path
        new_request["ARGS"] = dict(parse.parse_qsl(data_parse.query))
        new_request["HEADERS"] = new_request_headers
        http_method = request["METHOD"]

        if http_method in ['POST', 'PUT', 'PATCH']:
            # Content-type defines the body's format
            try:
                ct = new_request['HEADERS']['Content-Type']
            except KeyError:
                raise Exception('No Content-Type given')

            if ct == 'application/x-www-form-urlencoded':
                lst = request["BODY"].split('&')
                tmp_dict = {}
                for i in lst:
                    pair = i.split('=')
                    tmp_dict[pair[0]] = pair[1]
                new_request["BODY"] = tmp_dict
            # Multipart
            elif ct == 'multipart/form-data':
                self.raw_zones.append("BODY")
                new_request["BODY"] = request["BODY"]
            # Json
            elif ct == 'application/json':
                new_request["BODY"] = json.loads(request["BODY"])
            else:
                error = "Bad Content-Type given: \"{}\"".format(ct)
                logger.error(error)
                raise Exception(error)

        return new_request

    def _disable_rules(self, ids):
        """ Disable rules from id list """

        for id_rule in ids:
            self.rules[id_rule]['activated'] = False

    def get_results(self, req, disabled_rules_id=[]):
        """ Returns all results from a request """

        # Respect the order
        # 1 - Parse the request to set global values
        req = self._parse_request(req)
        # 2 - Load the configuration file
        self._load_config_file()
        # 3 - Disable selected rules
        self._disable_rules(disabled_rules_id)
        # 4 - Get the results
        res = self._get_response(req)
        return res

    def __init__(self, conf_file_path='config.txt', threshold=12):
        """
        conf_file_path: relative path to the configuration file
        threshold: minimum score to notice a malicious element
        """
        try:
            if threshold < 0:
                raise ValueError("Threshold value should be greater or equal than 0")

            if not os.path.isfile(os.path.abspath(conf_file_path)):
                raise FileNotFoundError(
                    errno.ENOENT, os.strerror(errno.ENOENT), conf_file_path
                )
        except ValueError as err:
            logger.error(err)
            raise

        self.conf_file_path = conf_file_path
        self.threshold = threshold
