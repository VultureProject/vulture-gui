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
__doc__ = 'Parser URLS'


import logging

from django.conf import settings
from toolkit.api_parser import *


logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


PARSER_LIST = {
    "elasticsearch": ElasticsearchParser,
    "forcepoint": ForcepointParser,
    "aws_bucket": AWSBucketParser,
    "office_365": Office365Parser,
    "symantec": SymantecParser,
    'imperva': ImpervaParser,
    "akamai": AkamaiParser,
    "reachfive": ReachFiveParser,
    "mongodb": MongoDBParser,
    "defender_atp": DefenderATPParser,
    "cortex_xdr": CortexXDRParser,
    "cisco_meraki": CiscoMerakiParser,
    "cybereason": CybereasonParser,
    "proofpoint_tap": ProofpointTAPParser,
    "sentinel_one": SentinelOneParser,
    "carbon_black": CarbonBlackParser,
    "netskope": NetskopeParser,
    "rapid7_idr": Rapid7IDRParser,
    "harfanglab": HarfangLabParser,
    "vadesecure": VadesecureParser,
}


class ParserDoesNotExist(Exception):
    pass


def get_api_parser(parser_name):
    try:
        return PARSER_LIST[parser_name]
    except KeyError:
        raise ParserDoesNotExist("Parser {} does not exist".format(parser_name))


def get_available_api_parser():
    return list(PARSER_LIST.keys())
