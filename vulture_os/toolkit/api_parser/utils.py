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
from toolkit.api_parser.akamai.akamai import AkamaiParser
from toolkit.api_parser.aws_bucket.aws_bucket import AWSBucketParser
from toolkit.api_parser.defender.defender import DefenderParser
from toolkit.api_parser.forcepoint.forcepoint import ForcepointParser
from toolkit.api_parser.imperva.imperva import ImpervaParser
from toolkit.api_parser.office365.office365 import Office365Parser
from toolkit.api_parser.symantec.symantec import SymantecParser
from toolkit.api_parser.reachfive.reachfive import ReachFiveParser
from toolkit.api_parser.mongodb.mongodb import MongoDBParser
from toolkit.api_parser.defender_atp.defender_atp import DefenderATPParser
from toolkit.api_parser.cortex_xdr.cortex_xdr import CortexXDRParser
from toolkit.api_parser.cybereason.cybereason import CybereasonParser
from toolkit.api_parser.cisco_meraki.cisco_meraki import CiscoMerakiParser
from toolkit.api_parser.proofpoint_tap.proofpoint_tap import ProofpointTAPParser
from toolkit.api_parser.sentinel_one.sentinel_one import SentinelOneParser
from toolkit.api_parser.carbon_black.carbon_black import CarbonBlackParser
from toolkit.api_parser.netskope.netskope import NetskopeParser
from toolkit.api_parser.rapid7_idr.rapid7_idr import Rapid7IDRParser
from toolkit.api_parser.harfanglab.harfanglab import HarfangLabParser
from toolkit.api_parser.vadesecure.vadesecure import VadesecureParser
from toolkit.api_parser.crowdstrike.crowdstrike import CrowdstrikeParser
from toolkit.api_parser.vadesecure_o365.vadesecure_o365 import VadesecureO365Parser
from toolkit.api_parser.nozomi_probe.nozomi_probe import NozomiProbeParser
from toolkit.api_parser.blackberry_cylance.blackberry_cylance import BlackberryCylanceParser
from toolkit.api_parser.ms_sentinel.ms_sentinel import MSSentinelParser
from toolkit.api_parser.proofpoint_pod.proofpoint_pod import ProofpointPodParser
from toolkit.api_parser.waf_cloudflare.waf_cloudflare import WAFCloudflareParser
from toolkit.api_parser.gsuite_alertcenter.gsuite_alertcenter import GsuiteAlertcenterParser
from toolkit.api_parser.sophos_cloud.sophos_cloud import SophosCloudParser
from toolkit.api_parser.trendmicro_worryfree.trendmicro_worryfree import TrendmicroWorryfreeParser
from toolkit.api_parser.safenet.safenet import SafenetParser
from toolkit.api_parser.proofpoint_casb.proofpoint_casb import ProofpointCASBParser
from toolkit.api_parser.proofpoint_trap.proofpoint_trap import ProofpointTRAPParser
from toolkit.api_parser.waf_cloud_protector.waf_cloud_protector import WAFCloudProtectorParser
from toolkit.api_parser.trendmicro_visionone.trendmicro_visionone import TrendmicroVisiononeParser
from toolkit.api_parser.cisco_duo.cisco_duo import CiscoDuoParser
from toolkit.api_parser.sentinel_one_mobile.sentinel_one_mobile import SentinelOneMobileParser
from toolkit.api_parser.csc_domainmanager.csc_domainmanager import CscDomainManagerParser
from toolkit.api_parser.retarus.retarus import RetarusParser
from toolkit.api_parser.vectra.vectra import VectraParser
from toolkit.api_parser.apex.apex import ApexParser
from toolkit.api_parser.signalsciences_ngwaf.signalsciences_ngwaf import SignalSciencesNgwafParser
from toolkit.api_parser.gatewatcher_alerts.gatewatcher_alerts import GatewatcherAlertsParser
from toolkit.api_parser.cisco_umbrella.cisco_umbrella import CiscoUmbrellaParser
from toolkit.api_parser.waf_barracuda.waf_barracuda import WAFBarracudaParser
from toolkit.api_parser.beyondtrust_pra.beyondtrust_pra import BeyondtrustPRAParser
from toolkit.api_parser.lockself.lockself import LockselfParser
from toolkit.api_parser.cisco_umbrella_managed_org.cisco_umbrella_managed_org import CiscoUmbrellaManagedOrgParser
from toolkit.api_parser.sentinel_one_singularity_mobile.sentinel_one_singularity_mobile import SentinelOneSingularityMobileParser
from toolkit.api_parser.catonetworks.catonetworks import CatonetworksParser
from toolkit.api_parser.infoblox_threat_defense.infoblox_threat_defense import InfobloxThreatDefenseParser
from toolkit.api_parser.beyondtrust_reportings.beyondtrust_reportings import BeyondtrustReportingsParser
from toolkit.api_parser.varonis.varonis import VaronisParser
from toolkit.api_parser.armis_centrix.armis_centrix import ArmisCentrixParser
from toolkit.api_parser.perception_point_x_ray.perception_point_x_ray import PerceptionPointXRayParser
from toolkit.api_parser.extrahop.extrahop import ExtrahopParser
from toolkit.api_parser.hornetsecurity.hornetsecurity import HornetSecurityParser
from toolkit.api_parser.sentinel_one_identity_graph.sentinel_one_identity_graph import SentinelOneIdentityGraphParser
from toolkit.api_parser.ubika.ubika import UbikaParser

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


PARSER_LIST = {
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
    "defender": DefenderParser,
    "crowdstrike": CrowdstrikeParser,
    "vadesecure_o365": VadesecureO365Parser,
    "nozomi_probe": NozomiProbeParser,
    "blackberry_cylance": BlackberryCylanceParser,
    "ms_sentinel": MSSentinelParser,
    "proofpoint_pod": ProofpointPodParser,
    "waf_cloudflare": WAFCloudflareParser,
    "gsuite_alertcenter": GsuiteAlertcenterParser,
    "sophos_cloud": SophosCloudParser,
    "trendmicro_worryfree": TrendmicroWorryfreeParser,
    "safenet": SafenetParser,
    "proofpoint_casb": ProofpointCASBParser,
    "proofpoint_trap": ProofpointTRAPParser,
    "waf_cloud_protector": WAFCloudProtectorParser,
    "trendmicro_visionone": TrendmicroVisiononeParser,
    "cisco_duo": CiscoDuoParser,
    "sentinel_one_mobile": SentinelOneMobileParser,
    "csc_domainmanager": CscDomainManagerParser,
    "retarus": RetarusParser,
    "vectra": VectraParser,
    "apex": ApexParser,
    "signalsciences_ngwaf": SignalSciencesNgwafParser,
    "gatewatcher_alerts": GatewatcherAlertsParser,
    "cisco_umbrella": CiscoUmbrellaParser,
    "waf_barracuda": WAFBarracudaParser,
    "beyondtrust_pra": BeyondtrustPRAParser,
    "lockself": LockselfParser,
    "cisco_umbrella_managed_org": CiscoUmbrellaManagedOrgParser,
    "sentinel_one_singularity_mobile": SentinelOneSingularityMobileParser,
    "catonetworks": CatonetworksParser,
    "infoblox_threat_defense": InfobloxThreatDefenseParser,
    "beyondtrust_reportings": BeyondtrustReportingsParser,
    "varonis": VaronisParser,
    "armis_centrix": ArmisCentrixParser,
    "perception_point_x_ray": PerceptionPointXRayParser,
    "extrahop": ExtrahopParser,
    "hornetsecurity": HornetSecurityParser,
    "ubika": UbikaParser,
    "sentinel_one_identity_graph": SentinelOneIdentityGraphParser
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
