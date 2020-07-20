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

__author__ = "Théo BERTIN"
__credits__ = []
__license__ = "GPLv3"
__version__ = "3.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Yara model'

# Django system imports
from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from djongo import models

# Required exceptions imports
from services.exceptions import ServiceTestConfigError, ServiceError
from subprocess import CalledProcessError
from system.exceptions import VultureSystemConfigError

# Extern modules imports
from subprocess import check_output, PIPE
from system.cluster.models import Cluster


# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')

DEFAULT_YARA_MODULES_IMPORT = "import \"pe\"\n" \
                              "import \"elf\"\n" \
                              "import \"math\"\n" \
                              "import \"hash\"\n" \
                              "import \"cuckoo\"\n"

DEFAULT_YARA_CATEGORIES = (
    "malware",
    "Webshells",
    "CVE_Rules",
    "Exploit-Kits"
)


PACKET_INSPECTION_TECHNO = (
    ("yara", "yara"),
)

YARA_CONF_PATH = "/home/darwin/conf/fcontent_inspection"
YARA_RULES_PATH = YARA_CONF_PATH + "/yara-rules"
YARA_TEST_CONF_PATH = "/var/tmp"

DARWIN_PERMS = "640"
DARWIN_OWNERS = "darwin:vlt-conf"


class InspectionRule(models.Model):
    """ Model representing a single rulefile """

    """ Name for the rule """
    name = models.TextField(
        default="Rule_name",
        help_text=_("Friendly name for the inspection rule")
    )

    """ Time of last update """
    last_update = models.DateTimeField(
        auto_now=True
    )

    """ Techno of the rule (yara) """
    techno = models.TextField(
        default=PACKET_INSPECTION_TECHNO[0][0],
        choices=PACKET_INSPECTION_TECHNO,
        help_text=_("Technology used to inspect")
    )

    """ Category of the rule """
    category = models.TextField(
        default="",
        help_text=_("Category of the rule")
    )

    """ Source of the rule """
    source = models.TextField(
        default="custom",
        help_text=_("Source of the rule")
    )

    """ Content of the file """
    content = models.TextField(
        default="",
        help_text=_("Content of the rule")
    )

    def __str__(self):
        return self.name

    def to_dict(self):
        return {
            'id': str(self.id),
            'name': self.name,
            'last_update': self.last_update,
            'techno': self.techno,
            'category': self.category,
            'source': self.source,
            'content': self.content
        }

    def to_html_template(self):
        return {
            'id': str(self.id),
            'name': self.name,
            'last_update': self.last_update.strftime("%d/%m/%Y %H:%M:%S"),
            'techno': self.techno,
            'category': self.category,
            'source': self.source,
            'content': self.content
        }

    def to_template(self):
        return self.to_html_template()

    def generate_content(self):
        return self.content


class InspectionPolicy(models.Model):
    """ Model representing a set of rules for packet inspection """

    """ Friendly name for the policy """
    name = models.TextField(
        unique=True,
        default="Custom Inspection Policy",
        help_text=_("Friendly name for your inspection policy")
    )

    """ Time of last update """
    last_update = models.DateTimeField(
        auto_now=True
    )

    """ Techno of the policy """
    techno = models.TextField(
        default=PACKET_INSPECTION_TECHNO[0][0],
        choices=PACKET_INSPECTION_TECHNO,
        help_text=_("Technology used to inspect")
    )

    description = models.TextField(
        default="",
        help_text=_("Give your policy a description")
    )

    rules = models.ArrayReferenceField(
        InspectionRule,
        null=True,
        blank=False,
        on_delete=models.CASCADE,
        help_text=_("rules in policy")
    )

    compilable = models.TextField(
        default="UNKNOWN"
    )

    compile_status = models.TextField(
        default="",
        help_text=_("yara compilation's result of this policy")
    )

    def __str__(self):
        return self.name

    def to_dict(self):
        return {
            'id': str(self.id),
            'techno': self.techno,
            'name': self.name,
            'last_update': self.last_update,
            'description': self.description,
            'compilable': self.compilable
        }

    def to_html_template(self):
        return {
            'id': str(self.id),
            'techno': self.techno,
            'name': self.name,
            'last_update': self.last_update.strftime("%d/%m/%Y %H:%M:%S"),
            'description': self.description,
            'compilable': self.compilable,
            'compile_status': self.compile_status
        }

    def to_template(self):
        return self.to_html_template()

    def get_full_filename(self):
        return YARA_CONF_PATH + '/' + self.name + "_" + self.last_update.strftime("%Y-%m-%d_%H-%M-00") + ".yar"

    def get_full_test_filename(self):
        return YARA_TEST_CONF_PATH + '/' + self.name + "_" + self.last_update.strftime("%Y-%m-%d_%H-%M-00") + ".yar"

    def generate_content(self):
        content = DEFAULT_YARA_MODULES_IMPORT + '\n'
        for rule in self.rules.all():
            content += rule.content + '\n'
        return content

    """ Save definitive policy file, containing all rules
        This should not be called if the rules have not been tested yet
        typically this is done with 'try_compile' so this function shouldn't be called"""
    def save_policy_file(self):
        params = [self.get_full_filename(), self.generate_content(), DARWIN_OWNERS, DARWIN_PERMS]
        try:
            logger.debug("InspectionPolicy::save_policy_file:: calling api to save inspection policy file")
            Cluster.api_request('system.config.models.write_conf', config=params)
        except Exception as e:
            raise VultureSystemConfigError("InspectionPolicy::save_policy_file:: failure to save inspection policy file")

    def delete_policy_file(self):
        try:
            check_output(['/bin/rm', self.get_full_filename()], stderr=PIPE).decode("utf8")
            return "conf for '{}' successfully deleted.".format(self.get_full_filename())
        except CalledProcessError as e:
            """ Command raise if permission denied or file does not exists """
            stdout = e.stdout.decode('utf8')
            stderr = e.stderr.decode('utf8')
            raise ServiceError("'{}' : {}".format(self.get_full_filename(), (stderr or stdout)), "inspection",
                               "delete inspection policy file")

    def try_compile(self):
        node = Cluster.get_current_node()
        if node:
            node.api_request("toolkit.yara.yara.try_compile_yara_rules", self.id)
