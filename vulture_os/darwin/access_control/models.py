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
__doc__ = 'Access Control model'

# Django system imports
from django.utils.translation import gettext_lazy as _
from django.conf import settings
from djongo import models
from django.template.loader import render_to_string

from services.haproxy.haproxy import TEST_CONF_PATH
from services.haproxy.haproxy import test_haproxy_conf

from bson import ObjectId
from hashlib import sha1
import logging
import json

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')

NAME_CHOICES = {
    'hdr': [
        "Accept", "Accept-Charset", "Accept-Encoding", "Accept-Language", "Accept-Datetime", "Authorization",
        "Cache-Control", "Connection", "Cookie", "Content-Length", "Content-MD5", "Content-Type", "Date", "DNT",
        "Expect", "From",
        "Front-End-Https", "Host", "If-Match", "If-Modified-Since", "If-None-Match", "If-Range", "If-Unmodified-Since",
        "Max-Forwards", "Origin", "Pragma", "Proxy-Authorization", "Proxy-Connection", "Range", "Referer", "TE",
        "User-Agent",
        "Upgrade", "Via", "Warning", "X-Requested-With", "X-Forwarded-For", "X-Forwarded-Host", "X-Forwarded-Proto",
        "X-Http-Method-Override", "X-ATT-DeviceId", "X-Wap-Profile"
    ],
    'shdr': [
        "Access-Control-Allow-Origin", "Accept-Ranges", "Age",
        "Allow", "Cache-Control", "Connection", "Content-Encoding", "Content-Language", "Content-Length",
        "Content-Location",
        "Content-MD5", "Content-Disposition", "Content-Range", "Content-Type", "Date", "ETag", "Expires",
        "Last-Modified", "Link",
        "Location", "P3P", "Pragma", "Proxy-Authenticate", "Public-Key-Pins", "Refresh", "Retry-After", "Server",
        "Set-Cookie",
        "Status", "Strict-Transport-Security", "Trailer", "Transfer-Encoding", "Upgrade", "Vary", "Via", "Warning",
        "WWW-Authenticate",
        "X-Frame-Options", "X-XSS-Protection", "Content-Security-Policy", "X-Content-Type-Options", "X-Powered-By",
        "X-UA-Compatible"
    ],
    'urlp': [],
    'cook': [],
    'scook': [],
    'http_auth_group': []
}

CRITERION_CHOICES = [
    ["src", "Source IP"],
    ["base", "Base"],
    ["hdr", "Request Header"],
    ["shdr", "Response Header"],
    ["http_auth_group", "Authentication group"],
    ["method", "Method"],
    ["path", "Path"],
    ["url", "URL"],
    ["urlp", "URLP"],
    ["path", "Path"],
    ["cook", "Request Cookie"],
    ["scook", "Response Cookie"],
    ["rdp_cookie", "RDP Cookie"]
]

CONVERTER_CHOICES = [
    ["beg", "Prefix match"],
    ["dir", "Subdir match"],
    ["dom", "Domain match"],
    ["end", "Suffix match"],
    ["hex", "Hex block match"],
    ["int", "Integer match"],
    ["ip", "IP address match"],
    ["len", "Length match"],
    ["reg", "Regex match"],
    ["str", "Exact string match"],
    ["sub", "Substring match"],
    ["found", "Found"]
]

FLAGS_CHOICES = [
    ["-i", "Case insensitive"],
    ["-n", "Forbid DNS resolution"]
]

OPERATOR_CHOICES = [
    ["eq", "Equal"],
    ["ge", "Greater than or Equal"],
    ["gt", "Greater than"],
    ["le", "Lesser than or Equal"],
    ["lt", "Lesser than"]
]

# Jinja template for backends rendering
JINJA_PATH = "/home/vlt-os/vulture_os/darwin/access_control/config"
JINJA_TEST_TEMPLATE = "haproxy_test.conf"


class AccessControl(models.Model):
    _id = models.ObjectIdField(default=ObjectId)

    name = models.SlugField(
        max_length=255,
        verbose_name=_("Friendly name"),
        help_text=_('Friendly name'),
        unique=True
    )

    acls = models.TextField(default="")
    rules = models.JSONField(default=[])

    @staticmethod
    def str_attrs():
        """ List of attributes required by __str__ method """
        return ['name']

    def __str__(self):
        return "ACL '{}'".format(self.name)

    def to_html_template(self):
        """ Returns needed attributes for html rendering """
        return {
            'id': str(self.pk),
            'name': self.name,
            'acls': self.acls,
            'used_by': [str(w) for w in self.workflowacl_set.all()],
            'rules': json.dumps(self.rules)
        }

    def to_template(self):
        return {
            'id': str(self.pk),
            'name': self.name,
            'acls': self.acls,
            'rules': json.dumps(self.rules)
        }

    def test_conf(self):
        """ Write the configuration attribute on disk, in test directory, as {id}.conf.new
            And test the conf with 'haproxy -c'
        :return     True or raise
        """
        """ No need to do API request cause Backends are not relative-to-node objects """
        test_filename = self.get_test_filename()
        conf = self.generate_test_conf()
        # NO Node-specific configuration, we can test-it on local node
        # Backends can not be used, so do not handle the HAProxy "not used" error by setting disabled=True
        test_haproxy_conf(test_filename, conf, disabled=True)
        # open("{}/{}".format(TEST_CONF_PATH, test_filename), "w+").write(conf)

    def get_test_filename(self):
        """ Return test filename for test conf with haproxy
        """
        return "acl_{}.conf".format("test")

    def generate_test_conf(self):
        """ Generate ACL
        """
        # Empty configuration case
        if len(self.rules) <= 0:
            return ""

        rules, tmp_conditions = self.generate_rules()

        conditions = []
        for tmp in tmp_conditions:
            conditions.extend(tmp)

        conditions = " ".join(conditions)
        template = render_to_string("{}/{}".format(JINJA_PATH, JINJA_TEST_TEMPLATE), {
            'conditions': conditions,
            'rules': rules
        })
        return template

    def generate_rules(self):

        def make_criterion(criterion, name):
            """
            Generate a Criterion with a specific parameter
            :param criterion:
            :param name:
            :return:
            """
            if name != "":
                choice = NAME_CHOICES.get(criterion, "")
                if choice != "":
                    return "{}({})".format(criterion, name)
            return "" + criterion

        # Initialization
        acls = []
        acls_name = []
        # For each OR block

        for i, rule in enumerate(self.rules):
            tmp_names = []
            for j, line in enumerate(rule['lines']):

                acl = "{}".format(make_criterion(line['criterion'], line.get('criterion_name')))

                pattern = line.get('pattern', '')
                # ensure quoting in haproxy conf when pattern contains spaces
                if " " in pattern:
                    pattern = '"' + pattern + '"'

                tmp_lst = [line.get('converter', ''),
                           line.get('operator', ''),
                           pattern]
                # Add -m option if a converter is used
                if line.get('converter', '') != "":
                    acl += " -m"

                tmp_lst.insert(1, line.get('flags', ''))
                acl += ''.join(" " + elem if (elem != "") else "" for elem in tmp_lst)

                acl_hash = sha1(acl.encode('utf-8')).hexdigest()
                acl_name = f"{self.name}_{acl_hash}"
                tmp_names.append(acl_name)

                acl = f"acl {acl_name} {acl}"
                if j > 0 or i > 0:
                    acl = f"    {acl}"

                acls.append(acl)

            acls_name.append(tmp_names)

        return "\n".join(acls), acls_name
