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
__doc__ = 'Log Viewer model'

from darwin.defender_policy import models as policy_models
from system.users.models import User
from django.conf import settings
from djongo import models
import logging
import re

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')

# Extern modules imports

# Required exceptions imports

JINJA_PATH = "/home/vlt-os/vulture_os/darwin/log_viewer/config/"
JINJA_SPOE_TEMPLATE = "haproxy_spoe_defender.conf"
JINJA_BACKEND_TEMPLATE = "haproxy_backend_defender.conf"

DEFENDER_PATH = "/usr/local/etc/defender.d"
DEFENDER_OWNER = "vlt-os:vlt-web"
DEFENDER_PERMS = "644"


class LogViewerConfiguration(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    type_logs = models.TextField()
    displayed_columns = models.JSONField()
    nb_lines = models.IntegerField(default=25)
    font_size = models.IntegerField(default=12)

    class Meta:
        unique_together = ('user', 'type_logs')

    def to_template(self):
        return {
            'pk': str(self.pk),
            'type_logs': self.type_logs,
            'displayed_columns': self.displayed_columns,
            'nb_lines': self.nb_lines,
            'font_size': self.font_size
        }


class LogViewerSearches(models.Model):
    user = models.ForeignKey(User, on_delete=models.CASCADE)
    type_logs = models.TextField()
    name = models.TextField()
    search = models.JSONField()

    def to_template(self):
        return {
            'pk': str(self.pk),
            'type_logs': self.type_logs,
            'name': self.name,
            'search': self.search
        }


class DefenderRule(models.Model):
    zone = models.TextField()
    ids = models.JSONField(models.IntegerField, default=[])
    key = models.TextField()
    value = models.TextField()
    url = models.TextField()
    matched_type = models.TextField()

    @staticmethod
    def is_regex(expr):
        return isinstance(expr, str) and ((expr.startswith("r(") and expr.endswith(")")) or expr == "*")

    @staticmethod
    def get_regex_value(expr):
        if expr == "*":
            return expr

        return expr[2:-1]

    @staticmethod
    def regexify(expr):
        if not expr:
            return ''

        return re.escape(expr)

    def to_dict(self):
        return {
            "id": self.id,
            "zone": self.zone,
            "ids": self.ids,
            "key": self.key,
            "value": self.value,
            "url": self.url,
            "matched_type": self.matched_type
        }

    def generate_rule(self):
        if len(self.ids) <= 0:
            return ''

        is_url_regex = self.url and self.is_regex(self.url)
        is_matched_type_regex = self.is_regex(self.key)

        if self.url:
            if is_matched_type_regex or is_url_regex:
                url_suffix = '_X'

                if is_url_regex:
                    url = self.get_regex_value(self.url)
                else:
                    url = self.regexify(self.url)
            else:
                url_suffix = ''
                url = self.url if self.url is not None else ''

            url_str = '$URL{url_suffix}:{url}|'.format(url_suffix=url_suffix, url=url)

        else:
            url_str = ''

        zone_str = self.zone.upper()
        matched_value_suffix = ''
        matched_type_suffix = ''
        matched_value = ''

        if zone_str.startswith('HEADERS'):
            zone_list = self.zone.split(':')
            expr = zone_list[1]

            if self.is_regex(expr):
                expr = self.get_regex_value(expr)

            zone_str = '$HEADERS_VAR:{}'.format(expr)
            mz_str = 'mz:{url_str}{zone_str}'.format(url_str=url_str, zone_str=zone_str)

        else:
            if zone_str not in ['URL']:
                zone_str = '{zone_str}_VAR'.format(zone_str=zone_str)

            mz_str = 'mz:{url_str}{zone_str}'.format(url_str=url_str, zone_str=zone_str)

            if self.matched_type == 'key':
                matched_type_suffix = '|NAME'

            if is_matched_type_regex or is_url_regex:
                matched_value_suffix = '_X'

                if is_matched_type_regex:
                    regex_value = self.get_regex_value(self.key)
                    matched_value = regex_value if regex_value is not None else ''

                else:
                    matched_value = self.regexify(self.key)

            else:
                matched_value_suffix = ''
                matched_value = self.key if self.key is not None else ''

            if matched_value:
                matched_value = ':{}'.format(matched_value)

        return 'BasicRule wl:{rule_ids} "{mz_str}{matched_value_suffix}{matched_value}{matched_type_suffix}";'.format(
            rule_ids=','.join([str(rule_id) for rule_id in self.ids]),
            mz_str=mz_str,
            matched_value=matched_value,
            matched_value_suffix=matched_value_suffix,
            matched_type_suffix=matched_type_suffix
        )


class DefenderRuleset(models.Model):
    name = models.TextField(unique=True)
    rules = models.ArrayReferenceField(
        to=DefenderRule,
        on_delete=models.CASCADE,
    )
    raw_rules = models.TextField()

    @staticmethod
    def str_attrs():
        """ List of attributes required by __str__ method """
        return ['name']

    def __str__(self):
        return "Defender ruleset '{}'".format(self.name)

    def to_dict(self):
        rule_descr_list = []

        for rule in self.rules.all():
            rule_descr_list.append(rule.to_dict())

        return {
            "id": self.id,
            "name": self.name,
            "rules": rule_descr_list,
            "raw_rules": self.raw_rules
        }

    def to_html_template(self):
        """ Returns needed attributes for html rendering """
        return {
            'id': str(self.pk),
            'name': self.name,
            'raw_rules': self.raw_rules,
            'used_by': ", ".join([
                defender_policy.name for defender_policy in policy_models.DefenderPolicy.objects.filter(
                    defender_ruleset=self
                )
            ]),
        }


class DefenderProcessRuleJob(models.Model):
    job_id = models.TextField(unique=True)
    is_done = models.BooleanField(default=False)
    expiration_date = models.DateTimeField(auto_now_add=True)

    objects = models.DjongoManager()

    def __init__(self, *args, ** kwargs):
        DefenderProcessRuleJob.objects._client.ensure_index('expiration_date', expireAfterSeconds=10 * 60)
        super(DefenderProcessRuleJob, self).__init__(*args, **kwargs)

    def to_dict(self):
        return {
            "job_id": self.job_id,
            "is_done": self.is_done,
            "expiration_date": self.expiration_date
        }


class DefenderProcessRule(models.Model):
    job_id = models.TextField()
    expiration_date = models.DateTimeField(auto_now_add=True)
    rule_id = models.IntegerField()
    rule_key = models.TextField(default="")
    data = models.JSONField(default={})

    objects = models.DjongoManager()

    def __init__(self, *args, ** kwargs):
        DefenderProcessRule.objects._client.ensure_index('expiration_date', expireAfterSeconds=10 * 60)
        super(DefenderProcessRule, self).__init__(*args, **kwargs)

    def to_dict(self):
        return {
            "job_id": self.job_id,
            "expiration_date": self.expiration_date,
            "rule_id": self.rule_id,
            "rule_key": self.rule_key,
            "data": self.data
        }
