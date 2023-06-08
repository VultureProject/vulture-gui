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
__doc__ = 'User Access Control model'

from django.utils.translation import gettext_lazy as _
from django.conf import settings
from django.forms.models import model_to_dict
from djongo import models

import logging
import re
import json


logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


OPERATOR_CHOICES = [
    ["exists", _("Exists")],
    ["not_exists", _("Does not exist")],
    ["equals", _("Equals to")],
    ["not_equals", _("Different from")],
    ["contains", _("Contains")],
    ["no_contains", _("Does not contain")],
    ["starts_with", _("Starts with")],
    ["no_start_with", _("Does not start with")],
    ["ends_with", _("Ends with")],
    ["no_end_with", _("Does not end with")],
    ["regex", _("Regex")],
]


def check_exists(scope, key, value):
    return key in scope

def check_not_exists(scope, key, value):
    return key not in scope

def check_equals(scope, key, value):
    if key not in scope:
        return False
    else:
        return scope[key] == value

def check_not_equals(scope, key, value):
    if key not in scope:
        return False
    else:
        return scope[key] != value

def check_contains(scope, key, value):
    if key not in scope:
        return False
    else:
        return value in scope[key]

def check_no_contains(scope, key, value):
    if key not in scope:
        return False
    else:
        return value not in scope[key]

def check_starts_with(scope, key, value):
    if key not in scope or type(scope[key]) != str:
        return False
    else:
        return scope[key].startswith(value)

def check_no_start_with(scope, key, value):
    if key not in scope or type(scope[key]) != str:
        return False
    else:
        return not scope[key].startswith(value)

def check_ends_with(scope, key, value):
    if key not in scope or type(scope[key]) != str:
        return False
    else:
        return scope[key].endswith(value)

def check_no_end_with(scope, key, value):
    if key not in scope or type(scope[key]) != str:
        return False
    else:
        return not scope[key].endswith(value)

def check_regex(scope, key, value):
    if key not in scope or type(scope[key]) != str:
        return False
    else:
        return re.match(value, scope[key]) != None



OPERATOR_FUNCTION = {
    "exists": check_exists,
    "not_exists": check_not_exists,
    "equals": check_equals,
    "not_equals": check_not_equals,
    "contains": check_contains,
    "no_contains": check_no_contains,
    "starts_with": check_starts_with,
    "no_start_with": check_no_start_with,
    "ends_with": check_ends_with,
    "no_end_with": check_no_end_with,
    "regex": check_regex,
}

class AuthAccessControl(models.Model):
    enabled = models.BooleanField(default=True)

    name = models.TextField(verbose_name=_("Friendly name"), help_text=_("Friendly name"), unique=True)
    rules = models.JSONField(default=[])

    def __str__(self):
        return f"Authentication ACL {self.name}"

    def to_dict(self, fields=None):
        result = model_to_dict(self, fields=fields)
        if not fields or "id" in fields:
            result['id'] = str(self.pk)
        return result

    def to_template(self):
        return {
            "id": str(self.pk),
            "name": self.name,
            "enabled": self.enabled,
            "rules": json.dumps(self.rules)
        }

    def apply_rules_on_scope(self, scope):
        for or_group in self.rules:
            match = True
            for line in or_group['lines']:
                try:
                    if not OPERATOR_FUNCTION[line['operator']](scope, line['variable_name'], line.get('value', '')):
                        logger.warning(f"AuthAccessControl:: user unauthorized -> variable '{line['variable_name']}' " 
                                    f"did not match value '{line.get('value', '')}' for operator '{line['operator']}'")
                        match = False
                        break
                except Exception as e:
                    logger.error(f"AuthAccessControl::apply_rules_on_scope: {e}")
                    return False
            if match:
                return True
        return False