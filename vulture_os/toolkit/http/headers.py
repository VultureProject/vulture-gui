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
__author__ = "Kevin Guillemot"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Response API toolkit functions'

# Django system imports
from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from django.forms import CheckboxInput, ModelForm, Select, TextInput, Form, ChoiceField, CharField
from djongo import models

# Django project imports

# Extern modules imports
from copy import deepcopy

# Required exceptions imports

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


DEFAULT_FRONTEND_HEADERS = [
    {
        'enabled': False,
        'type': "response",
        'action': "set-header",
        'header_name': "X-Frame-Options",
        'match': "",
        'replace': "SAMEORIGIN",
        'condition_action': "if",
        'condition': ""
    },
    {
        'enabled': False,
        'type': "response",
        'action': "set-header",
        'header_name': "X-Content-Type-Options",
        'match': "",
        'replace': "nosniff",
        'condition_action': "if",
        'condition': ""
    },
    {
        'enabled': False,
        'type': "response",
        'action': "set-header",
        'header_name': "X-XSS-Protection",
        'match': "",
        'replace': "1; mode=block",
        'condition_action': "if",
        'condition': ""
    }
]

HEADER_TYPE_CHOICES = (
    ('request', "Request"),
    ('response', "Response"),
)

HEADER_ACTION_CHOICES = (
    ('add-header', "Add"),
    ('set-header', "Set"),
    ('del-header', "Delete"),
    ('replace-header', "Replace name"),
    ('replace-value', "Replace value"),
)

HEADER_CONDITION_CHOICES = (
    ('', "Always"),
    ('if', "If"),
    ('unless', "Unless"),
)

HTTP_HEADER_CHOICES = (
    ("Accept", "Accept"),
    ("Accept-Charset", "Accept-Charset"),
    ("Accept-Encoding", "Accept-Encoding"),
    ("Accept-Language", "Accept-Language"),
    ("Accept-Datetime", "Accept-Datetime"),
    ("Authorization", "Authorization"),
    ("Cache-Control", "Cache-Control"),
    ("Connection", "Connection"),
    ("Cookie", "Cookie"),
    ("Content-Length", "Content-Length"),
    ("Content-MD5", "Content-MD5"),
    ("Content-Type", "Content-Type"),
    ("Date", "Date"),
    ("DNT", "DNT"),
    ("Expect", "Expect"),
    ("From", "From"),
    ("Front-End-Https", "Front-End-Https"),
    ("Host", "Host"),
    ("If-Match", "If-Match"),
    ("If-Modified-Since", "If-Modified-Since"),
    ("If-None-Match", "If-None-Match"),
    ("If-Range", "If-Range"),
    ("If-Unmodified-Since", "If-Unmodified-Since"),
    ("Max-Forwards", "Max-Forwards"),
    ("Origin", "Origin"),
    ("Pragma", "Pragma"),
    ("Proxy-Authorization", "Proxy-Authorization"),
    ("Proxy-Connection", "Proxy-Connection"),
    ("Range", "Range"),
    ("Referer", "Referer"),
    ("TE", "TE"),
    ("User-Agent", "User-Agent"),
    ("Upgrade", "Upgrade"),
    ("Via", "Via"),
    ("Warning", "Warning"),
    ("X-Requested-With", "X-Requested-With"),
    ("X-Forwarded-For", "X-Forwarded-For"),
    ("X-Forwarded-Host", "X-Forwarded-Host"),
    ("X-Forwarded-Proto", "X-Forwarded-Proto"),
    ("X-Frame-Options", "X-Frame-Options"),
    ("X-Content-Type-Options", "X-Content-Type-Options"),
    ("X-XSS-Protection", "X-XSS-Protection"),
    ("X-Http-Method-Override", "X-Http-Method-Override"),
    ("X-ATT-DeviceId", "X-ATT-DeviceId"),
    ("X-Wap-Profile", "X-Wap-Profile"),
)


class Header(models.Model):
    """ http-request and http-response directive Model """
    """ Enable or disable the header """
    enabled = models.BooleanField(
        default=True,
        verbose_name=_("Enabled"),
        help_text=_("Enable or disable the header")
    )
    """ What to do with the header """
    type = models.TextField(
        default="request",
        choices=HEADER_TYPE_CHOICES,
        help_text=_("Type of header, request or response")
    )
    """ What to do with the header """
    action = models.TextField(
        default="add-header",
        choices=HEADER_ACTION_CHOICES,
        help_text=_("Action to do with the header")
    )
    """ The name of the header """
    header_name = models.TextField(
        default="Cookie",
        help_text=_("Concerned header name")
    )
    """ Match regex """
    match = models.TextField(
        default="matching regex",
        help_text=_("")
    )
    replace = models.TextField(
        default="replacement pattern",
        help_text=_("")
    )
    condition_action = models.TextField(
        default="",
        choices=HEADER_CONDITION_CHOICES,
        help_text=_("Facultative condition type of applying the rule")
    )
    condition = models.TextField(
        default="",
        help_text=_("Facultative condition of applying to rule")
    )

    def __str__(self):
        return "{} {} {}".format(self.action, self.header_name, self.replace if self.replace else "")

    def to_template(self):
        """ Method used to serialize the Header object """
        return {
            'id': self.id,
            'type': self.type,
            'action': self.action,
            'header_name': self.header_name,
            'match': self.match,
            'replace': self.replace,
            'condition_action': self.condition_action if self.condition else "",
            'condition': self.condition if self.condition else ""
        }

    def generate_conf(self):
        # http-request or http-response
        result = "http-{} {} {}".format(self.type, self.action, self.header_name)
        if self.action == "add-header" or self.action == "set-header":
            result += ' "{}"'.format(self.replace.replace('"', '\\"'))
        elif self.action == "replace-header" or self.action == "replace-value":
            result += ' "{}" "{}"'.format(self.match.replace('"', '\\"'), self.replace.replace('"', '\\"'))
        if self.condition:
            result += " {} {}".format(self.condition_action, self.condition)
        return result


class HeaderForm(ModelForm):

    class Meta:
        model = Header
        fields = ('enabled', 'type', 'action', 'header_name', 'match', 'replace', 'condition_action', 'condition')

        widgets = {
            'enabled': CheckboxInput(attrs={"class": " js-switch"}),
            'type': Select(choices=HEADER_TYPE_CHOICES, attrs={'class': "form-control select2"}),
            'action': Select(choices=HEADER_ACTION_CHOICES, attrs={'class': "form-control select2"}),
            'header_name': TextInput(attrs={'class': "form-control"}),
            'match': TextInput(attrs={'class': "form-control"}),
            'replace': TextInput(attrs={'class': "form-control"}),
            'condition_action': Select(choices=HEADER_CONDITION_CHOICES, attrs={'class': "form-control select2"}),
            'condition': TextInput(attrs={'class': "form-control"}),
        }

    def __init__(self, *args, **kwargs):
        """ Initialize form and special attributes """
        super().__init__(*args, **kwargs)
        # Set required in POST data to False
        for field_name in ['enabled', 'match', 'replace', 'condition_action', 'condition']:
            self.fields[field_name].required = False

    def clean(self):
        """ Verify required field depending on other fields """
        cleaned_data = super().clean()
        """ If action = add-header """
        required_fields = {
            'add-header': ["replace"],
            'set-header': ["replace"],
            'replace-header': ["match", "replace"],
            'replace-value': ["match", "replace"],
        }
        action = cleaned_data.get('action')
        for field in required_fields.get(action, []):
            if not cleaned_data.get(field):
                self.add_error(field, "This field is required if action = '{}'".format(action))
        return cleaned_data

    def as_table_headers(self):
        """ Format field names as table head """
        result = "<tr><th style=\"visibility:hidden;\">Id</th>\n"
        for field in self:
            result += "<th>{}</th>\n".format(field.label)
        result += "<th>Delete</th></tr>\n"
        return result

    def as_table_td(self):
        """ Format fields as a table with <td></td> """
        result = "<tr><td style=\"visibility:hidden;\">{}</td>".format(self.instance.id or "")
        for field in self:
            result += "<td>{}</td>".format(field)
        result += "<td style='text-align:center'><a class='btnDelete'><i style='color:grey' " \
                  "class='fas fa-trash-alt'></i></a></td></tr>\n"
        return result


class HttpHealthCheckHeaderForm(Form):
    labels = ("Header name", "Header value")

    check_header_name = ChoiceField(
        choices=HTTP_HEADER_CHOICES,
        widget=Select(attrs={
            'class': 'form-control select2'
        })
    )

    check_header_value = CharField(
        widget=TextInput(attrs={
            'class': 'form-control'
        })
    )

    def __init__(self, *args, **kwargs):
        """ Initialisation of fields method """
        # Do not set id of html fields, that causes issues in JS/JQuery
        kwargs['auto_id'] = False
        super().__init__(*args, **kwargs)

    def as_table_headers(self):
        """ Format field names as table head """
        result = "<tr>"
        for field in self.labels:
            result += "<th>{}</th>\n".format(field)
        result += "<th>Delete</th></tr>\n"
        return result

    def as_table_td(self):
        """ Format fields as a table with <td></td> """
        result = "<tr>"
        for field in self:
            result += "<td>{}</td>\n".format(field)
        result += "<td style='text-align:center'><a class='btnDelete'><i style='color:grey' " \
                  "class='fas fa-trash-alt'></i></a></td></tr>\n"
        return result

    def as_table_td_internal(self):
        """ Format fields as a table with <td></td> """
        result = "<tr>"
        for field in self.fields:
            new_field = deepcopy(self.fields[field].widget)
            new_field.attrs['readonly'] = True
            result += "<td>{}</td>\n".format(new_field.render(field, self.initial.get(field)))
        result += "<td style='text-align:center'><a class='btnDelete'><i style='color:grey' " \
                  "class='fas fa-trash-alt'></i></a></td></tr>\n"
        return result
