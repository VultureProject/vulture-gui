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
__author__ = "Kevin GUILLEMOT"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Backends & Servers dedicated form classes'

# Django system imports
from django.conf import settings
from django.forms import CheckboxInput, ModelForm, NumberInput, Select, TextInput, Textarea, Form, \
    ChoiceField, CharField, HiddenInput, ValidationError
from django.utils.translation import gettext as _

# Django project imports
from gui.forms.form_utils import NoValidationField
from applications.backend.models import (Backend, Server, LOG_LEVEL_CHOICES, MODE_CHOICES, BALANCING_CHOICES, HEALTH_CHECK_TCP_EXPECT_CHOICES,
                                         HEALTH_CHECK_EXPECT_CHOICES, HEALTH_CHECK_METHOD_CHOICES, HEALTH_CHECK_VERSION_CHOICES)
from system.pki.models import TLSProfile

# Required exceptions imports

# Extern modules imports

# Logger configuration imports
import logging

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')

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
    ("X-Http-Method-Override", "X-Http-Method-Override"),
    ("X-ATT-DeviceId", "X-ATT-DeviceId"),
    ("X-Wap-Profile", "X-Wap-Profile"),
)


class BackendForm(ModelForm):
    headers = NoValidationField()

    class Meta:
        model = Backend
        fields = ('enabled', 'name', 'mode', 'timeout_connect', 'timeout_server',
                  'custom_haproxy_conf', 'balancing_mode', 'balancing_param', 'tags',
                  'enable_tcp_health_check', 'tcp_health_check_linger', 'tcp_health_check_send',
                  'tcp_health_check_expect_match', 'tcp_health_check_expect_pattern',
                  'tcp_health_check_interval', 'enable_tcp_keep_alive', 'tcp_keep_alive_timeout',
                  'http_backend_dir', 'accept_invalid_http_response', 'http_forwardfor_header', 'http_forwardfor_except',
                  'enable_http_health_check', 'http_health_check_linger', 'http_health_check_method',
                  'http_health_check_uri', 'http_health_check_version', 'http_health_check_expect_match',
                  'http_health_check_expect_pattern', 'http_health_check_interval',
                  'enable_http_keep_alive', 'http_keep_alive_timeout')

        widgets = {
            'enabled': CheckboxInput(attrs={"class": " js-switch"}),
            'name': TextInput(attrs={'class': 'form-control'}),
            'mode': Select(choices=MODE_CHOICES, attrs={'class': 'form-control select2'}),
            'timeout_connect': NumberInput(attrs={'class': 'form-control'}),
            'timeout_server': NumberInput(attrs={'class': 'form-control'}),
            'custom_haproxy_conf': Textarea(attrs={'class': 'form-control'}),
            'balancing_mode': Select(choices=BALANCING_CHOICES, attrs={'class': 'form-control select2'}),
            'balancing_param': TextInput(attrs={'class': 'form-control'}),
            'tags': TextInput(attrs={'class': 'form-control'}),
            'enable_tcp_health_check': CheckboxInput(attrs={'class': "form-control js-switch"}),
            'tcp_health_check_linger': CheckboxInput(attrs={'class': "form-control js-switch"}),
            'tcp_health_check_send': TextInput(attrs={'class': 'form-control'}),
            'tcp_health_check_expect_match': Select(choices=HEALTH_CHECK_TCP_EXPECT_CHOICES, attrs={'class': 'form-control select2'}),
            'tcp_health_check_expect_pattern': TextInput(attrs={'class': 'form-control'}),
            'tcp_health_check_interval': NumberInput(attrs={'class': 'form-control'}),
            'enable_tcp_keep_alive': CheckboxInput(attrs={'class': "form-control js-switch"}),
            'tcp_keep_alive_timeout': NumberInput(attrs={'class': 'form-control'}),
            'http_backend_dir': TextInput(attrs={'class': "form-control"}),
            'accept_invalid_http_response': CheckboxInput(attrs={'class': "form-control js-switch"}),
            'http_forwardfor_header': TextInput(attrs={'class': 'form-control', 'placeholder': 'header name'}),
            'http_forwardfor_except': TextInput(attrs={'class': 'form-control', 'placeholder': 'this IP address'}),
            'enable_http_health_check': CheckboxInput(attrs={'class': "form-control js-switch"}),
            'http_health_check_linger': CheckboxInput(attrs={'class': "form-control js-switch"}),
            'http_health_check_method': Select(choices=HEALTH_CHECK_METHOD_CHOICES, attrs={'class': 'form-control select2'}),
            'http_health_check_uri': TextInput(attrs={'class': 'form-control'}),
            'http_health_check_version': Select(choices=HEALTH_CHECK_VERSION_CHOICES, attrs={'class': 'form-control select2'}),
            'http_health_check_expect_match': Select(choices=HEALTH_CHECK_EXPECT_CHOICES, attrs={'class': 'form-control select2'}),
            'http_health_check_expect_pattern': TextInput(attrs={'class': 'form-control'}),
            'http_health_check_interval': NumberInput(attrs={'class': 'form-control'}),
            'enable_http_keep_alive': CheckboxInput(attrs={'class': "form-control js-switch"}),
            'http_keep_alive_timeout': NumberInput(attrs={'class': 'form-control'})
        }

    def __init__(self, *args, **kwargs):
        """ Initialize form and special attributes """
        super().__init__(*args, **kwargs)
        # Remove the blank input generated by django
        for field_name in ['mode', 'balancing_mode', 'tcp_health_check_expect_match']:
            self.fields[field_name].empty_label = None
        # Set required in POST data to False
        for field_name in ['headers', 'custom_haproxy_conf', 'balancing_param', 'tags',
                           'tcp_health_check_send', 'tcp_health_check_expect_match', 'tcp_health_check_expect_pattern',
                           'tcp_health_check_interval', 'tcp_keep_alive_timeout',
                           'http_backend_dir', 'http_health_check_method',
                           'http_health_check_uri', 'http_health_check_version',
                           'http_health_check_expect_match', 'http_health_check_expect_pattern',
                           'http_health_check_interval', 'http_keep_alive_timeout']:
            self.fields[field_name].required = False
        self.initial['tags'] = ','.join(self.initial.get('tags', []) or self.fields['tags'].initial)

    def clean_name(self):
        """ HAProxy does not support space in backend name directive, replace them by _ """
        return self.cleaned_data['name'].replace(' ', '_')

    def clean_tags(self):
        tags = self.cleaned_data.get('tags')
        if tags:
            return [i.replace(" ", "") for i in self.cleaned_data['tags'].split(',')]
        return []

    def clean_http_backend_dir(self):
        val = self.cleaned_data.get('http_backend_dir')
        if len(val) == 0:
            return val

        if val[0] != '/':
            val = "/" + val
        if val != "/" and val[-1] == "/":
            val = val[:-1]
        return val

    def clean(self, *args, **kwargs):
        cleaned_data = super().clean()

        is_tcp_hc_enable = cleaned_data.get('enable_tcp_health_check')
        if cleaned_data.get('enable_tcp_keep_alive') and not cleaned_data.get('tcp_keep_alive_timeout'):
            self.add_error('tcp_keep_alive_timeout', "Timeout field is required")

        is_http_hc_enable = cleaned_data.get('enable_http_health_check')
        if is_http_hc_enable and not cleaned_data.get('http_health_check_method'):
            self.add_error('http_health_check_method', 'Method field is required')
        if is_http_hc_enable and not cleaned_data.get('http_health_check_uri'):
            self.add_error('http_health_check_uri', 'URI field is required')
        if is_http_hc_enable and not cleaned_data.get('http_health_check_version'):
            self.add_error('http_health_check_version', 'Version field is required')
        if cleaned_data.get('enable_http_keep_alive') and not cleaned_data.get('http_keep_alive_timeout'):
            self.add_error('http_keep_alive_timeout', "Timeout field is required")

        """ For some balancing modes, a parameter is required """
        if cleaned_data.get('balancing_mode') in ("url_param", "hdr", "rdp-cookie") and \
                not cleaned_data.get('balancing_param'):
            self.add_error('balancing_param', "This field is required in '{}' balancing mode ".format(cleaned_data.get('balancing_mode')))
        if cleaned_data.get('mode') == "http" and is_http_hc_enable \
                and not cleaned_data.get('http_health_check_expect_match'):
            self.add_error('http_health_check_expect_pattern', "This field is required.")
        return cleaned_data


class HttpHealthCheckHeaderForm(Form):
    labels = ("Header select", "Header name")

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


class ServerForm(ModelForm):
    class Meta:
        model = Server
        fields = ('target', 'mode', 'port', 'tls_profile', 'weight', 'source')

        widgets = {
            'mode': HiddenInput(attrs={'class': 'form-control'}),
            'target': TextInput(attrs={'class': 'form-control'}),
            'port': NumberInput(attrs={'class': 'form-control'}),
            'tls_profile': Select(choices=TLSProfile.objects.all(), attrs={'class': 'form-control select2'}),
            'weight': NumberInput(attrs={'class': 'form-control'}),
            'source': TextInput(attrs={'class': 'form-control'})
        }

    def __init__(self, *args, **kwargs):
        """ Initialisation of fields method """
        # Do not set id of html fields, that causes issues in JS/JQuery
        kwargs['auto_id'] = False
        mode = kwargs.pop('mode', '')
        super().__init__(*args, **kwargs)
        # Remove the blank input generated by django
        self.fields['tls_profile'].empty_label = "Plain text"
        self.fields['tls_profile'].required = False
        self.fields['source'].required = False
        if mode == 'unix':
            self.fields['target'].label = 'Socket'
            del self.fields['port']


    def as_table_headers(self):
        """ Format field names as table head """
        result = "<tr><th style=\"visibility:hidden;\">{}</th>\n"
        for field in self:
            if field.name == "mode":
                continue
            result += "<th>{}</th>\n".format(field.label)
        result += "<th>Delete</th></tr>\n"
        return result

    def as_table_td(self):
        """ Format fields as a table with <td></td> """
        result = "<tr><td style=\"visibility:hidden;\">{}</td>\n".format(self.instance.id or "")
        mode = self.instance.mode
        for field in self:
            if field.name == 'mode' or (mode == 'unix' and field.name == 'port'):
                continue
            result += "<td>{}</td>\n".format(field)
        result += "<td style='text-align:center'><a class='btnDelete'><i style='color:grey' " \
                  "class='fas fa-trash-alt'></i></a></td></tr>\n"
        return result

    def clean(self):
        cleaned_data = self.cleaned_data
        target = cleaned_data.get('target')
        mode = cleaned_data.get('mode')
        if mode == "net":
            if "[" in target or "]" in target:
                self.add_error('target', "No need to put brackets for IPv6 addresses")
        else:
            if target[0] != "/":
                self.add_error('target', "Please enter a valid absolute path.")
        return cleaned_data
