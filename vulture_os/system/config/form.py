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
__author__ = "Jérémie JOURDIN"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Global Config dedicated form class'

# Django system imports
from django.conf import settings
from django.forms import ModelForm, Textarea, TextInput, Select, NumberInput

# Django project imports
from authentication.ldap.models import LDAPRepository
from gui.forms.form_utils import bootstrap_tooltips
from system.config.models import Config
from system.tenants.models import Tenants

# Required exceptions import
from django.forms import ValidationError

# Extern modules imports
from ipaddress import ip_address, ip_network

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('system')


class ConfigForm(ModelForm):

    class Meta:
        model = Config

        fields = [
            'pf_ssh_restrict', 'pf_admin_restrict', 'pf_whitelist', 'pf_blacklist',
            'cluster_api_key', 'ldap_repository', 'oauth2_header_name', 'portal_cookie_name',
            'public_token', 'redis_password', 'branch', 'smtp_server', 'ssh_authorized_key',
            'rsa_encryption_key', 'logs_ttl', 'internal_tenants'
        ]

        widgets = {
            'pf_ssh_restrict': TextInput(attrs={'class': 'form-control', 'data-role': 'tagsinput'}),
            'pf_admin_restrict': TextInput(attrs={'class': 'form-control', 'data-role': 'tagsinput'}),
            'pf_whitelist': TextInput(attrs={'class': 'form-control', 'data-role': 'tagsinput'}),
            'pf_blacklist': TextInput(attrs={'class': 'form-control', 'data-role': 'tagsinput'}),
            'cluster_api_key': TextInput(attrs={'class': 'form-control'}),
            'oauth2_header_name': TextInput(attrs={'class': 'form-control'}),
            'portal_cookie_name': TextInput(attrs={'class': 'form-control'}),
            'public_token': TextInput(attrs={'class': 'form-control'}),
            'redis_password': TextInput(attrs={'class': 'form-control'}),
            'branch': TextInput(attrs={'class': 'form-control'}),
            'smtp_server': TextInput(attrs={'class': 'form-control'}),
            'ssh_authorized_key': Textarea(attrs={'class': 'form-control'}),
            'rsa_encryption_key': Textarea(attrs={'class': 'form-control'}),
            'logs_ttl': NumberInput(attrs={'class': 'form-control'}),
            'internal_tenants': Select(choices=[],attrs={'class': 'form-control select2'}),
            'ldap_repository': Select(choices=[],attrs={'class': 'form-control select2'}),
        }

    def __init__(self, *args, **kwargs):
        """ Initialize form and special attributes """
        super().__init__(*args, **kwargs)
        self = bootstrap_tooltips(self)
        self.fields['internal_tenants'].empty_label = None
        self.fields['ldap_repository'].empty_label = "No ldap authentication"
        self.fields['ldap_repository'].required = False

    @staticmethod
    def validate_ip_list(field_value):
        """ Verify if the given parameter is a list of valid IP Address or IP Network separated by ; """
        for a in field_value:
            if a:
                is_valid = False
                try:
                    ip_address(a)
                    is_valid = True
                except Exception:
                    pass
                try:
                    ip_network(a)
                    is_valid = True
                except Exception:
                    pass
                if not is_valid:
                    raise ValidationError("This ip/cidr is not valid : '{}'".format(a))

    def clean_pf_ssh_restrict(self):
        field_value = self.cleaned_data.get('pf_ssh_restrict')
        if field_value != "any":
            self.validate_ip_list(field_value.split(","))
        return field_value

    def clean_pf_admin_restrict(self):
        field_value = self.cleaned_data.get('pf_admin_restrict')
        if field_value != "any":
            self.validate_ip_list(field_value.split(","))
        return field_value

    def clean_pf_blacklist(self):
        field_value = self.cleaned_data.get('pf_blacklist')
        if field_value != "any":
            self.validate_ip_list(field_value.split(","))
        return field_value

    def clean_pf_whitelist(self):
        field_value = self.cleaned_data.get('pf_whitelist')
        if field_value != "any":
            self.validate_ip_list(field_value.split(","))
        return field_value
