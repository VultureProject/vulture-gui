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
__doc__ = 'Cluster dedicated form class'

# Django system imports
from django.conf import settings
from django.forms import ModelForm, TextInput, Textarea, HiddenInput, ModelChoiceField, Select, ValidationError
from django.utils.translation import ugettext_lazy as _

# Django project imports
from system.cluster.models import Node, NetworkAddress
from toolkit.network.network import get_hostname

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('system')


class NodeForm(ModelForm):
    scanner_ip = ModelChoiceField(
        queryset=NetworkAddress.objects.filter(nic__node__name=get_hostname(),
                                               carp_vhid=0).only(*NetworkAddress.str_attrs()),
        widget=Select(attrs={'class': 'form-control select2'}),
        required=False,
        empty_label="No scanner"
    )

    class Meta:
        model = Node

        fields = ['name', 'management_ip', 'pf_custom_config', 'pf_limit_states',
                  'pf_limit_frags', 'pf_limit_src', 'static_routes',
                  'gateway', 'gateway_ipv6', 'internet_ip', 'scanner_ip']

        widgets = {
            'name': TextInput(attrs={'class': 'form-control'}),
            'management_ip': TextInput(attrs={'class': 'form-control'}),
            'pf_custom_config': Textarea(attrs={'class': 'form-control'}),
            'pf_limit_states': TextInput(attrs={'class': 'form-control'}),
            'pf_limit_frags': TextInput(attrs={'class': 'form-control'}),
            'pf_limit_src': TextInput(attrs={'class': 'form-control'}),
            'static_routes': Textarea(attrs={'class': 'form-control'}),
            'gateway': TextInput(attrs={'class': 'form-control'}),
            'gateway_ipv6': TextInput(attrs={'class': 'form-control'}),
            'internet_ip': TextInput(attrs={'class': 'form-control'}),
        }

    def clean_scanner_ip(self):
        value = self.cleaned_data.get('scanner_ip')
        if value and value.family != "inet":
            raise ValidationError("This field does not support non IPv4 address")
        return value


class NodeAddForm(ModelForm):

    class Meta:
        model = Node

        fields = ['name', 'pf_limit_states','pf_custom_config',
                  'pf_limit_frags', 'pf_limit_src']

        widgets = {
            'name': TextInput(attrs={'class': 'form-control'}),
            'pf_custom_config': Textarea(attrs={'class': 'form-control'}),
            'pf_limit_states': HiddenInput(attrs={'class': 'form-control'}),
            'pf_limit_frags': HiddenInput(attrs={'class': 'form-control'}),
            'pf_limit_src': HiddenInput(attrs={'class': 'form-control'})
        }
