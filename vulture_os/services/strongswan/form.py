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
__doc__ = 'Strongswan dedicated form classes'

# Django system imports
from django.conf import settings
from django.forms import (CheckboxInput, ModelForm, Select, TextInput, ModelChoiceField)

# Django project imports
from gui.forms.form_utils import bootstrap_tooltips
from services.strongswan.models import AUTHBY, DPD, KEYEXCHANGE, Strongswan, TYPE
from system.cluster.models import Node

# Required exceptions imports
from django.forms import ValidationError

# Extern modules imports
from ipaddress import ip_network

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


class StrongswanForm(ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self = bootstrap_tooltips(self)

        self.fields['node'] = ModelChoiceField(
            queryset=Node.objects.all(),
            widget=Select(attrs={'class': 'form-control select2'})
        )

    class Meta:
        model = Strongswan

        fields = ('node', 'enabled', 'ipsec_type', 'ipsec_keyexchange', 'ipsec_authby', 'ipsec_psk',
                  'ipsec_fragmentation', 'ipsec_forceencaps', 'ipsec_ike', 'ipsec_esp', 'ipsec_dpdaction',
                  'ipsec_dpddelay', 'ipsec_rekey', 'ipsec_ikelifetime', 'ipsec_keylife', 'ipsec_right',
                  'ipsec_leftsubnet', 'ipsec_leftid', 'ipsec_rightsubnet')

        widgets = {
            'enabled': CheckboxInput(attrs={"class": " js-switch"}),
            'ipsec_type': Select(choices=TYPE, attrs={'class': 'form-control select2'}),
            'ipsec_keyexchange': Select(choices=KEYEXCHANGE, attrs={'class': 'form-control select2'}),
            'ipsec_authby': Select(choices=AUTHBY, attrs={'class': 'form-control select2'}),
            'ipsec_psk': TextInput(attrs={'class': 'form-control'}),
            'ipsec_ike': TextInput(attrs={'class': 'form-control'}),
            'ipsec_esp': TextInput(attrs={'class': 'form-control'}),
            'ipsec_dpdaction': Select(choices=DPD, attrs={'class': 'form-control select2'}),
            'ipsec_dpddelay': TextInput(attrs={'class': 'form-control'}),
            'ipsec_ikelifetime': TextInput(attrs={'class': 'form-control'}),
            'ipsec_keylife': TextInput(attrs={'class': 'form-control'}),
            'ipsec_right': TextInput(attrs={'class': 'form-control'}),
            'ipsec_leftsubnet': TextInput(attrs={'class': 'form-control'}),
            'ipsec_leftid': TextInput(attrs={'class': 'form-control'}),
            'ipsec_rightsubnet': TextInput(attrs={'class': 'form-control', 'data-role': "tagsinput"}),
            'ipsec_fragmentation': CheckboxInput(attrs={'class': 'js-switch'}),
            'ipsec_forceencaps': CheckboxInput(attrs={'class': 'js-switch'}),
            'ipsec_rekey': CheckboxInput(attrs={'class': 'js-switch'}),
        }

    def clean_ipsec_rightsubnet(self):
        right_subnet = self.cleaned_data.get('ipsec_rightsubnet')
        for subnet in right_subnet.split(','):
            try:
                assert ip_network(subnet)
            except Exception:
                raise ValidationError("Invalid subnet : {}".format(subnet))
        return right_subnet

    def clean(self):
        """ Verify needed fields - depending on mode chosen """
        cleaned_data = super().clean()

        return cleaned_data
