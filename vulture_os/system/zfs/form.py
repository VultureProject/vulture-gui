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
__doc__ = 'Haproxy dedicated form class'

# Django system imports
from django.conf import settings
from django.forms import ModelForm, TextInput, SelectMultiple, NumberInput, ModelMultipleChoiceField
from system.cluster.models import NetworkInterfaceCard, NetworkAddress


# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('services')


class NetIfSystemForm(ModelForm):
    nic = ModelMultipleChoiceField(
        queryset=NetworkInterfaceCard.objects.exclude(dev__in=['lo0', 'lo1', 'lo2', 'lo3', 'lo4', 'lo5', 'lo6',
                                                               'pflog0', 'vm-public', 'tap0', 'tun0']),
        widget=SelectMultiple(attrs={'class': 'form-control select2'}),
    )

    class Meta:
        model = NetworkAddress
        fields = ('name', 'nic', 'ip', 'prefix_or_netmask', 'is_system')

        widgets = {
            'name': TextInput(attrs={'class': 'form-control'}),
            'ip': TextInput(attrs={'class': 'form-control'}),
            'prefix_or_netmask': TextInput(attrs={'class': 'form-control'})
        }


class NetIfForm(ModelForm):
    nic = ModelMultipleChoiceField(
        queryset=NetworkInterfaceCard.objects.exclude(dev__in=['lo0', 'lo1', 'lo2', 'lo3', 'lo4', 'lo5', 'lo6',
                                                               'pflog0', 'vm-public', 'tap0', 'tun0']),
        widget=SelectMultiple(attrs={'class': 'form-control select2'}),
    )

    class Meta:
        model = NetworkAddress
        fields = ('name', 'nic', 'ip', 'prefix_or_netmask', 'carp_vhid')

        widgets = {
            'name': TextInput(attrs={'class': 'form-control'}),
            'ip': TextInput(attrs={'class': 'form-control'}),
            'carp_vhid': NumberInput(attrs={'class': 'form-control'}),
            'prefix_or_netmask': TextInput(attrs={'class': 'form-control'}),
        }

        # FIXME: carp_vhid > 0 if multiple NIC detected
        # FIXME: Cannot select 2 NIC for CARP on the same node
