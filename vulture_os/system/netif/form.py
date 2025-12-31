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
from django.forms import ModelForm, TextInput, SelectMultiple, Select, NumberInput, ModelMultipleChoiceField, ValidationError
from system.cluster.models import (NetworkInterfaceCard, NetworkAddress, NetworkAddressNIC,
                                   NET_ADDR_TYPES, NET_ADDR_VERSIONS, LAGG_PROTO_TYPES)

# External libraries
from iptools.ipv4 import netmask2prefix

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('services')



class NetIfForm(ModelForm):
    nic = ModelMultipleChoiceField(
        queryset=NetworkInterfaceCard.objects.exclude(dev__in=[
            'lo0', 'lo1', 'lo2', 'lo3', 'lo4', 'lo5', 'lo6',
            'pflog0', 'vm-public'
        ]),
        widget=SelectMultiple(attrs={'class': 'form-control select2'}),
    )


    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields['iface_id'].disabled = True

        for field_name in ['ip_version', 'fib', 'vlan', 'carp_vhid', 'iface_id']:
            self.fields[field_name].required = False


    class Meta:
        model = NetworkAddress
        fields = ('name', 'type', 'ip_version', 'nic', 'ip', 'prefix_or_netmask', 'carp_vhid', 'fib', 'iface_id', 'vlan', 'lagg_proto')

        widgets = {
            'name': TextInput(attrs={'class': 'form-control'}),
            'type': Select(choices=NET_ADDR_TYPES, attrs={'class': 'form-control select2'}),
            'ip_version': Select(choices=NET_ADDR_VERSIONS, attrs={'class': 'form-control select2'}),
            'ip': TextInput(attrs={'class': 'form-control'}),
            'carp_vhid': NumberInput(attrs={'class': 'form-control'}),
            'prefix_or_netmask': TextInput(attrs={'class': 'form-control'}),
            'fib': NumberInput(attrs={'class': 'form-control'}),
            'iface_id': NumberInput(attrs={'class': 'form-control'}),
            'vlan': NumberInput(attrs={'class': 'form-control'}),
            'lagg_proto': Select(choices=LAGG_PROTO_TYPES, attrs={'class': 'form-control select2'}),
        }

    def clean(self):
        cleaned_data = super().clean()

        if cleaned_data.get('type') in ("system", "dynamic"):
            incompatible_types = {"system": "dynamic", "dynamic": "system"}
            if NetworkAddressNIC.objects.filter(nic=cleaned_data.get('nic').first().pk, network_address__type=incompatible_types[cleaned_data['type']]).exclude(network_address__ip=cleaned_data['ip']).exists():
                self.add_error('type', f"A {incompatible_types[cleaned_data['type']]} interface is already configured, this is not supported")

        if cleaned_data.get('type') == "lagg":
            if not cleaned_data.get('lagg_proto'):
                self.add_error('lagg_proto', "The protocol must be specified for a LAGG interface")
            nics = cleaned_data.get('nic')
            for nic in nics:
                if NetworkAddressNIC.objects.filter(nic=nic).exclude(network_address__type=cleaned_data['type'], network_address__iface_id=cleaned_data.get('iface_id')).exists():
                    self.add_error('nic', "An interface selected is already configured, this is incompatible with LAGG interfaces. Please remove configuration on interface then create LAGG interface or remove this interface.")
                    break
        elif cleaned_data.get('type') == "dynamic":
            if not cleaned_data.get('ip_version'):
                self.add_error('ip_version', "This field is required for dynamic interfaces.")
            cleaned_data['ip'] = ""
            cleaned_data['prefix_or_netmask'] = ""
            cleaned_data['fib'] = 0
        else:
            if not cleaned_data.get('ip'):
                self.add_error('ip', "This field is required")
            if not cleaned_data.get('prefix_or_netmask'):
                self.add_error('prefix_or_netmask', "This field is required")

        if cleaned_data.get('type') in ['vlan', 'lagg', 'alias'] and cleaned_data['iface_id'] == -1:
            cleaned_data['iface_id'] = 0
            while NetworkAddress.objects.only('type', 'iface_id').filter(type=cleaned_data['type'], iface_id=cleaned_data['iface_id']).exists():
                cleaned_data['iface_id']+=1


    def clean_prefix_or_netmask(self):
        value = self.cleaned_data.get('prefix_or_netmask')
        if value:
            if netmask2prefix(value) == 0:
                try:
                    test = int(value.replace('/', ''))
                except:
                    raise ValidationError("Netmask/Prefix invalid. (ex: 255.255.255.0 or 24 or 64 (ipv6))")
        return value

        # FIXME: carp_vhid > 0 if multiple NIC detected
        # FIXME: Cannot select 2 NIC for CARP on the same node


    def clean_vlan(self):
        value = self.cleaned_data.get('vlan')
        if value:
            try:
                value = int (value)
            except:
                raise ValidationError("vlan must be 0 or an integer corresponding to VLAN ID")
        else:
            value = 0

        return value

    def clean_fib(self):
        value = self.cleaned_data.get('fib')
        if value:
            try:
                value = int (value)
            except:
                value = 0
        else:
            value = 0

        # 2 fibs (0 and 1) are available in VultureOS (sysctl net.fibs=2)
        if value > 1:
            value = 1

        return value