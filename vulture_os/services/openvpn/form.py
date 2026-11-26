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
__doc__ = 'Openvpn dedicated form classes'

# Django system imports
from django.conf import settings
from django.forms import (CheckboxInput, ModelForm, Select, TextInput, ModelChoiceField)

# Django project imports
from gui.forms.form_utils import bootstrap_tooltips
from services.openvpn.models import Openvpn, PROTO
from system.cluster.models import Node
from system.pki.models import TLSProfile

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


class OpenvpnForm(ModelForm):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self = bootstrap_tooltips(self)

        self.fields['node'] = ModelChoiceField(
            queryset=Node.objects.all(),
            widget=Select(attrs={'class': 'form-control select2'})
        )

        self.fields['tls_profile'] = ModelChoiceField(
            queryset=TLSProfile.objects.all(),
            widget=Select(attrs={'class': 'form-control select2'})
        )

    class Meta:
        model = Openvpn

        fields = ('node', 'enabled', 'remote_server', 'remote_port', 'tls_profile', 'proto')

        widgets = {
            'enabled': CheckboxInput(attrs={"class": " js-switch"}),
            'remote_server': TextInput(attrs={'class': 'form-control'}),
            'remote_port': TextInput(attrs={'class': 'form-control'}),
            'proto': Select(choices=PROTO, attrs={'class': 'form-control select2'}),
        }

    def clean(self):
        """ Verify needed fields - depending on mode chosen """
        cleaned_data = super().clean()

        return cleaned_data
