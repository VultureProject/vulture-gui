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
__author__ = "Kévin GUILLEMOT"
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
from system.tenants.models import Tenants

# Required exceptions import
from django.forms import ValidationError

# Extern modules imports
from ipaddress import ip_address, ip_network

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('system')


class TenantsForm(ModelForm):

    class Meta:
        model = Tenants

        fields = [
            'name'
        ]

        widgets = {
            'name': TextInput(attrs={'class': 'form-control'})
        }

    def __init__(self, *args, **kwargs):
        """ Initialize form and special attributes """
        super().__init__(*args, **kwargs)
        self = bootstrap_tooltips(self)

    def clean_name(self):
        field = self.cleaned_data.get('name')
        if not field:
            raise ValidationError("This field is required.")
        return field.replace(' ', '_')
