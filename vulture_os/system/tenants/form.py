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
from django.forms import ModelForm, TextInput, HiddenInput

# Django project imports
from gui.forms.form_utils import bootstrap_tooltips
from system.tenants.models import Tenants

# Required exceptions import
from django.forms import ValidationError

# Extern modules imports
from json import loads as json_loads, JSONDecodeError

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('system')


class TenantsForm(ModelForm):

    class Meta:
        model = Tenants

        fields = [
            'name',
            'additional_config'
        ]

        widgets = {
            'name': TextInput(attrs={'class': 'form-control'}),
            'additional_config': HiddenInput()
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

    def clean_additional_config(self):
        additional_config = self.cleaned_data.get('additional_config')
        if isinstance(additional_config, str):
            if additional_config != "":
                try:
                    logger.info(f"additional_config is {additional_config}")
                    additional_config = json_loads(additional_config.replace("'",'"'))
                except JSONDecodeError as e:
                    logger.error(f"Could not parse value as json: {str(e)}")
                    self.add_error('additional_config', "This field must be a valid dict.")
            else:
                additional_config = dict()
        elif not isinstance(additional_config, dict):
                self.add_error('additional_config', "This field must be a dict.")
        return additional_config
