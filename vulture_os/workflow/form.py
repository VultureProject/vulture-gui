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
from django.utils.translation import gettext_lazy as _
from django.utils.crypto import get_random_string
from django.conf import settings
from django.forms import (ModelForm, CheckboxInput, NumberInput, SelectMultiple, TextInput)
import validators
import logging

# Django project imports
from workflow.models import Workflow, CORS_METHODS

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


class WorkflowForm(ModelForm):

    class Meta:
        model = Workflow
        fields = ('enabled', 'name', 'enable_cors_policy', 'cors_allowed_methods',
                  'cors_allowed_origins', 'cors_allowed_headers', 'cors_max_age')
        widgets = {
            'enabled': CheckboxInput(attrs={'class': 'js-switch'}),
            'name': TextInput(attrs={'class': 'form-control'}),
            'enable_cors_policy': CheckboxInput(attrs={'class': 'js-switch'}),
            'cors_allowed_methods': SelectMultiple(choices=CORS_METHODS, attrs={'class': 'form-control select2'}),
            'cors_allowed_origins': TextInput(attrs={'class': 'form-control'}),
            'cors_allowed_headers': TextInput(attrs={'class': 'form-control'}),
            'cors_max_age': NumberInput(attrs={'class': 'form-control'})
        }

    def __init__(self, *args, **kwargs):
        """ Initialize form and special attributes """
        super().__init__(*args, **kwargs)
        self.fields['cors_allowed_methods'].empty_label = ""

    # Exclude LOG Frontends
    def clean_public_dir(self):
        """ """
        public_dir = self.cleaned_data.get('public_dir')
        if public_dir and len(public_dir):
            if public_dir[0] != '/':
                public_dir = '/' + public_dir
            if public_dir[-1] != '/':
                public_dir += '/'
        return public_dir

    def clean(self):
        cleaned_data = super().clean()

        frontend = cleaned_data.get('frontend')
        backend = cleaned_data.get('backend')

        if frontend and backend:
            if frontend.mode != "http" and cleaned_data.get('authentication'):
                self.add_error('authentication', _("You cannot set-up Authentication on TCP frontend."))

            if frontend.mode != backend.mode:
                self.add_error('frontend', _("Frontend and Backend must have the same mode."))
                self.add_error('backend', _("Frontend and Backend must have the same mode."))

            if frontend.mode == 'http':
                if not cleaned_data.get('fqdn'):
                    self.add_error('fqdn', _("This field is required for http type"))
                if not cleaned_data.get('public_dir'):
                    self.add_error('public_dir', _("This field is required for http type"))

                if not validators.domain(cleaned_data.get('fqdn')):
                    self.add_error("fqdn", _("This FQDN is invalid"))
            else:
                cleaned_data['fqdn'] = get_random_string(length=12)

        return cleaned_data
