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
__author__ = "Olivier de Régis"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Access Control Form'

from authentication.auth_access_control.models import AuthAccessControl
from authentication.auth_access_control.models import OPERATOR_CHOICES
from django.conf import settings
from django import forms
import logging

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


class AuthAccessControlForm(forms.ModelForm):

    class Meta:
        model = AuthAccessControl
        fields = ('name', 'enabled', 'rules')

        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
            'enabled': forms.CheckboxInput(attrs={'class': "form-control js-switch"})
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['rules'].required = False

    def clean(self):
        """ Replace all spaces by underscores to prevent bugs later """
        self.cleaned_data['name'] = self.cleaned_data['name'].replace(' ', '_')


class AuthAccessControlRuleForm(forms.Form):

    variable_name = forms.CharField(
        required=True,
    )

    operator = forms.ChoiceField(
        choices=OPERATOR_CHOICES,
        required=True
    )

    value = forms.CharField(
        required=False,
    )

    def clean(self):
        """ Replace all spaces by underscores to prevent bugs later """
        cleaned_data = super().clean()
        logger.debug(f"cleaned data is {cleaned_data}")
        operator = self.cleaned_data.get('operator')
        value = self.cleaned_data.get('value')

        if operator not in ["exists", "not_exists"]:
            if not value:
                self.add_error("value", "a value is mandatory for this kind of operator")

