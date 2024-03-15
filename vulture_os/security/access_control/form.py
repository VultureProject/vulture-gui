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

from security.access_control.models import (AccessControl, CRITERION_CHOICES,
                                          CONVERTER_CHOICES, OPERATOR_CHOICES,
                                          FLAGS_CHOICES)
from django.conf import settings
from django import forms
import logging

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


class AccessControlForm(forms.ModelForm):

    class Meta:
        model = AccessControl
        fields = ('name', 'acls', 'rules')

        widgets = {
            'name': forms.TextInput(attrs={'class': 'form-control'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name in ['acls', 'rules']:
            self.fields[field_name].required = False

    def clean(self):
        """ Replace all spaces by underscores to prevent bugs later """
        self.cleaned_data['name'] = self.cleaned_data['name'].replace(' ', '_')


class AccessControlRuleForm(forms.Form):

    criterion = forms.ChoiceField(
        choices=CRITERION_CHOICES,
        required=True
    )

    criterion_name = forms.SlugField(
        max_length=32,
        required=False
    )
    converter = forms.ChoiceField(
        choices=CONVERTER_CHOICES,
        required=False
    )
    flags = forms.SlugField(
        max_length=64,
        required=False
    )
    operator = forms.ChoiceField(
        choices=OPERATOR_CHOICES,
        required=False
    )
    pattern = forms.CharField(
        max_length=256,
        required=False
    )

    def clean(self):
        """
        Check the user inputs
        :return:
        """
        cleaned_data = super().clean()

        # Case of using criterion and criterion_name
        if cleaned_data.get('criterion', "") == "":
            if cleaned_data.get('criterion_name', "") == "":
                self.add_error("criterion", "Criterion is required when a criterion_name is specified")

        # Case of using converter and a pattern
        if cleaned_data.get('converter', "") != "":
            if cleaned_data.get('pattern', "") == "":
                self.add_error("pattern", "Pattern is required when a converter is selected")

        # Case of parsing flags
        if cleaned_data.get("flags", "") != "":
            flags = cleaned_data.get("flags").split(' ')
            for flag in flags:
                if flag not in dict(FLAGS_CHOICES):
                    self.add_error("flags", "Flag injection detected")

        # Case of using operator and non number values
        def is_int(num):
            """
            :param num: str
            :return: bool
            """
            if num[0] in ('-', '+'):
                return num[1:].isdigit()
            return num.isdigit()

        # Bug: weak condition to check the operator field
        if cleaned_data.get('operator', "") != "":
            if not is_int(cleaned_data.get('pattern')):
                self.add_error("pattern", "pattern is not an integer")
