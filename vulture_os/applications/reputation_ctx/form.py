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
__doc__ = 'ReputationContext dedicated form classes'

# Django system imports
from django.conf import settings
from django.forms import CheckboxInput, ModelForm, Select, TextInput, Textarea

# Django project imports
from gui.forms.form_utils import NoValidationField
from applications.reputation_ctx.models import (DBTYPE_CHOICES, HTTP_METHOD_CHOICES, HTTP_AUTH_TYPE_CHOICES,
                                                ReputationContext)

# Required exceptions imports

# Extern modules imports

# Logger configuration imports
import logging

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


class ReputationContextForm(ModelForm):
    custom_headers = NoValidationField()

    class Meta:
        model = ReputationContext
        fields = ('name', 'description', 'db_type', 'method', 'url', 'verify_cert', 'post_data', 'auth_type', 'user',
                  'password', 'tags', 'enable_hour_download')

        widgets = {
            'name': TextInput(attrs={'class': 'form-control'}),
            'description': Textarea(attrs={'class': 'form-control'}),
            'db_type': Select(choices=DBTYPE_CHOICES, attrs={'class': 'form-control select2'}),
            'method': Select(choices=HTTP_METHOD_CHOICES, attrs={'class': 'form-control select2'}),
            'url': TextInput(attrs={'class': 'form-control'}),
            'verify_cert': CheckboxInput(attrs={'class': "form-control js-switch"}),
            'enable_hour_download': CheckboxInput(attrs={'class': "form-control js-switch"}),
            'post_data': TextInput(attrs={'class': 'form-control'}),
            'auth_type': Select(choices=HTTP_AUTH_TYPE_CHOICES, attrs={'class': 'form-control select2'}),
            'user': TextInput(attrs={'class': 'form-control'}),
            'password': TextInput(attrs={'class': 'form-control'}),
            'tags': TextInput(attrs={'class': 'form-control', 'data-role': "tagsinput"})
        }

    def __init__(self, *args, **kwargs):
        """ Initialize form and special attributes """
        super().__init__(*args, **kwargs)
        for field_name in ['auth_type', 'verify_cert', 'post_data', 'user', 'password', 'tags']:
            self.fields[field_name].required = False
        # Set readonly if internal reputation context
        if kwargs.get('instance') and kwargs.get('instance').internal:
            for field in self.fields:
                self.fields[field].widget.attrs['readonly'] = True
        self.initial['tags'] = ','.join(self.initial.get('tags', []) or self.fields['tags'].initial)

    def clean_tags(self):
        tags = self.cleaned_data.get('tags')
        if tags:
            return [i.replace(" ", "") for i in self.cleaned_data['tags'].split(',')]
        return []

    def clean(self, *args, **kwargs):
        cleaned_data = super().clean()
        if self.instance.internal:
            for field in ('name', 'description', 'db_type', 'method', 'url', 'verify_cert', 'post_data', 'auth_type', 'user',
                  'password'):
                self.cleaned_data.pop(field)

        if cleaned_data.get('auth_type') and not cleaned_data.get('user'):
            self.add_error('user', "At least User is required is any authentication method is selected.")
        return cleaned_data
