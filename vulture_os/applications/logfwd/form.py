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
__doc__ = 'rsyslog dedicated form classes'

# Django system imports
from django.conf import settings
from django.forms import ModelChoiceField, ModelForm, TextInput, CheckboxInput, NumberInput, Select

# Django project imports
from applications.logfwd.models import (LogOMFile, LogOMRELP, LogOMHIREDIS, LogOMFWD, LogOMElasticSearch, LogOMMongoDB,
                                        OMFWD_PROTOCOL)
from system.pki.models import X509Certificate

# Required exceptions imports
from django.forms import ValidationError

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


class LogOMFileForm(ModelForm):

    class Meta:
        model = LogOMFile
        fields = ('name', 'enabled', 'file', 'flush_interval', 'async_writing', 'stock_as_raw', 'retention_time',
                  'rotation_period')

        widgets = {
            'enabled': CheckboxInput(attrs={"class": " js-switch"}),
            'name': TextInput(attrs={'class': 'form-control'}),
            'file': TextInput(attrs={'class': 'form-control'}),
            'flush_interval': NumberInput(attrs={'class': 'form-control'}),
            'async_writing': CheckboxInput(attrs={"class": " js-switch"}),
            'stock_as_raw': CheckboxInput(attrs={"class": " js-switch"}),
            'retention_time': NumberInput(attrs={"class": "form-control"}),
            'rotation_period': Select(attrs={"class": "select2"})
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['retention_time'].empty_label = None
        self.fields['rotation_period'].empty_label = None

    def clean_name(self):
        field = self.cleaned_data.get('name')
        if not field:
            raise ValidationError("This field is required.")
        return field.replace(' ', '_')

    def clean_file(self):
        value = self.cleaned_data.get('file')
        if not value.startswith('/'):
            raise ValidationError("That field needs absolute path.")
        return value


class LogOMRELPForm(ModelForm):

    class Meta:
        model = LogOMRELP
        fields = ('name', 'enabled', 'target', 'port', 'tls_enabled', 'x509_certificate')

        widgets = {
            'enabled': CheckboxInput(attrs={"class": " js-switch"}),
            'name': TextInput(attrs={'class': 'form-control'}),
            'target': TextInput(attrs={'class': 'form-control'}),
            'port': NumberInput(attrs={'class': 'form-control'}),
            'tls_enabled': CheckboxInput(attrs={"class": " js-switch"}),
            'x509_certificate': Select(attrs={'class': 'form-control select2'})
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['x509_certificate'].empty_label = "No TLS certificate"
        self.fields['x509_certificate'].required = False

    def clean_name(self):
        field = self.cleaned_data.get('name')
        if not field:
            raise ValidationError("This field is required.")
        return field.replace(' ', '_')

    def clean(self):
        cleaned_data = super().clean()
        if not cleaned_data.get('tls_enabled') and cleaned_data.get('x509_certificate'):
            self.add_error('tls_enabled', "You must enable tls to specify a certificate.")
        return cleaned_data


class LogOMHIREDISForm(ModelForm):

    class Meta:
        model = LogOMHIREDIS
        fields = ('name', 'enabled', 'target', 'port', 'key', 'pwd')

        widgets = {
            'enabled': CheckboxInput(attrs={"class": " js-switch"}),
            'name': TextInput(attrs={'class': 'form-control'}),
            'target': TextInput(attrs={'class': 'form-control'}),
            'port': NumberInput(attrs={'class': 'form-control'}),
            'key': TextInput(attrs={'class': 'form-control'}),
            'pwd': TextInput(attrs={'class': 'form-control'})
        }

    def clean_name(self):
        field = self.cleaned_data.get('name')
        if not field:
            raise ValidationError("This field is required.")
        return field.replace(' ', '_')


class LogOMFWDForm(ModelForm):

    class Meta:
        model = LogOMFWD
        fields = ('name', 'enabled', 'target', 'port', 'protocol', 'zip_level', 'send_as_raw')

        widgets = {
            'enabled': CheckboxInput(attrs={"class": " js-switch"}),
            'name': TextInput(attrs={'class': 'form-control'}),
            'target': TextInput(attrs={'class': 'form-control'}),
            'port': NumberInput(attrs={'class': 'form-control'}),
            'protocol': Select(choices=OMFWD_PROTOCOL, attrs={'class': 'form-control select2'}),
            'zip_level': NumberInput(attrs={'class': 'form-control'}),
            'send_as_raw': CheckboxInput(attrs={'class': 'form-control js-switch'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def clean_name(self):
        field = self.cleaned_data.get('name')
        if not field:
            raise ValidationError("This field is required.")
        return field.replace(' ', '_')


class LogOMElasticSearchForm(ModelForm):

    class Meta:
        model = LogOMElasticSearch
        fields = ('name', 'enabled', 'index_pattern', 'servers', 'uid', 'pwd', 'x509_certificate')

        widgets = {
            'enabled': CheckboxInput(attrs={"class": " js-switch"}),
            'name': TextInput(attrs={'class': 'form-control'}),
            'index_pattern': TextInput(attrs={'class': 'form-control'}),
            'servers': TextInput(attrs={'class': 'form-control'}),
            'uid': TextInput(attrs={'class': 'form-control'}),
            'pwd': TextInput(attrs={'class': 'form-control'}),
            'x509_certificate': Select(attrs={'class': 'form-control'})
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['x509_certificate'].empty_label = "No TLS certificate"
        self.fields['x509_certificate'].required = False

    def clean_name(self):
        field = self.cleaned_data.get('name')
        if not field:
            raise ValidationError("This field is required.")
        return field.replace(' ', '_')


class LogOMMongoDBForm(ModelForm):
    x509_certificate = ModelChoiceField(
        queryset=X509Certificate.objects.filter(is_ca=False).only(*(X509Certificate.str_attrs())),
        required=False,
        widget=Select(attrs={'class': 'form-control select2'}),
        empty_label="No SSL"
    )

    class Meta:
        model = LogOMMongoDB
        fields = ('name', 'enabled', 'db', 'collection', 'uristr', 'x509_certificate')

        widgets = {
            'enabled': CheckboxInput(attrs={"class": " js-switch"}),
            'name': TextInput(attrs={'class': 'form-control'}),
            'db': TextInput(attrs={'class': 'form-control'}),
            'collection': TextInput(attrs={'class': 'form-control'}),
            'uristr': TextInput(attrs={'class': 'form-control'})
        }

    def clean_name(self):
        field = self.cleaned_data.get('name')
        if not field:
            raise ValidationError("This field is required.")
        return field.replace(' ', '_')
