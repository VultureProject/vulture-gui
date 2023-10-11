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
from django.core.validators import RegexValidator
from django.forms import ModelChoiceField, ModelForm, TextInput, CheckboxInput, NumberInput, Select

# Django project imports
from applications.logfwd.models import (LogOMFile, LogOMRELP, LogOMHIREDIS, LogOMFWD, LogOMElasticSearch, LogOMMongoDB, LogOMKAFKA,
                                        OMFWD_PROTOCOL)
from system.pki.models import X509Certificate

# Required exceptions imports
from django.forms import ValidationError

# Additional module imports
from ast import literal_eval as ast_literal_eval

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


class LogOMFileForm(ModelForm):

    class Meta:
        model = LogOMFile
        fields = ('name', 'enabled', 'file', 'flush_interval', 'async_writing', 'send_as_raw', 'retention_time',
                  'rotation_period', 'queue_size', 'dequeue_size', 'queue_timeout_shutdown', 'max_workers',
                  'new_worker_minimum_messages', 'worker_timeout_shutdown', 'enable_retry', 'enable_disk_assist',
                  'high_watermark', 'low_watermark', 'max_file_size', 'max_disk_space')

        widgets = {
            'enabled': CheckboxInput(attrs={"class": " js-switch"}),
            'name': TextInput(attrs={'class': 'form-control'}),
            'file': TextInput(attrs={'class': 'form-control'}),
            'flush_interval': NumberInput(attrs={'class': 'form-control'}),
            'async_writing': CheckboxInput(attrs={"class": " js-switch"}),
            'send_as_raw': CheckboxInput(attrs={"class": " js-switch"}),
            'retention_time': NumberInput(attrs={"class": "form-control"}),
            'rotation_period': Select(attrs={"class": "select2"}),
            'queue_size': NumberInput(attrs={'class': 'form-control'}),
            'dequeue_size': NumberInput(attrs={'class': 'form-control'}),
            'queue_timeout_shutdown': NumberInput(attrs={'class': 'form-control', 'placeholder': 10}),
            'max_workers': NumberInput(attrs={'class': 'form-control', 'placeholder': 1}),
            'new_worker_minimum_messages': NumberInput(attrs={'class': 'form-control', 'placeholder': 'queue size / max workers'}),
            'worker_timeout_shutdown': NumberInput(attrs={'class': 'form-control', 'placeholder': 60_000}),
            'enable_retry': CheckboxInput(attrs={"class": " js-switch"}),
            'enable_disk_assist': CheckboxInput(attrs={"class": " js-switch"}),
            'high_watermark': NumberInput(attrs={'class': 'form-control'}),
            'low_watermark': NumberInput(attrs={'class': 'form-control'}),
            'max_file_size': NumberInput(attrs={'class': 'form-control'}),
            'max_disk_space': NumberInput(attrs={'class': 'form-control'})
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['retention_time'].empty_label = None
        self.fields['rotation_period'].empty_label = None
        for field_name in ['high_watermark', 'low_watermark', 'max_file_size', 'max_disk_space']:
            self.fields[field_name].required = False

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

    def clean(self):
        """ Verify needed fields - depending on mode chosen """
        cleaned_data = super().clean()
        if cleaned_data.get('enable_disk_assist') == True:
            try:
                assert cleaned_data.get('high_watermark'), "high_watermark"
                assert cleaned_data.get('low_watermark'), "low_watermark"
            except AssertionError as e:
                self.add_error(str(e), "This field is required.")
            else:
                if cleaned_data.get('queue_size') and (cleaned_data.get('queue_size') < cleaned_data.get('high_watermark') or cleaned_data.get('queue_size') < cleaned_data.get('low_watermark')):
                    self.add_error("queue_size", "Queue size is lower than a watermark")
                if cleaned_data.get('high_watermark') < cleaned_data.get('low_watermark'):
                    self.add_error("high_watermark", "High watermark is lower than the low watermark value")
                    self.add_error("low_watermark", "Low watermark is higher than the high watermark value")
            try:
                assert cleaned_data.get('max_file_size'), "max_file_size"
                assert cleaned_data.get('max_disk_space'), "max_disk_space"
            except AssertionError as e:
                self.add_error(str(e), "This field is required.")
            else:
                if cleaned_data.get('max_file_size') > cleaned_data.get('max_disk_space'):
                    self.add_error("max_file_size", "File size is higher than the disk space")
        if cleaned_data.get('new_worker_minimum_messages'):
            if cleaned_data['new_worker_minimum_messages'] > cleaned_data.get('queue_size', 10000):
                self.add_error("new_worker_minimum_messages", "This value cannot be over the queue size")
        return cleaned_data


class LogOMRELPForm(ModelForm):

    class Meta:
        model = LogOMRELP
        fields = ('name', 'enabled', 'target', 'port', 'tls_enabled', 'x509_certificate', 'send_as_raw', 'queue_size',
                  'dequeue_size', 'queue_timeout_shutdown', 'max_workers', 'new_worker_minimum_messages',
                  'worker_timeout_shutdown', 'enable_retry', 'enable_disk_assist', 'high_watermark', 'low_watermark',
                  'max_file_size', 'max_disk_space')

        widgets = {
            'enabled': CheckboxInput(attrs={"class": " js-switch"}),
            'name': TextInput(attrs={'class': 'form-control'}),
            'target': TextInput(attrs={'class': 'form-control'}),
            'port': NumberInput(attrs={'class': 'form-control'}),
            'tls_enabled': CheckboxInput(attrs={"class": " js-switch"}),
            'x509_certificate': Select(attrs={'class': 'form-control select2'}),
            'send_as_raw': CheckboxInput(attrs={'class': 'form-control js-switch'}),
            'queue_size': NumberInput(attrs={'class': 'form-control'}),
            'dequeue_size': NumberInput(attrs={'class': 'form-control'}),
            'queue_timeout_shutdown': NumberInput(attrs={'class': 'form-control', 'placeholder': 10}),
            'max_workers': NumberInput(attrs={'class': 'form-control', 'placeholder': 1}),
            'new_worker_minimum_messages': NumberInput(attrs={'class': 'form-control', 'placeholder': 'queue size / max workers'}),
            'worker_timeout_shutdown': NumberInput(attrs={'class': 'form-control', 'placeholder': 60_000}),
            'enable_retry': CheckboxInput(attrs={"class": " js-switch"}),
            'enable_disk_assist': CheckboxInput(attrs={"class": " js-switch"}),
            'high_watermark': NumberInput(attrs={'class': 'form-control'}),
            'low_watermark': NumberInput(attrs={'class': 'form-control'}),
            'max_file_size': NumberInput(attrs={'class': 'form-control'}),
            'max_disk_space': NumberInput(attrs={'class': 'form-control'})
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['x509_certificate'].empty_label = "No TLS certificate"
        for field_name in ['x509_certificate', 'high_watermark', 'low_watermark', 'max_file_size', 'max_disk_space']:
            self.fields[field_name].required = False

    def clean_name(self):
        field = self.cleaned_data.get('name')
        if not field:
            raise ValidationError("This field is required.")
        return field.replace(' ', '_')

    def clean(self):
        cleaned_data = super().clean()
        if not cleaned_data.get('tls_enabled') and cleaned_data.get('x509_certificate'):
            self.add_error('tls_enabled', "You must enable tls to specify a certificate.")
        if cleaned_data.get('enable_disk_assist') == True:
            try:
                assert cleaned_data.get('high_watermark'), "high_watermark"
                assert cleaned_data.get('low_watermark'), "low_watermark"
            except AssertionError as e:
                self.add_error(str(e), "This field is required.")
            else:
                if cleaned_data.get('queue_size') and (cleaned_data.get('queue_size') < cleaned_data.get('high_watermark') or cleaned_data.get('queue_size') < cleaned_data.get('low_watermark')):
                    self.add_error("queue_size", "Queue size is lower than a watermark")
                if cleaned_data.get('high_watermark') < cleaned_data.get('low_watermark'):
                    self.add_error("high_watermark", "High watermark is lower than the low watermark value")
                    self.add_error("low_watermark", "Low watermark is higher than the high watermark value")
            try:
                assert cleaned_data.get('max_file_size'), "max_file_size"
                assert cleaned_data.get('max_disk_space'), "max_disk_space"
            except AssertionError as e:
                self.add_error(str(e), "This field is required.")
            else:
                if cleaned_data.get('max_file_size') > cleaned_data.get('max_disk_space'):
                    self.add_error("max_file_size", "File size is higher than the disk space")
        if cleaned_data.get('new_worker_minimum_messages'):
            if cleaned_data['new_worker_minimum_messages'] > cleaned_data.get('queue_size', 10000):
                self.add_error("new_worker_minimum_messages", "This value cannot be over the queue size")
        return cleaned_data


class LogOMHIREDISForm(ModelForm):

    class Meta:
        model = LogOMHIREDIS
        fields = ('name', 'enabled', 'target', 'port', 'key', 'dynamic_key', 'pwd', 'send_as_raw',
                  'queue_size', 'dequeue_size', 'queue_timeout_shutdown', 'max_workers', 'new_worker_minimum_messages',
                  'worker_timeout_shutdown', 'enable_retry', 'enable_disk_assist', 'high_watermark', 'low_watermark',
                  'max_file_size', 'max_disk_space')

        widgets = {
            'enabled': CheckboxInput(attrs={"class": " js-switch"}),
            'name': TextInput(attrs={'class': 'form-control'}),
            'target': TextInput(attrs={'class': 'form-control'}),
            'port': NumberInput(attrs={'class': 'form-control'}),
            'key': TextInput(attrs={'class': 'form-control'}),
            'dynamic_key': CheckboxInput(attrs={'class': ' js-switch'}),
            'pwd': TextInput(attrs={'class': 'form-control'}),
            'send_as_raw': CheckboxInput(attrs={'class': 'form-control js-switch'}),
            'queue_size': NumberInput(attrs={'class': 'form-control'}),
            'dequeue_size': NumberInput(attrs={'class': 'form-control'}),
            'queue_timeout_shutdown': NumberInput(attrs={'class': 'form-control', 'placeholder': 10}),
            'max_workers': NumberInput(attrs={'class': 'form-control', 'placeholder': 1}),
            'new_worker_minimum_messages': NumberInput(attrs={'class': 'form-control', 'placeholder': 'queue size / max workers'}),
            'worker_timeout_shutdown': NumberInput(attrs={'class': 'form-control', 'placeholder': 60_000}),
            'enable_retry': CheckboxInput(attrs={"class": " js-switch"}),
            'enable_disk_assist': CheckboxInput(attrs={"class": " js-switch"}),
            'high_watermark': NumberInput(attrs={'class': 'form-control'}),
            'low_watermark': NumberInput(attrs={'class': 'form-control'}),
            'max_file_size': NumberInput(attrs={'class': 'form-control'}),
            'max_disk_space': NumberInput(attrs={'class': 'form-control'})
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name in ['high_watermark', 'low_watermark', 'max_file_size', 'max_disk_space']:
            self.fields[field_name].required = False

    def clean_name(self):
        field = self.cleaned_data.get('name')
        if not field:
            raise ValidationError("This field is required.")
        return field.replace(' ', '_')

    def clean_key(self):
        key = self.cleaned_data.get('key')
        if " " in key:
            raise ValidationError("Cannot contain spaces")
        return key

    def clean(self):
        """ Verify needed fields - depending on mode chosen """
        cleaned_data = super().clean()
        if cleaned_data.get('enable_disk_assist') == True:
            try:
                assert cleaned_data.get('high_watermark'), "high_watermark"
                assert cleaned_data.get('low_watermark'), "low_watermark"
            except AssertionError as e:
                self.add_error(str(e), "This field is required.")
            else:
                if cleaned_data.get('queue_size') and (cleaned_data.get('queue_size') < cleaned_data.get('high_watermark') or cleaned_data.get('queue_size') < cleaned_data.get('low_watermark')):
                    self.add_error("queue_size", "Queue size is lower than a watermark")
                if cleaned_data.get('high_watermark') < cleaned_data.get('low_watermark'):
                    self.add_error("high_watermark", "High watermark is lower than the low watermark value")
                    self.add_error("low_watermark", "Low watermark is higher than the high watermark value")
            try:
                assert cleaned_data.get('max_file_size'), "max_file_size"
                assert cleaned_data.get('max_disk_space'), "max_disk_space"
            except AssertionError as e:
                self.add_error(str(e), "This field is required.")
            else:
                if cleaned_data.get('max_file_size') > cleaned_data.get('max_disk_space'):
                    self.add_error("max_file_size", "File size is higher than the disk space")
        if cleaned_data.get('dynamic_key') == True and cleaned_data.get('key'):
            key = cleaned_data.get('key')
            if key.count("%") % 2 != 0:
                self.add_error("key", "seems like your number of '%' is incorrect, please check your templated key")
        if cleaned_data.get('new_worker_minimum_messages'):
            if cleaned_data['new_worker_minimum_messages'] > cleaned_data.get('queue_size', 10000):
                self.add_error("new_worker_minimum_messages", "This value cannot be over the queue size")
        return cleaned_data


class LogOMFWDForm(ModelForm):

    class Meta:
        model = LogOMFWD
        fields = ('name', 'enabled', 'target', 'port', 'protocol', 'zip_level', 'queue_size', 'dequeue_size',
                  'queue_timeout_shutdown', 'max_workers', 'new_worker_minimum_messages', 'worker_timeout_shutdown',
                  'enable_retry', 'enable_disk_assist', 'high_watermark', 'low_watermark', 'max_file_size',
                  'max_disk_space', 'ratelimit_interval', 'ratelimit_burst', 'send_as_raw')

        widgets = {
            'enabled': CheckboxInput(attrs={"class": " js-switch"}),
            'name': TextInput(attrs={'class': 'form-control'}),
            'target': TextInput(attrs={'class': 'form-control'}),
            'port': NumberInput(attrs={'class': 'form-control'}),
            'protocol': Select(choices=OMFWD_PROTOCOL, attrs={'class': 'form-control select2'}),
            'zip_level': NumberInput(attrs={'class': 'form-control'}),
            'queue_size': NumberInput(attrs={'class': 'form-control'}),
            'dequeue_size': NumberInput(attrs={'class': 'form-control'}),
            'queue_timeout_shutdown': NumberInput(attrs={'class': 'form-control', 'placeholder': 10}),
            'max_workers': NumberInput(attrs={'class': 'form-control', 'placeholder': 1}),
            'new_worker_minimum_messages': NumberInput(attrs={'class': 'form-control', 'placeholder': 'queue size / max workers'}),
            'worker_timeout_shutdown': NumberInput(attrs={'class': 'form-control', 'placeholder': 60_000}),
            'enable_retry': CheckboxInput(attrs={"class": " js-switch"}),
            'enable_disk_assist': CheckboxInput(attrs={"class": " js-switch"}),
            'high_watermark': NumberInput(attrs={'class': 'form-control'}),
            'low_watermark': NumberInput(attrs={'class': 'form-control'}),
            'max_file_size': NumberInput(attrs={'class': 'form-control'}),
            'max_disk_space': NumberInput(attrs={'class': 'form-control'}),
            'ratelimit_interval': NumberInput(attrs={'class': 'form-control'}),
            'ratelimit_burst': NumberInput(attrs={'class': 'form-control'}),
            'send_as_raw': CheckboxInput(attrs={'class': 'form-control js-switch'})
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name in ['high_watermark', 'low_watermark', 'max_file_size', 'max_disk_space']:
            self.fields[field_name].required = False

    def clean_name(self):
        field = self.cleaned_data.get('name')
        if not field:
            raise ValidationError("This field is required.")
        return field.replace(' ', '_')

    def clean(self):
        """ Verify needed fields - depending on mode chosen """
        cleaned_data = super().clean()
        if cleaned_data.get('enable_disk_assist') == True:
            try:
                assert cleaned_data.get('high_watermark'), "high_watermark"
                assert cleaned_data.get('low_watermark'), "low_watermark"
            except AssertionError as e:
                self.add_error(str(e), "This field is required.")
            else:
                if cleaned_data.get('queue_size') and (cleaned_data.get('queue_size') < cleaned_data.get('high_watermark') or cleaned_data.get('queue_size') < cleaned_data.get('low_watermark')):
                    self.add_error("queue_size", "Queue size is lower than a watermark")
                if cleaned_data.get('high_watermark') < cleaned_data.get('low_watermark'):
                    self.add_error("high_watermark", "High watermark is lower than the low watermark value")
                    self.add_error("low_watermark", "Low watermark is higher than the high watermark value")
            try:
                assert cleaned_data.get('max_file_size'), "max_file_size"
                assert cleaned_data.get('max_disk_space'), "max_disk_space"
            except AssertionError as e:
                self.add_error(str(e), "This field is required.")
            else:
                if cleaned_data.get('max_file_size') > cleaned_data.get('max_disk_space'):
                    self.add_error("max_file_size", "File size is higher than the disk space")
        """ if ratelimit_interval or ratelimit_burst is specified, the other cannot be left blank"""
        if cleaned_data.get('ratelimit_interval') and not cleaned_data.get('ratelimit_burst'):
            self.add_error("ratelimit_burst", "This field cannot be left blank if rate-limiting interval is set")
        if cleaned_data.get('ratelimit_burst') and not cleaned_data.get('ratelimit_interval'):
            self.add_error("ratelimit_interval", "This field cannot be left blank if rate-limiting burst is set")
        if cleaned_data.get('new_worker_minimum_messages'):
            if cleaned_data['new_worker_minimum_messages'] > cleaned_data.get('queue_size', 10000):
                self.add_error("new_worker_minimum_messages", "This value cannot be over the queue size")
        return cleaned_data


class LogOMElasticSearchForm(ModelForm):

    class Meta:
        model = LogOMElasticSearch
        fields = ('name', 'enabled', 'servers', 'es8_compatibility', 'data_stream_mode', 'index_pattern', 'uid', 'pwd',
                  'x509_certificate', 'send_as_raw', 'queue_size', 'dequeue_size', 'queue_timeout_shutdown',
                  'max_workers', 'new_worker_minimum_messages', 'worker_timeout_shutdown', 'enable_retry',
                  'enable_disk_assist', 'high_watermark', 'low_watermark', 'max_file_size', 'max_disk_space')

        widgets = {
            'enabled': CheckboxInput(attrs={"class": " js-switch"}),
            'name': TextInput(attrs={'class': 'form-control'}),
            'servers': TextInput(attrs={'class': 'form-control'}),
            'es8_compatibility': CheckboxInput(attrs={"class": " js-switch"}),
            'data_stream_mode': CheckboxInput(attrs={"class": " js-switch"}),
            'index_pattern': TextInput(attrs={'class': 'form-control'}),
            'uid': TextInput(attrs={'class': 'form-control'}),
            'pwd': TextInput(attrs={'class': 'form-control'}),
            'x509_certificate': Select(attrs={'class': 'form-control'}),
            'send_as_raw': CheckboxInput(attrs={'class': 'form-control js-switch'}),
            'queue_size': NumberInput(attrs={'class': 'form-control'}),
            'dequeue_size': NumberInput(attrs={'class': 'form-control'}),
            'queue_timeout_shutdown': NumberInput(attrs={'class': 'form-control', 'placeholder': 10}),
            'max_workers': NumberInput(attrs={'class': 'form-control', 'placeholder': 1}),
            'new_worker_minimum_messages': NumberInput(attrs={'class': 'form-control', 'placeholder': 'queue size / max workers'}),
            'worker_timeout_shutdown': NumberInput(attrs={'class': 'form-control', 'placeholder': 60_000}),
            'enable_retry': CheckboxInput(attrs={"class": " js-switch"}),
            'enable_disk_assist': CheckboxInput(attrs={"class": " js-switch"}),
            'high_watermark': NumberInput(attrs={'class': 'form-control'}),
            'low_watermark': NumberInput(attrs={'class': 'form-control'}),
            'max_file_size': NumberInput(attrs={'class': 'form-control'}),
            'max_disk_space': NumberInput(attrs={'class': 'form-control'})
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['x509_certificate'].empty_label = "No TLS certificate"
        for field_name in ['x509_certificate', 'high_watermark', 'low_watermark', 'max_file_size', 'max_disk_space']:
            self.fields[field_name].required = False

    def clean_name(self):
        field = self.cleaned_data.get('name')
        if not field:
            raise ValidationError("This field is required.")
        return field.replace(' ', '_')

    def clean_index_pattern(self):
        field = self.cleaned_data.get('index_pattern')
        if field:
            return field.lower()

    def clean(self):
        """ Verify needed fields - depending on mode chosen """
        cleaned_data = super().clean()
        if cleaned_data.get('enable_disk_assist') == True:
            try:
                assert cleaned_data.get('high_watermark'), "high_watermark"
                assert cleaned_data.get('low_watermark'), "low_watermark"
            except AssertionError as e:
                self.add_error(str(e), "This field is required.")
            else:
                if cleaned_data.get('queue_size') and (cleaned_data.get('queue_size') < cleaned_data.get('high_watermark') or cleaned_data.get('queue_size') < cleaned_data.get('low_watermark')):
                    self.add_error("queue_size", "Queue size is lower than a watermark")
                if cleaned_data.get('high_watermark') < cleaned_data.get('low_watermark'):
                    self.add_error("high_watermark", "High watermark is lower than the low watermark value")
                    self.add_error("low_watermark", "Low watermark is higher than the high watermark value")
            try:
                assert cleaned_data.get('max_file_size'), "max_file_size"
                assert cleaned_data.get('max_disk_space'), "max_disk_space"
            except AssertionError as e:
                self.add_error(str(e), "This field is required.")
            else:
                if cleaned_data.get('max_file_size') > cleaned_data.get('max_disk_space'):
                    self.add_error("max_file_size", "File size is higher than the disk space")
        if cleaned_data.get('new_worker_minimum_messages'):
            if cleaned_data['new_worker_minimum_messages'] > cleaned_data.get('queue_size', 10000):
                self.add_error("new_worker_minimum_messages", "This value cannot be over the queue size")
        return cleaned_data


class LogOMMongoDBForm(ModelForm):
    x509_certificate = ModelChoiceField(
        queryset=X509Certificate.objects.filter(is_ca=False).only(*(X509Certificate.str_attrs())),
        required=False,
        widget=Select(attrs={'class': 'form-control select2'}),
        empty_label="No SSL"
    )

    class Meta:
        model = LogOMMongoDB
        fields = ('name', 'enabled', 'db', 'collection', 'uristr', 'x509_certificate', 'send_as_raw', 'queue_size',
                  'dequeue_size', 'queue_timeout_shutdown', 'max_workers', 'new_worker_minimum_messages',
                  'worker_timeout_shutdown', 'enable_retry', 'enable_disk_assist', 'high_watermark', 'low_watermark',
                  'max_file_size', 'max_disk_space')

        widgets = {
            'enabled': CheckboxInput(attrs={"class": " js-switch"}),
            'name': TextInput(attrs={'class': 'form-control'}),
            'db': TextInput(attrs={'class': 'form-control'}),
            'collection': TextInput(attrs={'class': 'form-control'}),
            'uristr': TextInput(attrs={'class': 'form-control'}),
            'send_as_raw': CheckboxInput(attrs={'class': 'form-control js-switch'}),
            'queue_size': NumberInput(attrs={'class': 'form-control'}),
            'dequeue_size': NumberInput(attrs={'class': 'form-control'}),
            'queue_timeout_shutdown': NumberInput(attrs={'class': 'form-control', 'placeholder': 10}),
            'max_workers': NumberInput(attrs={'class': 'form-control', 'placeholder': 1}),
            'new_worker_minimum_messages': NumberInput(attrs={'class': 'form-control', 'placeholder': 'queue size / max workers'}),
            'worker_timeout_shutdown': NumberInput(attrs={'class': 'form-control', 'placeholder': 60_000}),
            'enable_retry': CheckboxInput(attrs={"class": " js-switch"}),
            'enable_disk_assist': CheckboxInput(attrs={"class": " js-switch"}),
            'high_watermark': NumberInput(attrs={'class': 'form-control'}),
            'low_watermark': NumberInput(attrs={'class': 'form-control'}),
            'max_file_size': NumberInput(attrs={'class': 'form-control'}),
            'max_disk_space': NumberInput(attrs={'class': 'form-control'})
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name in ['high_watermark', 'low_watermark', 'max_file_size', 'max_disk_space']:
            self.fields[field_name].required = False

    def clean_name(self):
        field = self.cleaned_data.get('name')
        if not field:
            raise ValidationError("This field is required.")
        return field.replace(' ', '_')

    def clean(self):
        """ Verify needed fields - depending on mode chosen """
        cleaned_data = super().clean()
        if cleaned_data.get('enable_disk_assist') == True:
            try:
                assert cleaned_data.get('high_watermark'), "high_watermark"
                assert cleaned_data.get('low_watermark'), "low_watermark"
            except AssertionError as e:
                self.add_error(str(e), "This field is required.")
            else:
                if cleaned_data.get('queue_size') and (cleaned_data.get('queue_size') < cleaned_data.get('high_watermark') or cleaned_data.get('queue_size') < cleaned_data.get('low_watermark')):
                    self.add_error("queue_size", "Queue size is lower than a watermark")
                if cleaned_data.get('high_watermark') < cleaned_data.get('low_watermark'):
                    self.add_error("high_watermark", "High watermark is lower than the low watermark value")
                    self.add_error("low_watermark", "Low watermark is higher than the high watermark value")
            try:
                assert cleaned_data.get('max_file_size'), "max_file_size"
                assert cleaned_data.get('max_disk_space'), "max_disk_space"
            except AssertionError as e:
                self.add_error(str(e), "This field is required.")
            else:
                if cleaned_data.get('max_file_size') > cleaned_data.get('max_disk_space'):
                    self.add_error("max_file_size", "File size is higher than the disk space")
        if cleaned_data.get('new_worker_minimum_messages'):
            if cleaned_data['new_worker_minimum_messages'] > cleaned_data.get('queue_size', 10000):
                self.add_error("new_worker_minimum_messages", "This value cannot be over the queue size")
        return cleaned_data


class LogOMKafkaForm(ModelForm):

    class Meta:
        model = LogOMKAFKA
        fields = ('name', 'enabled', 'broker', 'topic', 'key', 'dynaKey', 'dynaTopic', 'partitions_useFixed',
                  'partitions_auto', 'confParam', 'topicConfParam', 'queue_size', 'dequeue_size',
                  'queue_timeout_shutdown', 'max_workers', 'new_worker_minimum_messages', 'worker_timeout_shutdown',
                  'enable_retry', 'enable_disk_assist', 'high_watermark', 'low_watermark', 'max_file_size',
                  'max_disk_space')

        widgets = {
            'enabled': CheckboxInput(attrs={"class": " js-switch"}),
            'name': TextInput(attrs={'class': 'form-control'}),
            'broker': TextInput(attrs={'class': 'form-control'}),
            'topic': TextInput(attrs={'class': 'form-control'}),
            'key': TextInput(attrs={'class': 'form-control'}),
            'dynaKey': CheckboxInput(attrs={"class": " js-switch"}),
            'dynaTopic': CheckboxInput(attrs={"class": " js-switch"}),
            'partitions_useFixed': NumberInput(attrs={'class': 'form-control'}),
            'partitions_auto': CheckboxInput(attrs={"class": " js-switch"}),
            'confParam': TextInput(attrs={'class': 'form-control', 'data-role': "tagsinput"}),
            'topicConfParam': TextInput(attrs={'class': 'form-control', 'data-role': "tagsinput"}),
            'queue_size': NumberInput(attrs={'class': 'form-control'}),
            'dequeue_size': NumberInput(attrs={'class': 'form-control'}),
            'queue_timeout_shutdown': NumberInput(attrs={'class': 'form-control', 'placeholder': 10}),
            'max_workers': NumberInput(attrs={'class': 'form-control', 'placeholder': 1}),
            'new_worker_minimum_messages': NumberInput(attrs={'class': 'form-control', 'placeholder': 'queue size / max workers'}),
            'worker_timeout_shutdown': NumberInput(attrs={'class': 'form-control', 'placeholder': 60_000}),
            'enable_retry': CheckboxInput(attrs={"class": " js-switch"}),
            'enable_disk_assist': CheckboxInput(attrs={"class": " js-switch"}),
            'high_watermark': NumberInput(attrs={'class': 'form-control'}),
            'low_watermark': NumberInput(attrs={'class': 'form-control'}),
            'max_file_size': NumberInput(attrs={'class': 'form-control'}),
            'max_disk_space': NumberInput(attrs={'class': 'form-control'})
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name in ['high_watermark', 'low_watermark', 'max_file_size', 'max_disk_space']:
            self.fields[field_name].required = False

        self.initial['confParam'] = ','.join(self.initial.get('confParam', []) or self.fields['confParam'].initial)
        self.initial['topicConfParam'] = ','.join(self.initial.get('topicConfParam', []) or self.fields['topicConfParam'].initial)

    def clean_name(self):
        field = self.cleaned_data.get('name')
        if not field:
            raise ValidationError("This field is required.")
        return field.replace(' ', '_')

    def clean_key(self):
        key = self.cleaned_data.get('key')
        if " " in key:
            raise ValidationError("Cannot contain spaces")
        return key

    def clean_topic(self):
        topic = self.cleaned_data.get('topic')
        if " " in topic:
            raise ValidationError("Cannot contain spaces")
        return topic

    def clean_confParam(self):
        data = self.cleaned_data.get('confParam')
        cleaned = []
        if not data:
            return cleaned
        try:
            data = ast_literal_eval(data)
        except Exception:
            data = [entry.strip() for entry in data.split(',')]
        for entry in data:
            kv = entry.split('=', 1)
            if len(kv) < 2:
                raise ValidationError("Every option should be a key/value separated by a '='")
            kv[0] = kv[0].strip()
            kv[1] = kv[1].strip().replace("'", '"')
            try:
                RegexValidator('^[A-Za-z0-9-._]+$')(kv[0])
            except Exception:
                raise ValidationError("Only letters, digits, '-' (dash), '_' (underscore) and '.' (dot) are allowed in the keys.")
            cleaned.append(kv[0] + "=" + kv[1])
        return cleaned

    def clean_topicConfParam(self):
        data = self.cleaned_data.get('topicConfParam')
        cleaned = []
        if not data:
            return cleaned
        try:
            data = ast_literal_eval(data)
        except Exception:
            data = [entry.strip() for entry in data.split(',')]
        for entry in data:
            kv = entry.split('=', 1)
            if len(kv) < 2:
                raise ValidationError("Every option should be a key/value separated by a '='")
            kv[0] = kv[0].strip()
            kv[1] = kv[1].strip().replace("'", '"')
            try:
                RegexValidator('^[A-Za-z0-9-._]+$')(kv[0])
            except Exception:
                raise ValidationError("Only letters, digits, '-' (dash), '_' (underscore) and '.' (dot) are allowed in the keys.")
            cleaned.append(kv[0] + "=" + kv[1])
        return cleaned

    def clean(self):
        """ Verify needed fields - depending on mode chosen """
        cleaned_data = super().clean()
        if cleaned_data.get('enable_disk_assist') == True:
            try:
                assert cleaned_data.get('high_watermark'), "high_watermark"
                assert cleaned_data.get('low_watermark'), "low_watermark"
            except AssertionError as e:
                self.add_error(str(e), "This field is required.")
            else:
                if cleaned_data.get('queue_size') and (cleaned_data.get('queue_size') < cleaned_data.get('high_watermark') or cleaned_data.get('queue_size') < cleaned_data.get('low_watermark')):
                    self.add_error("queue_size", "Queue size is lower than a watermark")
                if cleaned_data.get('high_watermark') < cleaned_data.get('low_watermark'):
                    self.add_error("high_watermark", "High watermark is lower than the low watermark value")
                    self.add_error("low_watermark", "Low watermark is higher than the high watermark value")
            try:
                assert cleaned_data.get('max_file_size'), "max_file_size"
                assert cleaned_data.get('max_disk_space'), "max_disk_space"
            except AssertionError as e:
                self.add_error(str(e), "This field is required.")
            else:
                if cleaned_data.get('max_file_size') > cleaned_data.get('max_disk_space'):
                    self.add_error("max_file_size", "File size is higher than the disk space")
        if cleaned_data.get('dynaKey') == True:
            if cleaned_data.get('key'):
                key = cleaned_data.get('key')
                if key.count("%") % 2 != 0:
                    self.add_error("key", "seems like your number of '%' is incorrect, please check your templated key")
            else:
                self.add_error("key", "This field is required.")
        if cleaned_data.get('dynaTopic') == True and cleaned_data.get('topic'):
            topic = cleaned_data.get('topic')
            if topic.count("%") % 2 != 0:
                self.add_error("topic", "seems like your number of '%' is incorrect, please check your templated topic")
        if cleaned_data.get('new_worker_minimum_messages'):
            if cleaned_data['new_worker_minimum_messages'] > cleaned_data.get('queue_size', 10000):
                self.add_error("new_worker_minimum_messages", "This value cannot be over the queue size")
        return cleaned_data