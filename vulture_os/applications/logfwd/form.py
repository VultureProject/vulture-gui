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
from django.forms import ModelChoiceField, ModelForm, TextInput, CheckboxInput, NumberInput, Select, URLInput

# Django project imports
from applications.logfwd.models import (LogOM, LogOMFile, LogOMRELP, LogOMHIREDIS, LogOMFWD, LogOMElasticSearch,
                                        LogOMMongoDB, LogOMKAFKA, LogOMSentinel,
                                        OMFWD_PROTOCOL, OMHIREDIS_MODE_CHOICES, ZLIB_LEVEL_CHOICES)
from system.pki.models import X509Certificate, TLSProfile

# Required exceptions imports
from django.forms import ValidationError

# Additional module imports
from ast import literal_eval as ast_literal_eval
from pyfaup.faup import Faup

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


class LogOMForm(ModelForm):

    class Meta:
        model = LogOM
        fields = ('name', 'enabled', 'send_as_raw', 'queue_size', 'dequeue_size', 'queue_timeout_shutdown',
                  'max_workers', 'new_worker_minimum_messages', 'worker_timeout_shutdown', 'enable_retry',
                  'enable_disk_assist', 'high_watermark', 'low_watermark', 'max_file_size', 'max_disk_space',
                  'spool_directory')

        widgets = {
            'enabled': CheckboxInput(attrs={'class': 'js-switch'}),
            'name': TextInput(attrs={'class': 'form-control'}),
            'send_as_raw': CheckboxInput(attrs={'class': 'js-switch'}),
            'queue_size': NumberInput(attrs={'class': 'form-control'}),
            'dequeue_size': NumberInput(attrs={'class': 'form-control'}),
            'queue_timeout_shutdown': NumberInput(attrs={'class': 'form-control', 'placeholder': 10}),
            'max_workers': NumberInput(attrs={'class': 'form-control', 'placeholder': 1}),
            'new_worker_minimum_messages': NumberInput(attrs={'class': 'form-control', 'placeholder': 'queue size / max workers'}),
            'worker_timeout_shutdown': NumberInput(attrs={'class': 'form-control', 'placeholder': 60_000}),
            'enable_retry': CheckboxInput(attrs={'class': 'js-switch'}),
            'enable_disk_assist': CheckboxInput(attrs={'class': 'js-switch'}),
            'high_watermark': NumberInput(attrs={'class': 'form-control'}),
            'low_watermark': NumberInput(attrs={'class': 'form-control'}),
            'max_file_size': NumberInput(attrs={'class': 'form-control'}),
            'max_disk_space': NumberInput(attrs={'class': 'form-control'}),
            'spool_directory': TextInput(attrs={'class': 'form-control'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self = bootstrap_tooltips(self)
        for field_name in ['high_watermark', 'low_watermark', 'max_file_size', 'max_disk_space', 'spool_directory']:
            self.fields[field_name].required = False

    def clean_name(self):
        return self.cleaned_data['name'].replace(' ', '_')

    def clean_spool_directory(self):
        return "/" + self.cleaned_data['spool_directory'].strip("/")

    def clean(self):
        """ Verify needed fields - depending on mode chosen """
        cleaned_data = super().clean()
        logger.info(self.initial)
        if cleaned_data.get('enable_disk_assist') is True:
            if cleaned_data.get('queue_size') is not None and cleaned_data.get('low_watermark') is not None:
                if cleaned_data['queue_size'] < cleaned_data['low_watermark']:
                    self.add_error("queue_size", "Queue size is lower than the low watermark")
            if cleaned_data.get('queue_size') is not None and cleaned_data.get('high_watermark') is not None:
                if cleaned_data['queue_size'] < cleaned_data['high_watermark']:
                    self.add_error("queue_size", "Queue size is lower than the high watermark")
            if cleaned_data.get('low_watermark') is not None and cleaned_data.get('high_watermark') is not None:
                if cleaned_data['high_watermark'] < cleaned_data['low_watermark']:
                    self.add_error("high_watermark", "High watermark is lower than the low watermark value")
                    self.add_error("low_watermark", "Low watermark is higher than the high watermark value")
            if cleaned_data.get('max_disk_space') is not None and cleaned_data.get('max_file_size') is not None:
                if cleaned_data['max_disk_space'] > 0 and cleaned_data['max_file_size'] > cleaned_data.get('max_disk_space'):
                    self.add_error("max_file_size", "File size is higher than the disk space")
        if cleaned_data.get('new_worker_minimum_messages') is not None and cleaned_data.get('queue_size') is not None:
            if cleaned_data['new_worker_minimum_messages'] > cleaned_data['queue_size']:
                self.add_error("new_worker_minimum_messages", "This value cannot be over the queue size")
        return cleaned_data


class LogOMFileForm(LogOMForm):

    class Meta(LogOMForm.Meta):
        model = LogOMFile
        fields = LogOMForm.Meta.fields + ('file', 'flush_interval', 'async_writing', 'retention_time',
                  'rotation_period')

        widgets = {
            'file': TextInput(attrs={'class': 'form-control'}),
            'flush_interval': NumberInput(attrs={'class': 'form-control'}),
            'async_writing': CheckboxInput(attrs={'class': 'js-switch'}),
            'retention_time': NumberInput(attrs={'class': 'form-control'}),
            'rotation_period': Select(attrs={'class': 'select2'}),
        }
        widgets.update(LogOMForm.Meta.widgets)

    def clean_file(self):
        value = self.cleaned_data['file']
        if not value.startswith('/'):
            raise ValidationError("That field needs absolute path.")
        return value


class LogOMRELPForm(LogOMForm):

    class Meta(LogOMForm.Meta):
        model = LogOMRELP
        fields = LogOMForm.Meta.fields + ('target', 'port', 'tls_enabled', 'x509_certificate')

        widgets = {
            'target': TextInput(attrs={'class': 'form-control'}),
            'port': NumberInput(attrs={'class': 'form-control'}),
            'tls_enabled': CheckboxInput(attrs={'class': 'js-switch'}),
            'x509_certificate': Select(attrs={'class': 'select2'}),
        }
        widgets.update(LogOMForm.Meta.widgets)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['x509_certificate'].empty_label = "No TLS certificate"

    def clean(self):
        cleaned_data = super().clean()
        if not cleaned_data.get('tls_enabled') and cleaned_data.get('x509_certificate'):
            self.add_error('tls_enabled', "You must enable tls to specify a certificate.")
        return cleaned_data


class LogOMHIREDISForm(LogOMForm):

    tls_profile = ModelChoiceField(
        queryset=TLSProfile.objects.all(),
        required=False,
        widget=Select(attrs={'class': 'form-control select2'}),
        label=LogOMHIREDIS.tls_profile.field.verbose_name,
        empty_label="No TLS"
    )

    class Meta(LogOMForm.Meta):
        model = LogOMHIREDIS
        fields = LogOMForm.Meta.fields + ('target', 'port', 'mode', 'key', 'dynamic_key', 'pwd',
                  'use_rpush', 'expire_key', 'stream_outfield', 'stream_capacitylimit', 'tls_profile')

        widgets = {
            'target': TextInput(attrs={'class': 'form-control'}),
            'port': NumberInput(attrs={'class': 'form-control'}),
            'mode': Select(choices=OMHIREDIS_MODE_CHOICES, attrs={'class': 'select2'}),
            'key': TextInput(attrs={'class': 'form-control'}),
            'dynamic_key': CheckboxInput(attrs={'class': 'js-switch'}),
            'pwd': TextInput(attrs={'class': 'form-control'}),
            'use_rpush': CheckboxInput(attrs={'class': 'js-switch'}),
            'expire_key': NumberInput(attrs={'class': 'form-control'}),
            'stream_outfield': TextInput(attrs={'class': 'form-control'}),
            'stream_capacitylimit': NumberInput(attrs={'class': 'form-control'}),
        }
        widgets.update(LogOMForm.Meta.widgets)

    def clean_key(self):
        key = self.cleaned_data['key']
        if " " in key:
            raise ValidationError("Cannot contain spaces")
        return key

    def clean(self):
        """ Verify needed fields - depending on mode chosen """
        cleaned_data = super().clean()
        if cleaned_data.get('dynamic_key') is True and cleaned_data.get('key'):
            key = cleaned_data['key']
            if key.count("%") % 2 != 0:
                self.add_error("key", "seems like your number of '%' is incorrect, please check your templated key")
        return cleaned_data


class LogOMFWDForm(LogOMForm):

    class Meta(LogOMForm.Meta):
        model = LogOMFWD
        fields = LogOMForm.Meta.fields + ('target', 'port', 'protocol', 'zip_level',
                  'ratelimit_interval', 'ratelimit_burst')

        widgets = {
            'target': TextInput(attrs={'class': 'form-control'}),
            'port': NumberInput(attrs={'class': 'form-control'}),
            'protocol': Select(choices=OMFWD_PROTOCOL, attrs={'class': 'select2'}),
            'zip_level': NumberInput(attrs={'class': 'form-control'}),
            'ratelimit_interval': NumberInput(attrs={'class': 'form-control'}),
            'ratelimit_burst': NumberInput(attrs={'class': 'form-control'}),
        }
        widgets.update(LogOMForm.Meta.widgets)

    def clean(self):
        """ Verify needed fields - depending on mode chosen """
        cleaned_data = super().clean()
        """ if ratelimit_interval or ratelimit_burst is specified, the other cannot be left blank"""
        if cleaned_data.get('ratelimit_interval') and not cleaned_data.get('ratelimit_burst'):
            self.add_error("ratelimit_burst", "This field cannot be left blank if rate-limiting interval is set")
        if cleaned_data.get('ratelimit_burst') and not cleaned_data.get('ratelimit_interval'):
            self.add_error("ratelimit_interval", "This field cannot be left blank if rate-limiting burst is set")
        return cleaned_data


class LogOMElasticSearchForm(LogOMForm):
    tls_profile = ModelChoiceField(
        queryset=TLSProfile.objects.all(),
        required=False,
        widget=Select(attrs={'class': 'form-control select2'}),
        label=LogOMElasticSearch.tls_profile.field.verbose_name,
        empty_label="No TLS"
    )

    class Meta(LogOMForm.Meta):
        model = LogOMElasticSearch
        fields = LogOMForm.Meta.fields + ('servers', 'es8_compatibility', 'data_stream_mode',
                  'retry_on_els_failures', 'index_pattern', 'uid', 'pwd', 'tls_profile')

        widgets = {
            'servers': TextInput(attrs={'class': 'form-control'}),
            'es8_compatibility': CheckboxInput(attrs={'class': 'js-switch'}),
            'data_stream_mode': CheckboxInput(attrs={'class': 'js-switch'}),
            'retry_on_els_failures': CheckboxInput(attrs={'class': 'js-switch'}),
            'index_pattern': TextInput(attrs={'class': 'form-control'}),
            'uid': TextInput(attrs={'class': 'form-control'}),
            'pwd': TextInput(attrs={'class': 'form-control'}),
        }
        widgets.update(LogOMForm.Meta.widgets)

    def clean_index_pattern(self):
        field = self.cleaned_data.get('index_pattern')
        if field:
            return field.lower()

    def clean(self):
        """ Verify needed fields - depending on mode chosen """
        cleaned_data = super().clean()
        if cleaned_data.get('retry_on_els_failures') is True and cleaned_data.get('data_stream_mode') is False:
            self.add_error('retry_on_els_failures', "This field cannot be set if Stream Mode is disabled.")
        return cleaned_data


class LogOMMongoDBForm(LogOMForm):
    x509_certificate = ModelChoiceField(
        queryset=X509Certificate.objects.filter(is_ca=False).only(*(X509Certificate.str_attrs())),
        required=False,
        widget=Select(attrs={'class': 'select2'}),
        empty_label="No SSL"
    )

    class Meta(LogOMForm.Meta):
        model = LogOMMongoDB
        fields = LogOMForm.Meta.fields + ('db', 'collection', 'uristr', 'x509_certificate')

        widgets = {
            'db': TextInput(attrs={'class': 'form-control'}),
            'collection': TextInput(attrs={'class': 'form-control'}),
            'uristr': TextInput(attrs={'class': 'form-control'}),
        }
        widgets.update(LogOMForm.Meta.widgets)


class LogOMKafkaForm(LogOMForm):

    class Meta(LogOMForm.Meta):
        model = LogOMKAFKA
        fields = LogOMForm.Meta.fields + ('broker', 'topic', 'key', 'dynaKey', 'dynaTopic', 'partitions_useFixed',
                  'partitions_auto', 'confParam', 'topicConfParam')

        widgets = {
            'broker': TextInput(attrs={'class': 'form-control'}),
            'topic': TextInput(attrs={'class': 'form-control'}),
            'key': TextInput(attrs={'class': 'form-control'}),
            'dynaKey': CheckboxInput(attrs={'class': 'js-switch'}),
            'dynaTopic': CheckboxInput(attrs={'class': 'js-switch'}),
            'partitions_useFixed': NumberInput(attrs={'class': 'form-control'}),
            'partitions_auto': CheckboxInput(attrs={'class': 'js-switch'}),
            'confParam': TextInput(attrs={'class': 'form-control', 'data-role': "tagsinput"}),
            'topicConfParam': TextInput(attrs={'class': 'form-control', 'data-role': "tagsinput"}),
        }
        widgets.update(LogOMForm.Meta.widgets)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.initial['confParam'] = ','.join(self.initial.get('confParam', []) or self.fields['confParam'].initial)
        self.initial['topicConfParam'] = ','.join(self.initial.get('topicConfParam', []) or self.fields['topicConfParam'].initial)

    def clean_key(self):
        key = self.cleaned_data['key']
        if key is not None and " " in key:
            raise ValidationError("Cannot contain spaces")
        return key

    def clean_topic(self):
        topic = self.cleaned_data['topic']
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
        if cleaned_data.get('dynaKey') is True:
            if cleaned_data.get('key'):
                key = cleaned_data['key']
                if key.count("%") % 2 != 0:
                    self.add_error("key", "seems like your number of '%' is incorrect, please check your templated key")
            else:
                self.add_error("key", "This field is required.")
        if cleaned_data.get('dynaTopic') is True and cleaned_data.get('topic'):
            topic = cleaned_data['topic']
            if topic.count("%") % 2 != 0:
                self.add_error("topic", "seems like your number of '%' is incorrect, please check your templated topic")
        return cleaned_data


class LogOMSentinelForm(LogOMForm):
    tls_profile = ModelChoiceField(
        queryset=TLSProfile.objects.all(),
        required=False,
        widget=Select(attrs={'class': 'form-control select2'}),
        label=LogOMSentinel.tls_profile.field.verbose_name,
        empty_label="No TLS"
    )

    class Meta(LogOMForm.Meta):
        model = LogOMSentinel
        fields = LogOMForm.Meta.fields + ('tenant_id', 'client_id', 'client_secret',
                                          'dcr', 'dce', 'stream_name', 'compression_level', 'scope',
                                          'batch_maxsize', 'batch_maxbytes', 'tls_profile', 'use_proxy', 'custom_proxy')

        widgets = {
            'tenant_id': TextInput(attrs={'class': 'form-control', 'placeholder': '47673b71-c5ae-4a2a-8d8a-e86e79f1f967'}),
            'client_id': TextInput(attrs={'class': 'form-control', 'placeholder': '47673b71-c5ae-4a2a-8d8a-e86e79f1f967'}),
            'client_secret': TextInput(attrs={'class': 'form-control', 'type': 'password'}),
            'dcr': TextInput(attrs={'class': 'form-control', 'placeholder': 'dcr-cbb3586665ebdbc6ebadd796e3ba5bcf'}),
            'dce': TextInput(attrs={'class': 'form-control', 'placeholder': 'example-a1b2.francecentral-1.ingest.monitor.azure.com'}),
            'stream_name': TextInput(attrs={'class': 'form-control', 'placeholder': 'table name / stream name'}),
            'compression_level': Select(choices=ZLIB_LEVEL_CHOICES, attrs={'class': 'select2'}),
            'scope': URLInput(attrs={'class': 'form-control'}),
            'batch_maxsize': NumberInput(attrs={'class': 'form-control', 'placeholder': 'nb of messages per request'}),
            'batch_maxbytes': NumberInput(attrs={'class': 'form-control', 'placeholder': 'Max size per request (bytes)'}),
            'use_proxy': CheckboxInput(attrs={'class': 'js-switch'}),
            'custom_proxy': TextInput(attrs={'class': 'form-control', 'placeholder': 'use system proxy'})
        }
        widgets.update(LogOMForm.Meta.widgets)

    def clean_custom_proxy(self):
        custom_proxy = self.cleaned_data.get('custom_proxy')
        scheme={"http", "https", "ftp", "socks4", "socks5", None}
        f = Faup()
        f.decode(custom_proxy)
        if f.get_scheme() not in scheme:
            raise ValidationError("Invalid scheme. Allowed values are: http, https, ftp, socks4, socks5.")
        return custom_proxy

    def clean_dce(self):
        dce = self.cleaned_data.get('dce')
        f = Faup()
        f.decode(dce)
        return f.get_host()
