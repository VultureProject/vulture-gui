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
__doc__ = 'Mongod main models'


from services.netdata.models import NetdataSettings, CHOICES_HISTORY, BACKEND_TYPE_CHOICES, DATA_SOURCE_CHOICES
from django.utils.translation import ugettext as _
from django.utils.safestring import mark_safe
from django.conf import settings
from django.forms import (CharField, CheckboxInput, ChoiceField, IntegerField,
                          ModelForm, NumberInput, Select, SelectMultiple, TextInput, Textarea)
from django.core.validators import RegexValidator
import logging
import logging.config

logging.config.dictConfig(settings.LOG_SETTINGS)


class NetdataForm(ModelForm):
    history = IntegerField(
        label=_("History"),
        widget=Select(
            attrs={'class': 'form-control select2'},
            choices=CHOICES_HISTORY
        ),
        help_text=_(mark_safe("""This option controls the maximum size of the memory database in use by Netdata.<br/>
    <ul><li>3600 seconds (1 hour of chart data retention) uses 15 MB of RAM</li>
    <li>7200 seconds (2 hours of chart data retention) uses 30 MB of RAM</li>
    <li>14400 seconds (4 hours of chart data retention) uses 60 MB of RAM</li>
    <li>28800 seconds (8 hours of chart data retention) uses 120 MB of RAM</li>
    <li>43200 seconds (12 hours of chart data retention) uses 180 MB of RAM</li>
    <li>86400 seconds (24 hours of chart data retention) uses 360 MB of RAM</li></ul>"""))
    )

    class Meta:
        model = NetdataSettings
        fields = ('history', 'backend_enabled', 'backend_type', 'backend_host_tags', 'backend_destination',
                  'backend_data_source', 'backend_prefix', 'backend_update_every', 'backend_buffer_on_failure',
                  'backend_timeout', 'backend_send_hosts_matching', 'backend_send_charts_matching',
                  'backend_send_names_or_ids')

        widgets = {
            'backend_enabled': CheckboxInput(attrs={'class': "js-switch"}),
            'backend_type': Select(choices=BACKEND_TYPE_CHOICES, attrs={'class': 'form-control select2'}),
            'backend_host_tags': TextInput(attrs={'class': 'form-control tags-input-comma'}),
            'backend_destination': TextInput(attrs={'class': 'form-control tags-input-space'}),
            'backend_data_source': Select(choices=DATA_SOURCE_CHOICES, attrs={'class': 'form-control select2'}),
            'backend_prefix': TextInput(attrs={'class': 'form-control'}),
            'backend_update_every': NumberInput(attrs={'class': 'form-control'}),
            'backend_buffer_on_failure': NumberInput(attrs={'class': 'form-control'}),
            'backend_timeout': NumberInput(attrs={'class': 'form-control'}),
            'backend_send_hosts_matching': TextInput(attrs={'class': 'form-control tags-input-space'}),
            'backend_send_charts_matching': TextInput(attrs={'class': 'form-control tags-input-space'}),
            'backend_send_names_or_ids': CheckboxInput(attrs={'class': "js-switch"})
        }

    def __init__(self, *args, **kwargs):
        """ Initialize form and special attributes """
        super().__init__(*args, **kwargs)
        # All backend fields are not required in case of backend disabled
        for field_name in ('backend_type', 'backend_host_tags', 'backend_destination',
                           'backend_data_source', 'backend_prefix', 'backend_update_every', 'backend_buffer_on_failure',
                           'backend_timeout', 'backend_send_hosts_matching', 'backend_send_charts_matching',
                           'backend_send_names_or_ids'):
            self.fields[field_name].required = False
        self.initial['backend_host_tags'] = ','.join(self.initial.get('backend_host_tags', []) or
                                                     self.fields['backend_host_tags'].initial)

    def clean_backend_host_tags(self):
        tags = self.cleaned_data.get('backend_host_tags')
        result = []
        if tags:
            for tag in tags:
                RegexValidator("^(\w+)=(\w+)$", tag)
                result.append(tag)
        return result

    def clean(self):
        cleaned_data = super().clean()
        # If backend is enabled, some fields are required
        if cleaned_data.get('backend_enabled'):
            for field_name in ('backend_type', 'backend_destination', 'backend_data_source', 'backend_prefix'):
                if not cleaned_data.get(field_name):
                    self.add_error(field_name, "This field is required if Backend is enabled.")
