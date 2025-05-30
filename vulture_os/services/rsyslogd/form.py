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
__doc__ = 'Rsyslog dedicated form class'

# Django system imports
from django.conf import settings
from django.forms import ModelForm, TextInput, Select, NumberInput, CheckboxInput

# Django project imports
from services.rsyslogd.models import RsyslogSettings, RsyslogQueue

# Required exceptions imports

# Extern modules imports

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('services')


class RsyslogForm(ModelForm):

    class Meta:
        model = RsyslogSettings
        fields = []
        widgets = {}


class RsyslogQueueForm(ModelForm):

    class Meta:
        model = RsyslogQueue
        fields = [
            'queue_type',
            'queue_size',
            'dequeue_batch_size',
            'nb_workers',
            'new_worker_minimum_messages',
            'light_delay_mark',
            'full_delay_mark',
            'shutdown_timeout',
            'save_on_shutdown',
            'enable_disk_assist',
            'high_watermark',
            'low_watermark',
            'max_file_size',
            'max_disk_space',
            'spool_directory',
            ]

        widgets = {
            'queue_type': Select(choices=RsyslogQueue.QueueTypes, attrs={'class': 'form-control select2'}),
            'queue_size': NumberInput(attrs={'class': 'form-control', 'placeholder': '1000/50000'}),
            'dequeue_batch_size': NumberInput(attrs={'class': 'form-control', 'placeholder': '128/1024'}),
            'nb_workers': NumberInput(attrs={'class': 'form-control', 'placeholder': '8'}),
            'new_worker_minimum_messages': NumberInput(attrs={'class': 'form-control', 'placeholder': 'queue size/queue workerthreads'}),
            'light_delay_mark': NumberInput(attrs={'class': 'form-control', 'placeholder': '70% of queue size'}),
            'full_delay_mark': NumberInput(attrs={'class': 'form-control', 'placeholder': '97% of queue size'}),
            'shutdown_timeout': NumberInput(attrs={'class': 'form-control', 'placeholder': '5000'}),
            'save_on_shutdown': CheckboxInput(attrs={'class': 'js-switch'}),
            'enable_disk_assist': CheckboxInput(attrs={'class': 'js-switch'}),
            'high_watermark': NumberInput(attrs={'class': 'form-control', 'placeholder': '90% of queue.size'}),
            'low_watermark': NumberInput(attrs={'class': 'form-control', 'placeholder': '70% of queue.size'}),
            'max_file_size': NumberInput(attrs={'class': 'form-control', 'placeholder': '1MB/16MB'}),
            'max_disk_space': NumberInput(attrs={'class': 'form-control', 'placeholder': 'Unlimited'}),
            'spool_directory': TextInput(attrs={'class': 'form-control', 'placeholder': '/var/tmp'}),
        }

    def clean_spool_directory(self):
        return "/" + self.cleaned_data['spool_directory'].strip("/")

    def clean(self):
        cleaned_data = super().clean()

        """ Rsyslog queue fields verification """
        if cleaned_data.get('queue_type') != RsyslogQueue.QueueTypes.DIRECT:
            if cleaned_data.get('dequeue_batch_size'):
                if not cleaned_data.get('queue_size'):
                    self.add_error("queue_size", "Please specify an explicit queue size when the size of the batch to dequeue is set")
                elif cleaned_data['dequeue_batch_size'] > cleaned_data['queue_size']:
                    self.add_error("dequeue_batch_size", "This value cannot be over the queue size")

            if cleaned_data.get('new_worker_minimum_messages'):
                if not cleaned_data.get('queue_size'):
                    self.add_error("queue_size", "Please specify an explicit queue size when the minimum messages to start a new worker is set")
                if cleaned_data['new_worker_minimum_messages'] > cleaned_data['queue_size']:
                    self.add_error("new_worker_minimum_messages", "This value cannot be over the queue size")

            light_delay_mark = cleaned_data.get('light_delay_mark') or 70
            full_delay_mark = cleaned_data.get('full_delay_mark') or 97
            if light_delay_mark > full_delay_mark:
                self.add_error("light_delay_mark", "This value cannot be over the full delay mark")
                self.add_error("full_delay_mark", "This value cannot be under the light delay mark")

            if cleaned_data.get('enable_disk_assist'):
                if (cleaned_data.get('high_watermark') or cleaned_data.get('low_watermark')) and not cleaned_data.get('queue_size'):
                    self.add_error("queue_size", "Queue size needs to be set if a watermark is set")
                    self.add_error("high_watermark", "Queue size needs to be set if a watermark is set")
                    self.add_error("low_watermark", "Queue size needs to be set if a watermark is set")

                high_watermark = cleaned_data.get('high_watermark') or 90
                low_watermark = cleaned_data.get('low_watermark') or 70

                if high_watermark < low_watermark:
                    self.add_error("high_watermark", "High watermark is lower than the low watermark value")
                    self.add_error("low_watermark", "Low watermark is higher than the high watermark value")
                if cleaned_data.get('max_disk_space') and not cleaned_data.get('max_file_size'):
                    self.add_error("max_file_size", "File size needs to be specified if the maximum disk space is set")
                elif cleaned_data.get('max_file_size') and not cleaned_data.get('max_disk_space'):
                    self.add_error("max_disk_space", "Max disk space needs to be specified if the maximum file size is set")
                elif cleaned_data.get('max_file_size') and cleaned_data.get('max_disk_space') and cleaned_data['max_file_size'] * 2 > cleaned_data['max_disk_space']:
                    self.add_error("max_file_size", "Max disk space needs to be at least twice the size of a single file size to allow to use at least 2 files")
                    self.add_error("max_disk_space", "Max disk space needs to be at least twice the size of a single file size to allow to use at least 2 files")

        return cleaned_data
