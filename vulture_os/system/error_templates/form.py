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
__doc__ = 'ErrorTemplate dedicated form classes'

# Django system imports
from django.conf import settings
from django.forms import ModelForm, Select, Textarea, TextInput

# Django project imports
from system.error_templates.models import ERROR_MODE_CHOICES, ErrorTemplate

# Required exceptions imports
from django.forms import ValidationError

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


class ErrorTemplateForm(ModelForm):

    class Meta:
        model = ErrorTemplate
        fields = ('name', 'error_400_mode', 'error_400_url', 'error_400_html', 'error_403_mode', 'error_403_url',
                  'error_403_html', 'error_405_mode', 'error_405_url', 'error_405_html', 'error_408_mode',
                  'error_408_url', 'error_408_html', 'error_425_mode', 'error_425_url', 'error_425_html',
                  'error_429_mode', 'error_429_url', 'error_429_html', 'error_500_mode', 'error_500_url',
                  'error_500_html', 'error_502_mode', 'error_502_url', 'error_502_html', 'error_503_mode',
                  'error_503_url', 'error_503_html', 'error_504_mode', 'error_504_url', 'error_504_html')
        widgets = {
            'name': TextInput(attrs={'class': 'form-control'}),
            'error_400_mode': Select(choices=ERROR_MODE_CHOICES, attrs={'class': 'form-control select2 mode'}),
            'error_400_url': TextInput(attrs={'class': 'form-control'}),
            'error_400_html': Textarea(attrs={'class': 'form-control'}),
            'error_403_mode': Select(choices=ERROR_MODE_CHOICES, attrs={'class': 'form-control select2 mode'}),
            'error_403_url': TextInput(attrs={'class': 'form-control'}),
            'error_403_html': Textarea(attrs={'class': 'form-control'}),
            'error_405_mode': Select(choices=ERROR_MODE_CHOICES, attrs={'class': 'form-control select2 mode'}),
            'error_405_url': TextInput(attrs={'class': 'form-control'}),
            'error_405_html': Textarea(attrs={'class': 'form-control'}),
            'error_408_mode': Select(choices=ERROR_MODE_CHOICES, attrs={'class': 'form-control select2 mode'}),
            'error_408_url': TextInput(attrs={'class': 'form-control'}),
            'error_408_html': Textarea(attrs={'class': 'form-control'}),
            'error_425_mode': Select(choices=ERROR_MODE_CHOICES, attrs={'class': 'form-control select2 mode'}),
            'error_425_url': TextInput(attrs={'class': 'form-control'}),
            'error_425_html': Textarea(attrs={'class': 'form-control'}),
            'error_429_mode': Select(choices=ERROR_MODE_CHOICES, attrs={'class': 'form-control select2 mode'}),
            'error_429_url': TextInput(attrs={'class': 'form-control'}),
            'error_429_html': Textarea(attrs={'class': 'form-control'}),
            'error_500_mode': Select(choices=ERROR_MODE_CHOICES, attrs={'class': 'form-control select2 mode'}),
            'error_500_url': TextInput(attrs={'class': 'form-control'}),
            'error_500_html': Textarea(attrs={'class': 'form-control'}),
            'error_502_mode': Select(choices=ERROR_MODE_CHOICES, attrs={'class': 'form-control select2 mode'}),
            'error_502_url': TextInput(attrs={'class': 'form-control'}),
            'error_502_html': Textarea(attrs={'class': 'form-control'}),
            'error_503_mode': Select(choices=ERROR_MODE_CHOICES, attrs={'class': 'form-control select2 mode'}),
            'error_503_url': TextInput(attrs={'class': 'form-control'}),
            'error_503_html': Textarea(attrs={'class': 'form-control'}),
            'error_504_mode': Select(choices=ERROR_MODE_CHOICES, attrs={'class': 'form-control select2 mode'}),
            'error_504_url': TextInput(attrs={'class': 'form-control'}),
            'error_504_html': Textarea(attrs={'class': 'form-control'}),
        }

    def clean_name(self):
        return self.cleaned_data['name'].replace(' ', '_')

    def clean_file(self):
        value = self.cleaned_data.get('file')
        if not value.startswith('/'):
            raise ValidationError("That field needs absolute path.")
        return value

