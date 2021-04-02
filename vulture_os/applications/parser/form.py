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
__doc__ = 'Parser dedicated form classes'

# Django system imports
from django.conf import settings
from django.forms import ModelForm, TextInput, Textarea

# Django project imports
from applications.parser.models import Parser

# Required exceptions imports

# Extern modules imports

# Logger configuration imports
import logging

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


class ParserForm(ModelForm):

    class Meta:
        model = Parser
        fields = ('name', 'rulebase', 'to_test', 'tags')

        widgets = {
            'name': TextInput(attrs={'class': 'form-control'}),
            'rulebase': Textarea(attrs={'class': 'form-control'}),
            'to_test': Textarea(attrs={'class': 'form-control'}),
            'tags': TextInput(attrs={'class': 'form-control', 'data-role': "tagsinput"})
        }

    def __init__(self, *args, **kwargs):
        """ Initialize form and special attributes """
        super().__init__(*args, **kwargs)
        # Convert list field from model to text input comma separated
        self.initial['tags'] = ','.join(self.initial.get('tags', []) or self.fields['tags'].initial)

    def clean_tags(self):
        tags = self.cleaned_data.get('tags')
        if tags:
            return [i.replace(" ", "") for i in self.cleaned_data['tags'].split(',')]
        return []
