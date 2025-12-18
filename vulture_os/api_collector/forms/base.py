#!/usr/bin/env python
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

__author__ = "Fabien Amelinck"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = "API Collector form classes"

# Django system imports
from django.conf import settings
from django.forms import ModelForm, TextInput, CheckboxInput, Select, ModelChoiceField

# Django project imports
from api_collector.models.base import ApiCollector
from system.pki.models import X509Certificate

# Extern modules imports

# Required exceptions imports

# Logger configuration imports
import logging

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class GenericApiCollectorForm(ModelForm):
    template_name = "api_collector_edit.html"

    custom_certificate = ModelChoiceField(
        queryset=X509Certificate.objects.all(),
        widget=Select(attrs={'class': 'form-control select2'}),
        required=False,
        label=ApiCollector.x509_cert.field.verbose_name,
    )

    class Meta:
        model = ApiCollector
        fields = ("use_proxy", "custom_proxy", "verify_ssl", "custom_certificate")

        widgets = {
            'use_proxy': CheckboxInput(attrs={'class': "js-switch"}),
            'custom_proxy': TextInput(attrs={'class': "form-control"}),
            'verify_ssl': CheckboxInput(attrs={'class': 'js-switch'}),
        }

    @property
    def name(self):
        return self.__class__.__name__.lower()
