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
from django.forms import TextInput, PasswordInput

# Django project imports
from api_collector.forms.base import GenericApiCollectorForm
from api_collector.models.proofpoint_trap import ProofpointTRAPCollector

# Extern modules imports

# Required exceptions imports

# Logger configuration imports
import logging

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class ProofpointTRAPCollectorForm(GenericApiCollectorForm):
    class Meta:
        model = ProofpointTRAPCollector
        fields = GenericApiCollectorForm.Meta.fields + ("host", "apikey")

        widgets = {
            'host': TextInput(attrs={'class': "form-control"}),
            'apikey': PasswordInput(attrs={'class': "form-control"})
        } | GenericApiCollectorForm.Meta.widgets
