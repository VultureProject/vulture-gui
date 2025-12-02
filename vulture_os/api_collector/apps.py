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
__doc__ = "API Collector model classes"

# Django system imports
from django.apps import AppConfig
from django.conf import settings

# Django project imports

# Extern modules imports

# Required exceptions imports
from django.core.exceptions import ImproperlyConfigured

# Logger configuration imports
import logging

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class ApiCollectorConfig(AppConfig):
    default_auto_field = 'django.db.models.BigAutoField'
    name = 'api_collector'
    verbose_name = "Collection of API LOG collectors"
    _api_collectors_generic_form = None
    _api_collectors = {}

    def ready(self):
        from .models import MODELS_LIST
        from .forms import FORMS_LIST
        from .forms.base import GenericApiCollectorForm

        self._api_collectors_generic_form = GenericApiCollectorForm

        for collector_name, collector_def in MODELS_LIST.items():
            if collector_name not in self._api_collectors:
                self._api_collectors[collector_name] = dict()
            self._api_collectors[collector_name]['model'] = collector_def

        for collector_name, collector_def in FORMS_LIST.items():
            if collector_name not in self._api_collectors:
                self._api_collectors[collector_name] = dict()
            self._api_collectors[collector_name]['form'] = collector_def

        for collector_name, collector_defs in self._api_collectors.items():
            if len(collector_defs) != 2:
                raise ImproperlyConfigured(f"Collector {collector_name} is improperly configured: missing Model or Form")

    def get_available_api_collectors_list(self):
        return self._api_collectors
