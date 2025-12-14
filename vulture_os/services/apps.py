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
from django.apps import AppConfig, apps
from django.conf import settings

# Django project imports

# Extern modules imports

# Required exceptions imports

# Logger configuration imports
import logging

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class ServicesConfig(AppConfig):
    name = 'services'
    
    @staticmethod
    def get_available_api_collectors_list():
        _api_collectors = dict()
        for config in apps.get_app_configs():
            if hasattr(config, "_api_collectors"):
                _api_collectors.update(getattr(config, "_api_collectors", {}))
        return _api_collectors

    @staticmethod
    def api_collectors_generic_form():
        _api_collectors_generic_form = None
        for config in apps.get_app_configs():
            if hasattr(config, "_api_collectors_generic_form"):
                _api_collectors_generic_form = getattr(config, "_api_collectors_generic_form", {})
        return _api_collectors_generic_form

    @staticmethod
    def api_collectors_forms():
        forms = dict()
        for collector_name, config in ServicesConfig.get_available_api_collectors_list().items():
            # forms.append(config.get('form')(prefix=config.get('form')().name))
            # forms.append(config.get('form')(prefix=f"{collector_name}collectorform"))
            forms[collector_name] = config['form']
        return forms

    @staticmethod
    def api_collectors_get_form(collector_name, instance=None, data=None):
        try:
            form = ServicesConfig.get_available_api_collectors_list()[collector_name]['form']
        except KeyError:
            return None
        # return form(instance=instance, prefix=form().name)
        return form(data, instance=instance)

    @staticmethod
    def api_collectors_get_model(collector_name):
        return ServicesConfig.get_available_api_collectors_list()[collector_name]['model']
