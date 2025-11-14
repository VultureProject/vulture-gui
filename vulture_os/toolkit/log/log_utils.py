#!/usr/bin/python
# -*- coding: utf-8 -*-
"""This file is part of Vulture 3.

Vulture 3 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Vulture 3 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Vulture 3.  If not, see http://www.gnu.org/licenses/.
"""
__author__ = "Olivier de Régis"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture Project"
__email__ = "contact@vultureproject.org"
__doc__ = 'Database handler for logging'

from toolkit.mongodb.postgres_base import PostgresBase
from django.conf import settings
from django.utils import timezone
import logging


class DatabaseHandler(logging.StreamHandler):
    """
    A handler class which writes formatted logging records to disk files.
    """

    def __init__(self, type_logs):
        """
        Open the specified file and use it as the stream for logging.
        """
        # keep the absolute path, otherwise derived classes which use this
        # may come a cropper when the current directory changes
        self._name = "Database Handler"
        self.filters = []
        self.lock = None

        self.database = "logs"
        self.collection = "internal"

        self.postgres = PostgresBase()

    def emit(self, record):
        """
        Emit a record.
        Save the log into the repository
        """

        if record.levelname != "ERROR":
            return
        try:

            return self.postgres.insert(self.database, self.collection, {
                'timestamp': timezone.now(),
                'log_level': record.levelname,
                'filename': record.filename,
                'message': record.msg,
                'source': record.name,
                'node': settings.HOSTNAME,
            })

        except Exception:
            pass


def get_obj_value_or_default(element, keys=[], default=None):
    '''
    Check if keys (nested) exists in `element` (obj).
    `keys`can be either a list defining ordered sub-objects to traverse, or a string in the form 'obj1.obj2.obj3'
    Returns value if last key exists, else returns default value
    '''
    if isinstance(keys, str):
        keys = keys.split('.')

    if not isinstance(element, dict) and not isinstance(element, list):
        return default

    current_element = element
    for key in keys:
        if isinstance(current_element, dict) and key in current_element:
            current_element = current_element[key]
        elif isinstance(current_element, list) and isinstance(key, int) and key < len(current_element):
            current_element = current_element[key]
        else:
            return default

    return current_element
