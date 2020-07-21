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

__author__ = "Jérémie JOURDIN"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Darwin Policy views'


# Logger configuration imports
import logging
from django.conf import settings

# Django system imports
from django.shortcuts import render

# Django project imports
from gui.forms.form_utils import DivErrorList
from system.cluster.models import Cluster, Node

# Required exceptions imports
from django.core.exceptions import ObjectDoesNotExist
from services.exceptions import ServiceConfigError, ServiceError, ServiceReloadError
from system.exceptions import VultureSystemError

# Extern modules imports
from json import loads as json_loads
from sys import exc_info
from traceback import format_exception

# Logger configuration imports
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')

COMMAND_LIST = {}

def policy_edit(request, object_id=None):
    return render(request, 'policy_edit_v2.html', {
        "object_id": object_id if object_id else ""
    })
