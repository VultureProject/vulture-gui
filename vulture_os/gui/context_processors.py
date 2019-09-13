#!/home/vlt-os/env/bin/python
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
__maintainer__ = "Vulture OS"
__email__ = ""
__doc__ = ''

from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist

from applications.apps import Apps
from authentication.authentication import Authentication
from authentication.portal import Portal
from darwin.darwin import Darwin
from services.service import Service
from system.cluster.models import Cluster
from system.system import System
from toolkit.network.network import get_hostname
from workflow.workflow import Workflows

import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


def admin_media(request):
    """ Middleware for Jinja template

    Args:
        request (Django request)

    Returns:
        DICT: Variable for jinja template
    """
    try:
        cluster = Cluster.objects.get()
        node = cluster.get_current_node()
        assert node
        node_name = node.name

    except (ObjectDoesNotExist, AssertionError):
        node_name = ""

    menu = (System().menu, Service().menu, Authentication().menu, Portal().menu, Darwin().menu, Apps().menu, Workflows().menu)
    results = {
        'MENUS': menu,
        'VERSION': settings.VERSION,
        'CURRENT_NODE': node_name,
        'DEV_MODE': settings.DEV_MODE,
        'TITLE': get_hostname(),
        'COLLAPSE': request.session.get('collapse')
    }

    return results
