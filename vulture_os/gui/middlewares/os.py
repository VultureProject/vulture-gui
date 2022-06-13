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

__author__ = "Olivier de Régis"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Middleware for GUI of Vulture OS'

from django.conf.urls.static import static
from django.http import HttpResponseRedirect, JsonResponse
from django.shortcuts import render
from system.cluster.models import Node, Cluster

from django.conf import settings
from django.urls import reverse

import logging
import os

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


class OsMiddleware:

    def __init__(self, get_response):
        self.get_response = get_response
        self.is_nodeBootstrapped = Cluster.get_current_node()
        # One-time configuration and initialization.

    def __call__(self, request):
        # Code to be executed for each request before
        # the view (and later middleware) are called.
        if not self.is_nodeBootstrapped:
            return render(request, "gui/not_install.html", {
                'TITLE': 'VultureOS',
                'WALLPAPER': static("img/VultureOS_wallpaper.png")
            })

        # No authentication for API (protected later by decorators)
        if request.path_info.startswith('/api/'):
            return self.get_response(request)
            

        # Check if is authenticated
        if "login" in request.path_info:
            return self.get_response(request)

        if not request.user.is_authenticated:
            if request.is_ajax():
                return JsonResponse({
                    'status': False,
                    'error': 'need_login'
                })
            if request.path != reverse('gui.login'):
                return HttpResponseRedirect("{}?next={}".format(reverse('gui.login'), request.path))
            else:
                return HttpResponseRedirect(reverse('gui.login'))

        try:
            response = self.get_response(request)
        except Exception as e:
            logger.critical("[NOT HANDLED ERROR] {}".format(e), exc_info=1)

            if settings.DEV_MODE:
                raise

            if request.is_ajax():
                return JsonResponse({
                    "status": False,
                    "error": "Please check the troubleshooting documentation <a target=\"blank\" href=\"https://www.vultureproject.org/doc/troubleshooting/troubleshooting.html\">here</a>"
                })
        # Code to be executed for each request/response after
        # the view is called.

        return response
