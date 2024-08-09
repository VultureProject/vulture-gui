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
__doc__ = 'Authentication Access Control views'

from authentication.auth_access_control.form import AuthAccessControlForm
from authentication.auth_access_control.models import AuthAccessControl, OPERATOR_CHOICES
from django.views.decorators.http import require_http_methods
from django.http import HttpResponseNotFound
from django.shortcuts import render
from django.conf import settings
import logging

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')

@require_http_methods(["GET"])
def auth_access_control_edit(request, object_id=None):
    access_control = None

    if object_id:
        try:
            access_control = AuthAccessControl.objects.get(pk=object_id)
        except AuthAccessControl.DoesNotExist:
            return HttpResponseNotFound()

    form = AuthAccessControlForm(None, instance=access_control)
    return render(request, "authentication/access_control/edit.html", {
        "object_id": object_id,
        "operators": OPERATOR_CHOICES,
        "form": form
    })
