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
__doc__ = 'LogRotate service wrapper utils'

# Django system imports
from django.conf import settings
from django.http import HttpResponseForbidden, HttpResponseRedirect
from django.shortcuts import render

# Django project imports
from gui.forms.form_utils import DivErrorList
from services.logrotate.form import LogRotateForm
from services.logrotate.models import LogRotateSettings

# Required exceptions imports
from bson.errors import InvalidId

# Logger configuration imports
import logging

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('services')


def logrotate_edit(request, object_id=None):
    logrotate_model = None
    if object_id:
        try:
            logrotate_model = LogRotateSettings.objects.get()
            if not logrotate_model:
                raise InvalidId()
        except InvalidId:
            return HttpResponseForbidden("Injection detected")

    form = LogRotateForm(request.POST or None, instance=logrotate_model, error_class=DivErrorList)

    if request.method == "POST" and form.is_valid():
        logrotate_model = form.save(commit=False)
        logrotate_model.save()
        return HttpResponseRedirect('/services/logrotate/')

    return render(request, 'services/logrotate_edit.html', {'form': form})
