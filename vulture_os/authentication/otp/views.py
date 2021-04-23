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
__doc__ = 'OTP Repository views'


# Django system imports
from django.conf import settings
from django.http import HttpResponseBadRequest, HttpResponseForbidden, HttpResponseRedirect, JsonResponse
from django.http.response import HttpResponseNotFound
from django.utils.translation import gettext as _
from django.shortcuts import render

# Django project imports
from gui.forms.form_utils import DivErrorList
from toolkit.api.responses import build_response, build_form_errors

# Required exceptions imports
from django.core.exceptions import ObjectDoesNotExist
from authentication.otp.form import OTPRepositoryForm
from authentication.otp.models import OTPRepository

# Extern modules imports

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


def otp_clone(request, object_id):
    """ LDAPRepository view used to clone an object
    N.B: Do not totally clone the object and save-it in MongoDB 
        because some attributes are unique constraints
 
    :param request: Django request object
    :param object_id: MongoDB object_id of an LDAPRepository object
    """
    """ If POST request, same as edit with no ID """
    if request.POST:
        return otp_edit(request)

    try:
        otp = OTPRepository.objects.get(pk=object_id)
    except Exception as e:
        logger.exception(e)
        return HttpResponseNotFound(_("Object not found"))

    otp.pk = None
    otp.name = "Copy_of_" + str(otp.name)

    form = OTPRepositoryForm(None, instance=otp, error_class=DivErrorList)

    return render(request, 'authentication/otp_edit.html', {'form': form})


def otp_edit(request, object_id=None, api=False):
    otp = None
    if object_id:
        try:
            otp = OTPRepository.objects.get(pk=object_id)
        except ObjectDoesNotExist:
            if api:
                    return JsonResponse({'error': _("Object does not exist.")}, status=404)

            return HttpResponseNotFound(_("Object not found"))

    if hasattr(request, "JSON") and api:
        form = OTPRepositoryForm(request.JSON or None, instance=otp, error_class=DivErrorList)
    else:
        form = OTPRepositoryForm(request.POST or None, instance=otp, error_class=DivErrorList)

    if request.method in ("POST", "PUT") and form.is_valid():
        # Save the form to get an id if there is not already one
        otp = form.save(commit=False)
        otp.save()

        # If everything succeed, redirect to list view
        if api:
            return build_response(otp.id, "api.authentication.otp", [])
        return HttpResponseRedirect('/authentication/otp/')

    if api:
        return JsonResponse({"errors": build_form_errors(form.errors)}, status=400)
    return render(request, 'authentication/otp_edit.html', {'form': form})
