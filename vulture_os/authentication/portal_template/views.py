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
__doc__ = 'Portal templates View'

# Django system imports
from django.conf import settings
from django.http import (JsonResponse, HttpResponseBadRequest, HttpResponseForbidden, HttpResponseRedirect,
                         HttpResponseNotAllowed, HttpResponseNotFound)
from django.shortcuts import render
from django.urls import reverse
from django.utils.translation import ugettext_lazy as _
from django.views.decorators.http import require_http_methods

# Django project imports
from gui.forms.form_utils import DivErrorList
from authentication.portal_template.models import PortalTemplate
from authentication.portal_template.form import PortalTemplateForm
from toolkit.api.responses import build_response
from toolkit.http.headers import HeaderForm, Header

# Required exceptions imports
from django.core.exceptions import ObjectDoesNotExist
from services.exceptions import ServiceConfigError, ServiceError, ServiceReloadError
from system.exceptions import VultureSystemError

# Extern modules imports
from json import loads as json_loads
from sys import exc_info
from traceback import format_exception

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


@require_http_methods(["GET"])
def template_edit(request, object_id=None):
    portal_template = None

    if object_id:
        try:
            portal_template = PortalTemplate.objects.get(pk=object_id)
        except PortalTemplate.DoesNotExist:
            return HttpResponseNotFound()
    
    form = PortalTemplateForm(None, instance=portal_template)
    return render(request, "authentication/portal_template/edit.html", {
        "object_id": object_id,
        "form": form
    })


# def template_edit(request, object_id=None, api=False):
#     template = PortalTemplate()
#     if object_id:
#         try:
#             template = PortalTemplate.objects.get(pk=object_id)
#         except ObjectDoesNotExist:
#             if api:
#                 return JsonResponse({'error': _("Object does not exist.")}, status=404)
#             return HttpResponseNotFound("Object not found")

#     """ Create form with object if exists, and request.POST (or JSON) if exists """
#     if hasattr(request, "JSON") and api:
#         form = PortalTemplateForm(request.JSON or None, instance=template, error_class=DivErrorList)
#     else:
#         form = PortalTemplateForm(request.POST or None, instance=template, error_class=DivErrorList)

#     def render_form(**kwargs):
#         save_error = kwargs.get('save_error')
#         if api:
#             if form.errors:
#                 return JsonResponse(form.errors.get_json_data(), status=400)
#             if save_error:
#                 return JsonResponse({'error': save_error[0]}, status=500)

#         return render(request, 'portal/portal_template/edit.html',
#                       {'form': form, **kwargs})

#     if request.method in ("POST", "PUT", "PATCH"):

#         # If errors has been added in form
#         if not form.is_valid():
#             logger.error("Form errors: {}".format(form.errors.as_json()))
#             if api:
#                 return JsonResponse(form.errors.get_json_data(), status=400)
#             return render_form()

#         # Save the form to get an id if there is not already one
#         template = form.save(commit=False)
#         template.save()

#         first_save = not object_id
#         try:
#             template.save_conf()
#         except (VultureSystemError, ServiceError) as e:
#             """ Error saving configuration file """
#             """ The object has been saved, delete-it if needed """
#             if first_save:
#                 template.delete()

#             logger.exception(e)
#             return render_form(save_error=[str(e), e.traceback])

#         except Exception as e:
#             """ If we arrive here, the object has not been saved """
#             logger.exception(e)
#             return render_form(save_error=["Failed to save object in database :\n{}".format(e),
#                                                     str.join('', format_exception(*exc_info()))])

#         if api:
#             return build_response(template.id, "applications.portal_template.api", COMMAND_LIST)
#         return HttpResponseRedirect('/portal/template/')

#     return render_form()



# COMMAND_LIST = {
# }
