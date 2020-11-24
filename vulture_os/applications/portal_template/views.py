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
                         HttpResponseNotAllowed)
from django.shortcuts import render
from django.urls import reverse
from django.utils.translation import ugettext_lazy as _

# Django project imports
from gui.forms.form_utils import DivErrorList
from applications.portal_template.models import PortalTemplate
from applications.portal_template.form import PortalTemplateForm
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

#
# def backend_clone(request, object_id):
#     """ Backend view used to clone a Backend object
#     N.B: Do not totally clone the object and save-it in MongoDB
#         because some attributes are unique constraints
#
#     :param request: Django request object
#     :param object_id: MongoDB object_id of a Backend object
#     """
#     if not object_id:
#         return HttpResponseRedirect('/apps/backend/')
#
#     """ Retrieve object from id in MongoDB """
#     try:
#         backend = Backend.objects.get(pk=object_id)
#     except ObjectDoesNotExist:
#         return HttpResponseForbidden("Injection detected")
#
#     server_form_list = []
#     header_form_list = []
#     httpchk_header_form_list = []
#
#     for l_tmp in backend.server_set.all():
#         l_tmp.pk = None
#         server_form_list.append(ServerForm(instance=l_tmp))
#     for h_tmp in backend.headers.all():
#         h_tmp.pk = None
#         header_form_list.append(HeaderForm(instance=h_tmp))
#     for k, v in backend.http_health_check_headers.items():
#         httpchk_header_form_list.append(HttpHealthCheckHeaderForm({'check_header_name': k, 'value': v}))
#
#     backend.pk = None
#     backend.name = 'Copy of {}'.format(backend.name)
#     form = BackendForm(None, instance=backend, error_class=DivErrorList)
#
#     return render(request, 'apps/backend_edit.html',
#                   {'form': form, 'servers': server_form_list, 'server_form': ServerForm(),
#                    'headers': header_form_list, 'header_form': HeaderForm(),
#                    'http_health_check_headers': httpchk_header_form_list,
#                    'http_health_check_headers_form': HttpHealthCheckHeaderForm(),
#                    'cloned': True})
#
#
# def backend_delete(request, object_id, api=False):
#     """ Delete Backend and related Listeners """
#     error = ""
#     try:
#         backend = Backend.objects.get(pk=object_id)
#     except ObjectDoesNotExist:
#         if api:
#             return JsonResponse({'error': _("Object does not exist.")}, status=404)
#         return HttpResponseForbidden("Injection detected")
#
#     if ((request.method == "POST" and request.POST.get('confirm', "").lower() == "yes")
#             or (api and request.method == "DELETE" and request.JSON.get('confirm', "").lower() == "yes")):
#
#         # Save backend filename before delete-it
#         backend_filename = backend.get_filename()
#
#         try:
#             # API request deletion of backend filename
#             Cluster.api_request('services.haproxy.haproxy.delete_conf', backend_filename)
#             # And reload of HAProxy service
#             Cluster.api_request('services.haproxy.haproxy.reload_service')
#             # If POST request and no error: delete frontend
#             backend.delete()
#
#             if api:
#                 return JsonResponse({
#                     'status': True
#                 }, status=204)
#             return HttpResponseRedirect(reverse('applications.backend.list'))
#
#         except Exception as e:
#             # If API request failure, bring up the error
#             logger.error("Error trying to delete backend '{}': API|Database failure. Details:".format(backend.name))
#             logger.exception(e)
#             error = "API or Database request failure: {}".format(str(e))
#
#             if api:
#                 return JsonResponse({'status': False,
#                                      'error': error}, status=500)
#     if api:
#         return JsonResponse({'error': _("Please confirm with confirm=yes in JSON body.")}, status=400)
#
#     # If GET request or POST request and API/Delete failure
#     return render(request, 'apps/backend_delete.html', {
#         'backend': backend,
#         'error': error
#     })


def template_edit(request, object_id=None, api=False):
    template = PortalTemplate()
    if object_id:
        try:
            template = PortalTemplate.objects.get(pk=object_id)
        except ObjectDoesNotExist:
            if api:
                return JsonResponse({'error': _("Object does not exist.")}, status=404)
            return HttpResponseForbidden("Injection detected")

    """ Create form with object if exists, and request.POST (or JSON) if exists """
    if hasattr(request, "JSON") and api:
        form = PortalTemplateForm(request.JSON or None, instance=template, error_class=DivErrorList)
    else:
        form = PortalTemplateForm(request.POST or None, instance=template, error_class=DivErrorList)

    def render_form(**kwargs):
        save_error = kwargs.get('save_error')
        if api:
            if form.errors:
                return JsonResponse(form.errors.get_json_data(), status=400)
            if save_error:
                return JsonResponse({'error': save_error[0]}, status=500)

        return render(request, 'apps/portal_template_edit.html',
                      {'form': form, **kwargs})

    if request.method in ("POST", "PUT", "PATCH"):

        # If errors has been added in form
        if not form.is_valid():
            logger.error("Form errors: {}".format(form.errors.as_json()))
            if api:
                return JsonResponse(form.errors.get_json_data(), status=400)
            return render_form()

        # Save the form to get an id if there is not already one
        template = form.save(commit=False)
        template.save()

        first_save = not object_id
        try:
            template.save_conf()
        except (VultureSystemError, ServiceError) as e:
            """ Error saving configuration file """
            """ The object has been saved, delete-it if needed """
            if first_save:
                template.delete()

            logger.exception(e)
            return render_form(save_error=[str(e), e.traceback])

        except Exception as e:
            """ If we arrive here, the object has not been saved """
            logger.exception(e)
            return render_form(save_error=["Failed to save object in database :\n{}".format(e),
                                                    str.join('', format_exception(*exc_info()))])

        if api:
            return build_response(template.id, "applications.portal_template.api", COMMAND_LIST)
        return HttpResponseRedirect('/apps/portal_template/')

    return render_form()



COMMAND_LIST = {
}
