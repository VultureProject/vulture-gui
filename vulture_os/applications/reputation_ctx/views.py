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
__doc__ = 'Listeners View'

# Django system imports
from django.conf import settings
from django.http import (JsonResponse, HttpResponseBadRequest, HttpResponseForbidden, HttpResponseRedirect,
                         HttpResponseNotAllowed)
from django.shortcuts import render
from django.urls import reverse
from django.utils.translation import ugettext_lazy as _

# Django project imports
from gui.forms.form_utils import DivErrorList
from applications.reputation_ctx.form import ReputationContextForm
from applications.reputation_ctx.models import ReputationContext
from system.cluster.models import Cluster, Node
from toolkit.api.responses import build_response
from toolkit.http.headers import HttpHealthCheckHeaderForm

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


def reputation_ctx_clone(request, object_id):
    """ Backend view used to clone a Backend object
    N.B: Do not totally clone the object and save-it in MongoDB 
        because some attributes are unique constraints
 
    :param request: Django request object
    :param object_id: MongoDB object_id of a Backend object
    """
    if not object_id:
        return HttpResponseRedirect('/apps/reputation_ctx/')

    """ Retrieve object from id in MongoDB """
    try:
        reputation_ctx = ReputationContext.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        return HttpResponseForbidden("Injection detected")

    header_form_list = []

    for k, v in reputation_ctx.custom_headers.items():
        header_form_list.append(HttpHealthCheckHeaderForm({'check_header_name': k, 'check_header_value': v}))

    reputation_ctx.pk = None
    reputation_ctx.internal = False
    reputation_ctx.name = 'Copy of {}'.format(reputation_ctx.name)
    form = ReputationContextForm(None, instance=reputation_ctx, error_class=DivErrorList)

    return render(request, 'apps/reputation_ctx_edit.html',
                  {'form': form, 'headers': header_form_list,
                   'header_form': HttpHealthCheckHeaderForm(),
                   'cloned': True})


def reputation_ctx_delete(request, object_id, api=False):
    """ Delete Backend and related Listeners """
    error = ""
    try:
        reputation_ctx = ReputationContext.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        if api:
            return JsonResponse({'error': _("Object does not exist.")}, status=404)
        return HttpResponseForbidden("Injection detected")

    if reputation_ctx.internal:
        error = "You cannot delete an internal reputation context"
    else:
        if ((request.method == "POST" and request.POST.get('confirm', "").lower() == "yes")
                or (api and request.method == "DELETE" and request.JSON.get('confirm', "").lower() == "yes")):

            # Save reputation_ctx filename before delete-it
            ctx_filename = reputation_ctx.absolute_filename

            try:
                """ Delete file """
                Cluster.api_request("system.config.models.delete_conf", ctx_filename)

                """ Disable the reputation context in frontend, to reload rsyslog conf """
                for frontendreputationcontext in reputation_ctx.frontendreputationcontext_set.all():
                    frontendreputationcontext.enabled = False
                    frontendreputationcontext.save()
                logger.info("Reputation '{}' disabled.".format(reputation_ctx.name))

                """ And reload Frontends conf """
                reputation_ctx.reload_frontend_conf()

                """ If everything's ok, delete the object """
                reputation_ctx.delete()
                logger.info("Reputation '{}' deleted.".format(ctx_filename))

                if api:
                    return JsonResponse({
                        'status': True
                    }, status=204)
                return HttpResponseRedirect(reverse('applications.reputation_ctx.list'))

            except Exception as e:
                # If API request failure, bring up the error
                logger.error("Error trying to delete reputation_ctx '{}': API|Database failure. "
                            "Details:".format(reputation_ctx.name))
                logger.exception(e)
                error = "API or Database request failure: {}".format(str(e))

                if api:
                    return JsonResponse({'status': False,
                                        'error': error}, status=500)
        if api:
            return JsonResponse({'error': _("Please confirm with confirm=yes in JSON body.")}, status=400)

    # If GET request or POST request and API/Delete failure
    return render(request, 'generic_delete.html', {
        'menu_name': _("Applications -> Context Tags -> Delete"),
        'redirect_url': reverse("applications.reputation_ctx.list"),
        'delete_url': reverse("applications.reputation_ctx.delete", kwargs={'object_id': reputation_ctx.id}),
        'obj_inst': reputation_ctx,
        'error': error,
        'used_by': reputation_ctx.frontend_set.all(),
    })


def reputation_ctx_edit(request, object_id=None, api=False, update=False):
    header_form_list = list()
    reputation_ctx = None
    if object_id:
        try:
            reputation_ctx = ReputationContext.objects.get(pk=object_id)
        except ObjectDoesNotExist:
            if api:
                return JsonResponse({'error': _("Object does not exist.")}, status=404)
            return HttpResponseForbidden("Injection detected")

    """ Create form with object if exists, and request.POST (or JSON) if exists """
    if (hasattr(request, "JSON") and api) or (request.method in ("POST", "PUT") and reputation_ctx and reputation_ctx.internal):
        # If internal objects, only tags is allowed to be modified
        if reputation_ctx and reputation_ctx.internal:
            request.JSON = {**reputation_ctx.to_dict(), 'tags': request.POST.get('tags')}
        elif update:
            request.JSON = {**reputation_ctx.to_dict(), **request.JSON}
        form = ReputationContextForm(request.JSON or None, instance=reputation_ctx, error_class=DivErrorList)
    else:
        form = ReputationContextForm(request.POST or None, instance=reputation_ctx, error_class=DivErrorList)

    def render_form(ctx, **kwargs):
        save_error = kwargs.get('save_error')
        if api:
            if form.errors:
                return JsonResponse(form.errors.get_json_data(), status=400)
            if save_error:
                return JsonResponse({'error': save_error[0]}, status=500)

        if not header_form_list and ctx:
            for k, v in ctx.custom_headers.items():
                header_form_list.append(HttpHealthCheckHeaderForm(initial={'check_header_name': k, 'check_header_value': v}))

        return render(request, 'apps/reputation_ctx_edit.html',
                      {'form': form,
                       'headers': header_form_list,
                       'header_form': HttpHealthCheckHeaderForm(),
                       **kwargs})

    if request.method in ("POST", "PUT", "PATCH"):
        headers_dict = {}
        """ Handle JSON formatted request Http-health-check-headers """
        try:
            if api:
                header_ids = request.JSON.get('custom_headers', [])
                assert isinstance(header_ids, list), "Custom headers field must be a list."
            else:
                header_ids = json_loads(request.POST.get('custom_headers') or "[]")
        except Exception as e:
            return render_form(reputation_ctx, save_error=["Error in Custom_headers field : {}".format(e),
                                                           str.join('', format_exception(*exc_info()))])

        """ For each Health check header in list """
        for header in header_ids:
            headerform = HttpHealthCheckHeaderForm(header, error_class=DivErrorList)
            if not headerform.is_valid():
                if api:
                    form.add_error(None, headerform.errors.get_json_data())
                else:
                    form.add_error('custom_headers', headerform.errors.as_ul())
                continue
            # Save forms in case we re-print the page
            header_form_list.append(headerform)
            headers_dict[header.get('check_header_name')] = header.get('check_header_value')

        # If errors has been added in form
        if not form.is_valid():
            logger.error("Form errors: {}".format(form.errors.as_json()))
            return render_form(reputation_ctx)

        # Save the form to get an id if there is not already one
        reputation_ctx = form.save(commit=False)
        reputation_ctx.custom_headers = headers_dict

        if not reputation_ctx.internal:
            """ Generate the non-yet saved object conf """
            try:
                logger.info("Trying to retrieve MMDB database context '{}'".format(reputation_ctx.name))
                content = reputation_ctx.download_mmdb()
                logger.info("Reputation context '{}' successfully downloaded".format(reputation_ctx.name))
            except VultureSystemError as e:
                logger.exception(e)
                return render_form(reputation_ctx, save_error=[str(e), e.traceback])

            except Exception as e:
                logger.exception(e)
                return render_form(reputation_ctx, save_error=["No referenced error",
                                                               str.join('', format_exception(*exc_info()))])

        """ If the conf is OK, save the ReputationContext object """
        # Is that object already in db or not
        first_save = not reputation_ctx.id
        try:
            logger.debug("Saving reputation context")
            reputation_ctx.save()
            logger.debug("Reputation CTX '{}' (id={}) saved in MongoDB.".format(reputation_ctx.name, reputation_ctx.id))

            # If it is not an internal database, write the file on disk
            if not reputation_ctx.internal:
                """ API request asynchrone to save conf on node """
                # Save conf, to raise if there is an error
                reputation_ctx.save_conf()
                logger.info("Write file of reputationCTX '{}' asked on cluster".format(reputation_ctx.name))

        except (VultureSystemError, ServiceError) as e:
            """ Error saving configuration file """
            """ The object has been saved, delete-it if needed """
            if first_save:
                reputation_ctx.delete()

            logger.exception(e)
            return render_form(reputation_ctx, save_error=[str(e), e.traceback])

        except Exception as e:
            """ If we arrive here, the object has not been saved """
            logger.exception(e)
            return render_form(reputation_ctx, save_error=["Failed to save object in database :\n{}".format(e),
                                                    str.join('', format_exception(*exc_info()))])

        if api:
            return build_response(reputation_ctx.id, "applications.reputation_ctx.api", COMMAND_LIST)
        return HttpResponseRedirect('/apps/reputation_ctx/')

    return render_form(reputation_ctx)


def reputation_ctx_download(request, object_id, api=False):
    if not request.is_ajax() and not api:
        return HttpResponseBadRequest()

    try:
        reputation_ctx = ReputationContext.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        if api:
            return JsonResponse({'error': _("Object does not exist.")}, status=404)
        return HttpResponseForbidden('Injection detected.')

    try:
        """ Returns a string, or raise ServiceError """
        res = reputation_ctx.download_file()
    except VultureSystemError as e:
        logger.exception(e)
        return JsonResponse({'status': False, 'error': str(e), 'error_details': e.traceback})

    return JsonResponse({'status': True, 'message': res})


COMMAND_LIST = {
    'force_download': reputation_ctx_download
}
