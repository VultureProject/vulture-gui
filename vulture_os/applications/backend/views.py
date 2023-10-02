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
from django.utils.translation import gettext_lazy as _

# Django project imports
from gui.forms.form_utils import DivErrorList
from applications.backend.form import BackendForm, ServerForm
from applications.backend.models import Backend, BACKEND_OWNER, BACKEND_PERMS, Server
from services.darwin.darwin import get_darwin_sockets
from system.cluster.models import Cluster, Node
from toolkit.api.responses import build_response
from toolkit.http.headers import HeaderForm, Header, HttpHealthCheckHeaderForm

# Required exceptions imports
from django.core.exceptions import ObjectDoesNotExist
from django.db.models.deletion import ProtectedError
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


def backend_clone(request, object_id):
    """ Backend view used to clone a Backend object
    N.B: Do not totally clone the object and save-it in MongoDB
        because some attributes are unique constraints

    :param request: Django request object
    :param object_id: MongoDB object_id of a Backend object
    """
    if not object_id:
        return HttpResponseRedirect('/apps/backend/')

    """ Retrieve object from id in MongoDB """
    try:
        backend = Backend.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        return HttpResponseForbidden("Injection detected")

    server_form_list = []
    header_form_list = []
    httpchk_header_form_list = []

    for l_tmp in backend.server_set.all():
        l_tmp.pk = None
        server_form_list.append(ServerForm(instance=l_tmp))
    for h_tmp in backend.headers.all():
        h_tmp.pk = None
        header_form_list.append(HeaderForm(instance=h_tmp))
    for k, v in backend.http_health_check_headers.items():
        httpchk_header_form_list.append(HttpHealthCheckHeaderForm({'check_header_name': k, 'check_header_value': v}))

    backend.pk = None
    backend.name = 'Copy of {}'.format(backend.name)
    form = BackendForm(None, instance=backend, error_class=DivErrorList)

    available_sockets = get_darwin_sockets()

    return render(request, 'apps/backend_edit.html',
                  {'form': form, 'servers': server_form_list, 'server_form': ServerForm(),
                   'headers': header_form_list, 'header_form': HeaderForm(),
                   'http_health_check_headers': httpchk_header_form_list,
                   'http_health_check_headers_form': HttpHealthCheckHeaderForm(),
                   'sockets_choice': available_sockets,
                   'cloned': True})


def backend_delete(request, object_id, api=False):
    """ Delete Backend and related Listeners """
    error = ""
    try:
        backend = Backend.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        if api:
            return JsonResponse({'error': _("Object does not exist.")}, status=404)
        return HttpResponseForbidden("Injection detected")

    if ((request.method == "POST" and request.POST.get('confirm', "").lower() == "yes")
            or (api and request.method == "DELETE" and request.JSON.get('confirm', "").lower() == "yes")):

        # Save backend filename before delete-it
        backend_filename = backend.get_base_filename()

        try:
            # If POST request and no error: delete frontend
            backend.delete()

            # API request deletion of backend filename
            Cluster.api_request('services.haproxy.haproxy.delete_conf', backend_filename)

            # And reload of HAProxy service
            Cluster.api_request('services.haproxy.haproxy.reload_service')

            # Reload cluster PF configuration
            Cluster.api_request ("services.pf.pf.gen_config")

            if api:
                return JsonResponse({
                    'status': True
                }, status=204)

            return HttpResponseRedirect(reverse('applications.backend.list'))

        except ProtectedError as e:
            logger.error("Error trying to delete Backend '{}': Object is currently used :".format(backend.name))
            logger.exception(e)
            error = "Object is currently used by a Workflow, cannot be deleted"

            if api:
                return JsonResponse({
                    'status': False,
                    'error': error,
                    'protected': True
                }, status=500)

        except Exception as e:
            # If API request failure, bring up the error
            logger.error("Error trying to delete backend '{}': API|Database failure. Details:".format(backend.name))
            logger.exception(e)
            error = "API or Database request failure: {}".format(str(e))

            if api:
                return JsonResponse({'status': False,
                                     'error': error}, status=500)

    if api:
        return JsonResponse({'error': _("Please confirm with confirm=yes in JSON body.")}, status=400)

    # If GET request or POST request and API/Delete failure
    return render(request, 'generic_delete.html', {
        'menu_name': _("Applications -> Applications -> Delete"),
        'redirect_url': reverse("applications.backend.list"),
        'delete_url': reverse("applications.backend.delete", kwargs={'object_id': backend.id}),
        'obj_inst': backend,
        'error': error,
    })


def backend_edit(request, object_id=None, api=False):
    backend = None
    server_form_list = []
    header_form_list = []
    httpchk_header_form_list = []
    api_errors = []

    if object_id:
        try:
            backend = Backend.objects.get(pk=object_id)
        except ObjectDoesNotExist:
            if api:
                return JsonResponse({'error': _("Object does not exist.")}, status=404)
            return HttpResponseForbidden("Injection detected")

    """ Create form with object if exists, and request.POST (or JSON) if exists """
    if hasattr(request, "JSON") and api:
        form = BackendForm(request.JSON or None, instance=backend, error_class=DivErrorList)
    else:
        form = BackendForm(request.POST or None, instance=backend, error_class=DivErrorList)

    def render_form(back, **kwargs):
        save_error = kwargs.get('save_error')
        if api:
            if len(api_errors) > 0 or form.errors:
                api_errors.append(form.errors.as_json())
                return JsonResponse({"errors": api_errors}, status=400)

            if save_error:
                return JsonResponse({'error': save_error[0], 'details': save_error[1]}, status=500)

        available_sockets = get_darwin_sockets()

        if not server_form_list and back:
            for l_tmp in back.server_set.all():
                server_form_list.append(ServerForm(instance=l_tmp))

        if not header_form_list and back:
            for h_tmp in back.headers.all():
                header_form_list.append(HeaderForm(instance=h_tmp))

        if not httpchk_header_form_list and back:
            for k, v in back.http_health_check_headers.items():
                httpchk_header_form_list.append(HttpHealthCheckHeaderForm({'check_header_name': k, 'check_header_value': v}))

        return render(request, 'apps/backend_edit.html',
                      {'form': form, 'servers': server_form_list,
                       'net_server_form': ServerForm(mode='net'),
                       'unix_server_form': ServerForm(mode='unix'),
                       'headers': header_form_list, 'header_form': HeaderForm(),
                       'sockets_choice': available_sockets,
                       'http_health_check_headers': httpchk_header_form_list,
                       'http_health_check_headers_form': HttpHealthCheckHeaderForm(),
                       **kwargs})

    if request.method in ("POST", "PUT"):
        """ Handle JSON formatted listeners """
        try:
            if api:
                server_ids = request.JSON.get('servers', [])
                assert isinstance(server_ids, list), "Servers field must be a list."
            else:
                server_ids = json_loads(request.POST.get('servers', "[]"))
        except Exception as e:
            return render_form(backend, save_error=["Error in Servers field : {}".format(e),
                                                    str.join('', format_exception(*exc_info()))])
        header_objs = []
        httpchk_headers_dict = {}
        if form.data.get('mode') == "http":
            """ Handle JSON formatted request headers """
            try:
                if api:
                    header_ids = request.JSON.get('headers', [])
                    assert isinstance(header_ids, list), "Headers field must be a list."
                else:
                    header_ids = json_loads(request.POST.get('headers', "[]"))
            except Exception as e:
                return render_form(backend, save_error=["Error in Request-headers field : {}".format(e),
                                                        str.join('', format_exception(*exc_info()))])

            """ Handle JSON formatted request Http-health-check-headers """
            try:
                if api:
                    httpchk_headers_dict = request.JSON.get('http_health_check_headers', {})
                else:
                    httpchk_headers_dict = json_loads(request.POST.get('http_health_check_headers', "{}"))
                assert isinstance(httpchk_headers_dict, dict), "Health check headers field must be a dictionary."
            except Exception as e:
                return render_form(backend, save_error=["Error in Http-health-check-headers field : {}".format(e),
                                                        str.join('', format_exception(*exc_info()))])

            """ For each Health check header in list """
            for k,v in httpchk_headers_dict.items():
                httpchkform = HttpHealthCheckHeaderForm({'check_header_name': k, 'check_header_value': v}, error_class=DivErrorList)
                if not httpchkform.is_valid():
                    if api:
                        api_errors.append({"health_check": httpchkform.errors.get_json_data()})
                    else:
                        form.add_error('enable_http_health_check', httpchkform.errors.as_ul())
                    continue

                # Save forms in case we re-print the page
                httpchk_header_form_list.append(httpchkform)

            """ For each header in list """
            for header in header_ids:
                """ If id is given, retrieve object from mongo """
                try:
                    instance_h = Header.objects.get(pk=header['id']) if header.get('id') else None
                except ObjectDoesNotExist:
                    form.add_error(None, "Request-header with id {} not found. Injection detected ?")
                    continue

                """ And instantiate form with the object, or None """
                header_f = HeaderForm(header, instance=instance_h)
                if not header_f.is_valid():
                    if api:
                        api_errors.append({"headers": header_f.errors.get_json_data()})
                    else:
                        form.add_error('headers', header_f.errors.as_ul())
                    continue

                # Save forms in case we re-print the page
                header_form_list.append(header_f)
                # And save objects list, to save them later, when Frontend will be saved
                header_objs.append(header_f.save(commit=False))

        server_objs = []
        """ For each listener in list """
        for server in server_ids:
            """ If id is given, retrieve object from mongo """
            try:
                instance_s = Server.objects.get(pk=server['id']) if server.get('id') else None
            except ObjectDoesNotExist:
                form.add_error(None, "Server with id {} not found.".format(server['id']))
                continue

            """ And instantiate form with the object, or None """
            server_f = ServerForm(server, instance=instance_s)
            server_form_list.append(server_f)
            if not server_f.is_valid():
                if api:
                    api_errors.append({'server': server_f.errors.get_json_data()})
                else:
                    form.add_error(None, server_f.errors.as_ul())

                continue

            server_obj = server_f.save(commit=False)
            server_objs.append(server_obj)

        first_save = not object_id

        # Backend used by workflow type change check
        if not first_save and "mode" in form.changed_data:
            if backend.workflow_set.exists():
                if api:
                    api_errors.append({'mode': "You can't modify backend's mode, currently used by workflow(s) : {}".format([w.name for w in backend.workflow_set.all().only('name')])})
                else:
                    form.add_error('mode', "You can't modify backend's type, currently used by workflow(s) : {}".format(", ".join([w.name for w in backend.workflow_set.all().only('name')])))

        # If errors has been added in form
        if not form.is_valid():
            logger.error("Form errors: {}".format(form.errors.as_json()))
            return render_form(backend)

        # Save the form to get an id if there is not already one
        backend = form.save(commit=False)
        backend.configuration = ""
        backend.http_health_check_headers = httpchk_headers_dict

        # At least one server is required if Frontend enabled
        if not server_objs and backend.enabled:
            form.add_error(None, "At least one server is required if backend is enabled.")
            return render_form(backend)

        """ Generate the non-yet saved object conf """
        try:
            logger.debug("Generating conf of backend '{}'".format(backend.name))
            backend.configuration = backend.generate_conf(header_list=header_objs, server_list=server_objs)
            """ Save the conf on disk, and test-it with haproxy -c """
            logger.debug("Writing/Testing conf of backend '{}'".format(backend.name))
            backend.test_conf()
        except ServiceError as e:
            logger.exception(e)
            return render_form(backend, save_error=[str(e), e.traceback])

        except Exception as e:
            logger.exception(e)
            return render_form(backend, save_error=["No referenced error",
                                                    str.join('', format_exception(*exc_info()))])

        """ If the conf is OK, save the Backend object """
        # Is that object already in db or not
        try:
            logger.debug("Saving backend")
            backend.save()
            logger.debug("Backend '{}' (id={}) saved in MongoDB.".format(backend.name, backend.id))

            """ And all the listeners created earlier """
            for s in server_objs:
                s.backend = backend
                logger.debug("Saving server {}".format(str(s)))
                s.save()

            """ Delete listeners deleted in form """
            for s in backend.server_set.exclude(pk__in=[l.id for l in server_objs]):
                s.delete()
                logger.info("Deleting server {}".format(s))

            """ If mode is HTTP """
            if backend.mode == "http":
                """ Remove request-headers removed """
                for header in backend.headers.all():
                    if header not in header_objs:
                        backend.headers.remove(header)

                """ Associate added request-headers """
                for header in header_objs:
                    new_object = not header.id
                    header.save()
                    if new_object:
                        backend.headers.add(header)
                    logger.debug("HTTP Headers {} associated to Frontend {}".format(header, backend))

            """ if the Backend is updated and its name was changed """
            if not first_save and "name" in form.changed_data:
                logger.info("Backend name changed, looking for associated frontends...")
                workflow_list =  backend.workflow_set.all()
                for workflow in workflow_list:
                    logger.info("reloading frontend '{}' haproxy configuration".format(workflow.frontend))
                    workflow.frontend.reload_conf()

            # Re-generate config AFTER save, to get ID
            backend.configuration = backend.generate_conf()

            """ asynchronous API request to save conf on node """
            # Save conf first, to raise if there is an error
            backend.save_conf()
            logger.debug("Write conf of backend '{}' asked on cluster".format(backend.name))

            """ Reload HAProxy service - After rsyslog to prevent logging crash """
            api_res = Cluster.api_request("services.haproxy.haproxy.reload_service")
            if not api_res.get('status'):
                raise ServiceReloadError("on cluster\n API request error.", "haproxy",
                                         traceback=api_res.get('message'))

            for node in Node.objects.all():
                backend.status[node.name] = "WAITING"

            backend.save()

            Cluster.api_request("services.pf.pf.gen_config")


        except (VultureSystemError, ServiceError) as e:
            """ Error saving configuration file """
            """ The object has been saved, delete-it if needed """
            if first_save:
                for server in backend.server_set.all():
                    server.delete()

                backend.delete()

            logger.exception(e)
            return render_form(backend, save_error=[str(e), e.traceback])

        except Exception as e:
            """ If we arrive here, the object has not been saved """
            logger.exception(e)
            return render_form(backend, save_error=["Failed to save object in database :\n{}".format(e),
                                                    str.join('', format_exception(*exc_info()))])

        if api:
            return build_response(backend.id, "applications.backend.api", COMMAND_LIST)
        return HttpResponseRedirect('/apps/backend/')

    return render_form(backend)


def backend_start(request, object_id, api=False):
    if not request.META.get('HTTP_X_REQUESTED_WITH') == 'XMLHttpRequest':
        return HttpResponseBadRequest()

    try:
        backend = Backend.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        if api:
            return JsonResponse({'error': _("Object does not exist.")}, status=404)
        return HttpResponseForbidden('Injection detected.')

    try:
        """ Returns a string, or raise ServiceError """
        res = backend.enable()
    except ServiceError as e:
        logger.exception(e)
        return JsonResponse({'status': False, 'error': str(e), 'error_details': e.traceback})

    return JsonResponse({'status': True, 'message': res})


def backend_pause(request, object_id, api=False):
    if not request.META.get('HTTP_X_REQUESTED_WITH') == 'XMLHttpRequest':
        return HttpResponseBadRequest()

    try:
        backend = Backend.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        return HttpResponseForbidden('Injection detected.')

    try:
        res = backend.disable()
    except ServiceError as e:
        logger.exception(e)
        return JsonResponse({'status': False, 'error': str(e), 'error_details': e.traceback})

    return JsonResponse({'status': True, 'message': res})


COMMAND_LIST = {
    'start': backend_start,
    'pause': backend_pause,
}
