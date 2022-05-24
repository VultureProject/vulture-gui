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
__doc__ = 'Openvpn View'


# Django system imports
from django.conf import settings
from django.http import (JsonResponse, HttpResponseBadRequest, HttpResponseForbidden, HttpResponseRedirect,
                         HttpResponseNotAllowed)
from django.shortcuts import render
from django.urls import reverse
from django.utils.translation import ugettext_lazy as _

# Django project imports
from services.openvpn.form import OpenvpnForm
from services.openvpn.models import Openvpn
from gui.forms.form_utils import DivErrorList

# Required exceptions imports
from django.core.exceptions import ObjectDoesNotExist
from services.exceptions import ServiceConfigError, ServiceError, ServiceRestartError
from system.exceptions import VultureSystemError

# Extern modules imports
from json import loads as json_loads
from re import findall as re_findall
from sys import exc_info
from traceback import format_exception

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


def openvpn_clone(request, object_id=None):
    """ Openvpn view used to clone an Openvpn object

    :param request: Django request object
    :param object_id: MongoDB object_id of an Openvpn object
    """
    if not object_id:
        return HttpResponseRedirect('/services/openvpn/')

    """ Retrieve object from id in MongoDB """
    try:
        openvpn = Openvpn.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        return HttpResponseForbidden("Injection detected")

    openvpn.pk = None
    openvpn.node = None
    form = OpenvpnForm(None, instance=openvpn, error_class=DivErrorList)

    return render(request, 'services/openvpn_edit.html', {'form': form})


def openvpn_delete(request, object_id, api=False):

    """ Delete Openvpn config """
    error = ""
    try:
        openvpn = Openvpn.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        if api:
            return JsonResponse({
                'error': _("Object does not exist")
            }, status=404)

        return HttpResponseForbidden("Injection detected")

    if request.POST.get('confirm', "").lower() == "yes" or api:
        try:
            openvpn.node.api_request("services.openvpn.openvpn.stop_service")
            openvpn.node.api_request("services.openvpn.openvpn.set_rc_conf", "NO")
            openvpn.delete()

            if api:
                return JsonResponse({
                    'status': True
                }, status=204)

            return HttpResponseRedirect(reverse('services.openvpn.list'))

        except Exception as e:
            # If API request failure, bring up the error
            logger.error("Error trying to delete openvpn config: '{}'".format (str(e)))
            error = _("API or Database request failure:") + " {}".format(str(e))

            if api:
                return JsonResponse({
                    'status': False,
                    'error': error
                }, status=500)

    # If GET request or POST request and API/Delete failure
    return render(request, 'generic_delete.html',
    {
        'menu_name': _("Services -> VPNSSL Client -> Delete"),
        'obj_inst': Openvpn, 'redirect_url': "/services/openvpn/",
        'delete_url': "/services/openvpn/delete/{}".format(object_id),
        'error': error
    })


def openvpn_edit(request, object_id=None, api=False, update=False):
    openvpn = None
    if object_id:
        try:
            openvpn = Openvpn.objects.get(pk=object_id)
        except ObjectDoesNotExist:
            if api:
                return JsonResponse({
                    'error': _("Object does not exist")
                }, status=404)

            return HttpResponseForbidden(_("Object does not exist"))

    """ Create form with object if exists, and request.POST (or request.JSON) if exists """
    if hasattr(request, "JSON") and api:
        if update:
            request.JSON = {**openvpn.to_dict(), **request.JSON}
        form = OpenvpnForm(request.JSON, instance=openvpn, error_class=DivErrorList)
    else:
        form = OpenvpnForm(request.POST or None, instance=openvpn, error_class=DivErrorList)

    if request.method in ("POST", 'PUT', 'PATCH'):
        if not form.is_valid():
            if api:
                return JsonResponse(form.errors.get_json_data(), status=400)
            return render(request, 'services/openvpn_edit.html', {'form': form})

        # Save the form to get an id if there is not already one
        openvpn = form.save(commit=True)

        logger.info("Openvpn configuration updated in MongoDB.")
        try:
            openvpn.save_conf()
            logger.info("Write Openvpn conf on node '{}'".format(openvpn.node.name))

            if not openvpn.enabled:

                """ Stop openvpn """
                openvpn.node.api_request("services.openvpn.openvpn.set_rc_conf", "NO")
                api_res = openvpn.node.api_request("services.openvpn.openvpn.stop_service")
                if not api_res.get('status'):
                    raise ServiceError(
                        "on node {}\n API request error.".format(openvpn.node.name),
                        "openvpn",
                        traceback=api_res.get('message')
                    )

            else:

                """ Reload openvpn """
                openvpn.node.api_request("services.openvpn.openvpn.set_rc_conf", "YES")
                api_res = openvpn.node.api_request("services.openvpn.openvpn.restart_service")
                if not api_res.get('status'):
                    raise ServiceRestartError(
                        "on node {}\n API request error.".format(openvpn.node.name),
                        "openvpn",
                        traceback=api_res.get('message')
                    )

        except (VultureSystemError, ServiceError) as e:
            """ Error saving configuration file """
            logger.exception(e)
            if api:
                return JsonResponse({
                    'error': str(e)
                }, status=500)

            return render(request, 'services/openvpn_edit.html', {
                'form': form, 
                'save_error': [str(e), e.traceback]
            })

        except Exception as e:
            """ If we arrive here, the object has been saved """
            logger.exception(e)
            if api:
                return JsonResponse({
                    'error': str(e)
                }, status=500)

            errors = ["Unknown error :\n{}".format(e),
                      str.join('', format_exception(*exc_info()))]
            return render(request, 'services/openvpn_edit.html', {
                'form': form, 
                'save_error': errors
            })

        if api:
            return JsonResponse({
                'id': str(openvpn.pk),
                'links': {
                    'get': {
                        'rel': 'self', 'type': 'GET',
                        'href': reverse('services.openvpn.api', kwargs={
                            'object_id': str(openvpn.pk)
                        })
                    },
                    'put': {
                        'rel': 'self', 'type': 'PUT',
                        'href': reverse('services.openvpn.api', kwargs={
                            'object_id': str(openvpn.pk)
                        })
                    },
                    'delete': {
                        'rel': 'self', 'type': 'DELETE',
                        'href': reverse('services.openvpn.api', kwargs={
                            'object_id': str(openvpn.pk)
                        })
                    },
                    'start': { 
                        'rel': 'self', 'type': 'POST', 'name': "start",
                        'href': reverse('services.openvpn.api', kwargs={
                            'object_id': str(openvpn.pk), 'action': "start",
                        })
                    },
                    'stop': { 
                        'rel': 'self', 'type': 'POST', 'name': "stop",
                        'href': reverse('services.openvpn.api', kwargs={
                            'object_id': str(openvpn.pk), 'action': "stop",
                        })
                    },
                    'reload': { 
                        'rel': 'self', 'type': 'POST', 'name': "reload",
                        'href': reverse('services.openvpn.api', kwargs={
                            'object_id': str(openvpn.pk), 'action': "reload",
                        })
                    },
                    'restart': { 
                        'rel': 'self', 'type': 'POST', 'name': "restart",
                        'href': reverse('services.openvpn.api', kwargs={
                            'object_id': str(openvpn.pk), 'action': "restart",
                        })
                    }
                }
            }, status=201)

        return HttpResponseRedirect(reverse("services.openvpn.list"))

    return render(request, 'services/openvpn_edit.html', {'form': form})


def openvpn_start(request, object_id, api=False):
    if not request.is_ajax() and not api:
        return HttpResponseBadRequest()

    try:
        openvpn = Openvpn.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        if api:
            return JsonResponse({
                'error': _("Object does not exist")
            }, status=404)

        return HttpResponseForbidden('Injection detected.')

    try:
        res = openvpn.node.api_request("services.openvpn.openvpn.start_service")
        if not res.get('status'):
            res['error'] = res.pop('message', "")
            status = 500
        else:
            status = 202
            if not res.get('message'):
                res['message'] = _("Starting service. Please wait a moment please...")

        return JsonResponse(res, status=status)

    except Exception as e:
        # If API request failure, bring up the error
        logger.error("Error trying to start openvpn config: '{}'".format(str(e)))
        return JsonResponse({
            'status': False, 
            'error': "API request failure on node '{}'".format(openvpn.node.name),
            'error_details': str.join('', format_exception(*exc_info()))
        }, status=500)


def openvpn_restart(request, object_id, api=False):
    if not request.is_ajax() and not api:
        return HttpResponseBadRequest()

    try:
        openvpn = Openvpn.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        if api:
            return JsonResponse({
                'error': _("Object does not exist")
            }, status=404)

        return HttpResponseForbidden('Injection detected.')

    try:
        res = openvpn.node.api_request("services.openvpn.openvpn.restart_service")
        if not res.get('status'):
            res['error'] = res.pop('message', "")
            status = 500
        else:
            status = 202
            if not res.get('message'):
                res['message'] = _("Restarting service. Please wait a moment please...")

        return JsonResponse(res, status=status)

    except Exception as e:
        # If API request failure, bring up the error
        logger.error("Error trying to restart openvpn config: '{}'".format(str(e)))
        return JsonResponse({
            'status': False, 
            'error': "API request failure on node '{}'".format(openvpn.node.name),
            'error_details': str.join('', format_exception(*exc_info()))
        }, status=500)


def openvpn_stop(request, object_id, api=False):
    if not request.is_ajax() and not api:
        return HttpResponseBadRequest()

    try:
        openvpn = Openvpn.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        if api:
            return JsonResponse({
                'error': _("Object does not exist")
            }, status=404)

        return HttpResponseForbidden('Injection detected.')

    try:
        res = openvpn.node.api_request("services.openvpn.openvpn.stop_service")
        if not res.get('status'):
            res['error'] = res.pop('message', "")
            status = 500
        else:
            status = 202
            if not res.get('message'):
                res['message'] = _("Stopping service. Please wait a moment please...")

        return JsonResponse(res, status=status)

    except Exception as e:
        # If API request failure, bring up the error
        logger.error("Error trying to stop openvpn config: '{}'".format (str(e)))
        return JsonResponse({
            'status': False, 
            'error': "API request failure on node '{}'".format(openvpn.node.name),
            'error_details': str.join('', format_exception(*exc_info()))
        }, status=500)


def openvpn_reload(request, object_id, api=False):
    if not request.is_ajax() and not api:
        return HttpResponseBadRequest()

    try:
        openvpn = Openvpn.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        if api:
            return JsonResponse({
                'error': _("Object does not exist")
            }, status=404)

        return HttpResponseForbidden('Injection detected.')

    try:
        res = openvpn.node.api_request("services.openvpn.openvpn.reload_service")
        if not res.get('status'):
            res['error'] = res.pop('message', "")
            status = 500
        else:
            status = 202
            if not res.get('message'):
                res['message'] = _("Reloading service. Please wait a moment please...")

        return JsonResponse(res, status=status)

    except Exception as e:
        # If API request failure, bring up the error
        logger.error("Error trying to reload openvpn config: '{}'".format (str(e)))
        return JsonResponse({
            'status': False, 
            'error': "API request failure on node '{}'".format(openvpn.node.name),
            'error_details': str.join('', format_exception(*exc_info()))
        }, status=500)


def openvpn_status(request, object_id, api=False):
    if not request.is_ajax() and not api:
        return HttpResponseBadRequest()

    try:
        openvpn = Openvpn.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        if api:
            return JsonResponse({
                'error': _("Object does not exist")
            }, status=404)

        return HttpResponseForbidden('Injection detected.')

    return JsonResponse({
        'data': openvpn.get_status()
    })

