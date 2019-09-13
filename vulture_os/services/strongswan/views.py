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
__doc__ = 'Strongswan View'


# Django system imports
from django.conf import settings
from django.http import (JsonResponse, HttpResponseBadRequest, HttpResponseForbidden, HttpResponseRedirect)
from django.shortcuts import render
from django.urls import reverse
from django.utils.translation import ugettext_lazy as _

# Django project imports
from services.strongswan.form import StrongswanForm
from services.strongswan.models import Strongswan
from gui.forms.form_utils import DivErrorList

# Required exceptions imports
from django.core.exceptions import ObjectDoesNotExist
from services.exceptions import ServiceError, ServiceRestartError
from system.exceptions import VultureSystemError

# Extern modules imports
from sys import exc_info
from traceback import format_exception

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


def strongswan_clone(request, object_id=None):
    """ Strongswan view used to clone a Strongswan object

    :param request: Django request object
    :param object_id: MongoDB object_id of a Frontend object
    """
    if not object_id:
        return HttpResponseRedirect('/services/strongswan/')

    """ Retrieve object from id in MongoDB """
    try:
        strongswan = Strongswan.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        return HttpResponseForbidden("Injection detected")

    strongswan.pk = None
    strongswan.node = None
    form = StrongswanForm(None, instance=strongswan, error_class=DivErrorList)

    return render(request, 'services/strongswan_edit.html', {'form': form})


def strongswan_delete(request, object_id, api=False):
    """ Delete Strongswan config """
    error = ""
    try:
        strongswan = Strongswan.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        if api:
            return JsonResponse({
                'error': _("Object does not exist")
            }, status=404)

        return HttpResponseForbidden("Injection detected")

    if request.POST.get('confirm', "").lower() == "yes" or api:
        try:
            strongswan.node.api_request("services.strongswan.strongswan.stop_service")
            strongswan.delete()

            strongswan.node.api_request("services.strongswan.strongswan.set_rc_conf", "NO")

            if api:
                return JsonResponse({
                    'status': True
                }, status=204)

            return HttpResponseRedirect(reverse('services.strongswan.list'))

        except Exception as e:
            # If API request failure, bring up the error
            logger.error("Error trying to delete strongswan config: '{}'".format(str(e)))
            error = _("API or Database request failure:") + " {}".format(str(e))

            if api:
                return JsonResponse({
                    'status': False,
                    'error': error
                }, status=500)

    # If GET request or POST request and API/Delete failure
    return render(request, 'generic_delete.html', {
        'menu_name': _("Services -> IPSEC Configuration -> Delete"),
        'obj_inst': Strongswan, 'redirect_url': "/services/strongswan/",
        'delete_url': "/services/strongswan/delete/{}".format(object_id),
        'error': error
    })


def strongswan_edit(request, object_id, api=False, update=False):
    strongswan = None
    if object_id:
        try:
            strongswan = Strongswan.objects.get(pk=object_id)
        except ObjectDoesNotExist:
            if api:
                return JsonResponse({
                    'error': _("Object does not exist")
                }, status=404)

            return HttpResponseForbidden("Injection detected.")

    """ Create form with object if exists, and request.POST (or request.JSON) if exists """
    if hasattr(request, "JSON") and api:
        if update:
            request.JSON = {**strongswan.to_dict(), **request.JSON}
        form = StrongswanForm(request.JSON, instance=strongswan, error_class=DivErrorList)
    else:
        form = StrongswanForm(request.POST or None, instance=strongswan, error_class=DivErrorList)

    if request.method in ("POST", 'PUT', 'PATCH'):
        if not form.is_valid():
            if api:
                return JsonResponse(form.errors.get_json_data(), status=400)
            return render(request, 'services/strongswan_edit.html', {'form': form})

        # Save the form to get an id if there is not already one
        strongswan = form.save(commit=True)

        logger.info("Strongswan configuration updated in MongoDB.")
        try:
            strongswan.save_conf()
            logger.info("Write Strongswan conf on node '{}'".format(strongswan.node.name))

            if not strongswan.enabled:
                strongswan.node.api_request("services.strongswan.strongswan.set_rc_conf", "NO")
                """Stop strongswan"""
                api_res = strongswan.node.api_request("services.strongswan.strongswan.stop_service")
                if not api_res.get('status'):
                    raise ServiceRestartError(
                        "on node {}\n API request error.".format(strongswan.node.name),
                        "strongswan",
                        traceback=api_res.get('message')
                    )
            else:
                strongswan.node.api_request("services.strongswan.strongswan.set_rc_conf", "YES")
                """Reload strongswan"""
                api_res = strongswan.node.api_request("services.strongswan.strongswan.restart_service")
                if not api_res.get('status'):
                    raise ServiceRestartError(
                        "on node {}\n API request error.".format(strongswan.node.name),
                        "strongswan",
                        traceback=api_res.get('message')
                    )

        except (VultureSystemError, ServiceError) as e:
            """ Error saving configuration file """
            logger.exception(e)
            if api:
                return JsonResponse({
                    'error': str(e)
                }, status=500)

            return render(request, 'services/strongswan_edit.html', {
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
            return render(request, 'services/strongswan_edit.html', {
                'form': form,
                'save_error': errors
            })

        if api:
            return JsonResponse({
                'id': str(strongswan.pk),
                'links': {
                    'get': {
                        'rel': 'self', 'type': 'GET',
                        'href': reverse('services.strongswan.api', kwargs={
                            'object_id': str(strongswan.pk)
                        })
                    },
                    'put': {
                        'rel': 'self', 'type': 'PUT',
                        'href': reverse('services.strongswan.api', kwargs={
                            'object_id': str(strongswan.pk)
                        })
                    },
                    'delete': {
                        'rel': 'self', 'type': 'DELETE',
                        'href': reverse('services.strongswan.api', kwargs={
                            'object_id': str(strongswan.pk)
                        })
                    },
                    'start': {
                        'rel': 'self', 'type': 'POST', 'name': "start",
                        'href': reverse('services.strongswan.api', kwargs={
                            'object_id': str(strongswan.pk), 'action': "start",
                        })
                    },
                    'stop': {
                        'rel': 'self', 'type': 'POST', 'name': "stop",
                        'href': reverse('services.strongswan.api', kwargs={
                            'object_id': str(strongswan.pk), 'action': "stop",
                        })
                    },
                    'reload': {
                        'rel': 'self', 'type': 'POST', 'name': "reload",
                        'href': reverse('services.strongswan.api', kwargs={
                            'object_id': str(strongswan.pk), 'action': "reload",
                        })
                    },
                    'restart': {
                        'rel': 'self', 'type': 'POST', 'name': "restart",
                        'href': reverse('services.strongswan.api', kwargs={
                            'object_id': str(strongswan.pk), 'action': "restart",
                        })
                    }
                }
            }, status=201)

        return HttpResponseRedirect(reverse("services.strongswan.list"))

    return render(request, 'services/strongswan_edit.html', {'form': form})


def strongswan_start(request, object_id, api=False):
    if not request.is_ajax() and not api:
        return HttpResponseBadRequest()

    try:
        strongswan = Strongswan.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        if api:
            return JsonResponse({
                'error': _("Object does not exist")
            }, status=404)

        return HttpResponseForbidden('Injection detected.')

    try:
        res = strongswan.node.api_request("services.strongswan.strongswan.start_service")
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
        logger.error("Error trying to start strongswan config: '{}'".format(str(e)))
        return JsonResponse({
            'status': False,
            'error': "API request failure on node '{}'".format(strongswan.node.name),
            'error_details': str.join('', format_exception(*exc_info()))
        }, status=500)


def strongswan_restart(request, object_id, api=False):
    if not request.is_ajax() and not api:
        return HttpResponseBadRequest()

    try:
        strongswan = Strongswan.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        if api:
            return JsonResponse({
                'error': _("Object does not exist")
            }, status=404)

        return HttpResponseForbidden('Injection detected.')

    try:
        res = strongswan.node.api_request("services.strongswan.strongswan.restart_service")
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
        logger.error("Error trying to restart strongswan config: '{}'".format(str(e)))
        return JsonResponse({
            'status': False,
            'error': "API request failure on node '{}'".format(strongswan.node.name),
            'error_details': str.join('', format_exception(*exc_info()))
        }, status=500)


def strongswan_stop(request, object_id, api=False):
    if not request.is_ajax() and not api:
        return HttpResponseBadRequest()

    try:
        strongswan = Strongswan.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        if api:
            return JsonResponse({
                'error': _("Object does not exist")
            }, status=404)

        return HttpResponseForbidden('Injection detected.')

    try:
        res = strongswan.node.api_request("services.strongswan.strongswan.stop_service")
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
        logger.error("Error trying to stop strongswan config: '{}'".format(str(e)))
        return JsonResponse({
            'status': False,
            'error': "API request failure on node '{}'".format(strongswan.node.name),
            'error_details': str.join('', format_exception(*exc_info()))
        }, status=500)


def strongswan_reload(request, object_id, api=False):
    if not request.is_ajax() and not api:
        return HttpResponseBadRequest()

    try:
        strongswan = Strongswan.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        if api:
            return JsonResponse({
                'error': _("Object does not exist")
            }, status=404)

        return HttpResponseForbidden('Injection detected.')

    try:
        res = strongswan.node.api_request("services.strongswan.strongswan.reload_service")
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
        logger.error("Error trying to reload strongswan config: '{}'".format(str(e)))
        return JsonResponse({
            'status': False,
            'error': "API request failure on node '{}'".format(strongswan.node.name),
            'error_details': str.join('', format_exception(*exc_info()))
        }, status=500)


def strongswan_status(request, object_id, api=False):
    if not request.is_ajax() and not api:
        return HttpResponseBadRequest()

    try:
        strongswan = Strongswan.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        if api:
            return JsonResponse({
                'error': _("Object does not exist")
            }, status=404)

        return HttpResponseForbidden('Injection detected.')

    return JsonResponse({
        'data': strongswan.get_status()
    })
