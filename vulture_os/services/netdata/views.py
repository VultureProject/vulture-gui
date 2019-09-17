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
__doc__ = 'Netdata View'


# Django system imports
from django.conf import settings
from django.http import JsonResponse, HttpResponseBadRequest
from django.shortcuts import render
from django.urls import reverse
from django.utils.translation import ugettext_lazy as _

# Django project imports
from gui.forms.form_utils import DivErrorList
from services.netdata.forms import NetdataForm
from services.netdata.models import NetdataSettings
from services.netdata.netdata import NetdataService
from system.cluster.models import Cluster, Node

# Required exceptions imports

# Extern modules imports
from sys import exc_info
from traceback import format_exception

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('services')


def build_response_netdata(module_url, command_list):
    result = {
        'links': {
            'get': {
                'rel': 'self', 'type': 'GET',
                'href': reverse(module_url)
            },
            'put': {
                'rel': 'self', 'type': 'PUT',
                'href': reverse(module_url)
            },
            'patch': {
                'rel': 'self', 'type': 'PATCH',
                'href': reverse(module_url)
            }
        }
    }
    for command in command_list:
        result[command] = {
            'rel': 'self', 'type': "POST", 'name': command,
            'href': reverse(module_url, kwargs={
                'action': command,
            })
        }
    return JsonResponse(result, status=201)


def netdata_edit(request, api=False, update=False):
    """ Netdata view
    Allow to edit the history settings for netdata config

    request (Django Request)
    api    Is this a django api
    Returns:
        TYPE: Django view
    """
    service = NetdataService()
    status = {}

    try:
        for node in Node.objects.all():
            status[node.name] = service.last_status()[0]
    except AttributeError:
        status[node.name] = "Error"

    try:
        netdata_model = NetdataSettings.objects.get()
    except NetdataSettings.DoesNotExist:
        netdata_model = NetdataSettings()

    if hasattr(request, "JSON") and api:
        if update:
            request.JSON = {**netdata_model.to_dict(), **request.JSON}
        netdata_form = NetdataForm(request.JSON or None, instance=netdata_model, error_class=DivErrorList)
    else:
        netdata_form = NetdataForm(request.POST or None, instance=netdata_model, error_class=DivErrorList)

    if request.method in ("POST", "PUT", "PATCH"):
        if netdata_form.is_valid():
            netdata_model = netdata_form.save(commit=False)
            netdata_model.save()

            Cluster.api_request(action="services.netdata.netdata.reload_conf")
        elif api:
            return JsonResponse(netdata_form.errors.get_json_data(), status=400)

    if api:
        return build_response_netdata("services.netdata.api", COMMAND_LIST)

    return render(request, 'services/netdata.html', {
        'netdata_form': netdata_form,
        'status': status
    })


def netdata_reload(request, api=False):
    if not request.is_ajax() and not api:
        return HttpResponseBadRequest()

    try:
        res = Cluster.api_request("services.netdata.netdata.reload_conf")
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
        logger.error("Error trying to reload netdata config: '{}'".format(str(e)))
        return JsonResponse({
            'status': False,
            'error': "API request failure : ".format(str(e)),
            'error_details': str.join('', format_exception(*exc_info()))
        }, status=500)


COMMAND_LIST = {
    'reload': netdata_reload
}
