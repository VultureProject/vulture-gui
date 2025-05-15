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
__doc__ = 'Haproxy service wrapper utils'

# Django system imports
from django.conf import settings
from django.http import JsonResponse, HttpResponseBadRequest, HttpResponseForbidden, HttpResponseRedirect
from django.shortcuts import render

# Django project imports
from gui.forms.form_utils import DivErrorList
from services.haproxy.form import HAProxyForm
from services.haproxy.models import HAProxySettings
from services.pf.models import PFSettings
from services.darwin.models import DarwinSettings
from system.cluster.models import Node

# Required exceptions imports
from bson.errors import InvalidId

# Logger configuration imports
import logging

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('services')


def haproxy_edit(request, object_id=None):
    haproxy_model = None
    if object_id:
        try:
            haproxy_model = HAProxySettings.objects.get(pk=object_id)
            pf_model = PFSettings.objects.get()
            darwin_model = DarwinSettings.objects.get()
            if not haproxy_model:
                raise InvalidId()
        except InvalidId:
            return HttpResponseForbidden("Injection detected")

    form = HAProxyForm(request.POST or None, instance=haproxy_model, error_class=DivErrorList)

    if request.method == "POST" and form.is_valid():
        haproxy_model = form.save(commit=False)
        haproxy_model.save()
        return HttpResponseRedirect('/services/haproxy/')

    return render(request, 'services/haproxy_edit.html', {'form': form})


def haproxy_clone(request, object_id):
    """ HAProxy view used to clone an HAProxySettings object
    :param request: Django request object
    :param object_id: MongoDB object_id of an HAProxySettings
    """
    """ (try to) Retrieve object from id in MongoDB """
    try:
        haproxy_model = HAProxySettings.objects.get(pk=object_id)
        if not haproxy_model:
            raise InvalidId()
    except InvalidId:
        return HttpResponseForbidden("Injection detected")
    except HAProxySettings.DoesNotExist:
        return HttpResponseRedirect('/services/haproxy/')

    # members = balancer.members
    # members_list = list()
    # for member in members:
    #     member.pk=None
    #     member.save()
    #     members_list.append(member)
    haproxy_model.pk = None
    haproxy_model.name = 'Copy of ' + str(haproxy_model.name)
    # balancer.members = members_list
    haproxy_model.save()
    logger.info(haproxy_model.__dict__)

    return HttpResponseRedirect("/services/haproxy/")


def reload(request):
    if not request.headers.get('x-requested-with') == 'XMLHttpRequest':
        return HttpResponseBadRequest()

    error_nodes = {}
    for node in Node.objects.all():
        """ Send API request to reload haproxy service """
        # Do not apply any delay for actions triggered by the API
        api_res = node.api_request("services.haproxy.haproxy.reload_service")

        if not api_res.get('status'):
            error_nodes[node.name] = api_res.get('message')

    if not error_nodes:
        result = {'status': True, 'message': "HAProxy reload request sent."}
    else:
        result = {
            'status': False,
            'error': "API error on node(s): {}".format(','.join(error_nodes.keys())),
            'error_details': "\n".join(["Error on node {}\nDetails: \n{}".format(key, val)
                                        for key, val in error_nodes.items()])
        }

    return JsonResponse(result)
