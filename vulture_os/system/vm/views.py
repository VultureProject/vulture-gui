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
__doc__ = 'VM View'



from django.http import HttpResponseForbidden, HttpResponseRedirect,JsonResponse
from django.utils.translation import ugettext_lazy as _
from django.core.exceptions import ObjectDoesNotExist

from django.shortcuts import render
from django.urls import reverse
from django.conf import settings

from system.vm.models import VM

from system.cluster.models import Cluster

import logging

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('system')

def vm_start (request, object_id, api=False):
    try:
        vm_model = VM.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        if api:
            return JsonResponse({'error': _("Object does not exist.")}, status=404)
        return HttpResponseForbidden("Injection detected")

    vm_model.start_vm()

    if api:
        return JsonResponse({
            'status': True
        }, status=204)

    return HttpResponseRedirect(reverse('system.vm.list'))


def vm_stop (request, object_id, api=False):
    try:
        vm_model = VM.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        if api:
            return JsonResponse({'error': _("Object does not exist.")}, status=404)
        return HttpResponseForbidden("Injection detected")

    vm_model.stop_vm()

    if api:
        return JsonResponse({
            'status': True
        }, status=204)

    return HttpResponseRedirect(reverse('system.vm.list'))


def vm_delete(request, object_id, api=False):

    error = ""
    try:
        vm_model = VM.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        if api:
            return JsonResponse({'error': _("Object does not exist.")}, status=404)
        return HttpResponseForbidden("Injection detected")

    if((request.method == "POST" and request.POST.get('confirm', "").lower() == "yes")
       or (api and request.method == "DELETE" and request.JSON.get('confirm', "").lower() == "yes")):

        try:
            logger.debug("Trying to delete VM {} ({})".format(vm_model, vm_model.id))
            message = "ZFS snapshot {} ({}) deleted".format(vm_model, vm_model.id)

            # Delete asked object
            vm_model.delete_vm()

            if api:
                return JsonResponse({
                    'status': True
                }, status=204)
            return HttpResponseRedirect(reverse('system.vm.list'))

        except Exception as e:
            logger.error("Error trying to delete VM '{}' : API|Database failure. "
                         "Details:".format(vm_model))
            logger.exception(e)
            error = "API or Database request failure: {}".format(str(e))

            if api:
                return JsonResponse({'status': False,
                                     'error': error}, status=500)

    # If no confirmation message
    if api:
        return JsonResponse({'error': _("Please confirm with confirm=yes in JSON body.")}, status=400)

    # If GET request or POST request and API/Delete failure
    return render(request, 'generic_delete.html', {
        'menu_name': _("System -> VM -> Delete"),
        'redirect_url': reverse("system.vm.list"),
        'delete_url': reverse("system.vm.delete", kwargs={'object_id': vm_model.id}),
        'obj_inst': vm_model,
        'error': error
    })
