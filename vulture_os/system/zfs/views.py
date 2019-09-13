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
__doc__ = 'ZFS View'


from django.http import HttpResponseForbidden, HttpResponseRedirect, JsonResponse
from django.utils.translation import ugettext_lazy as _
from django.core.exceptions import ObjectDoesNotExist

from django.shortcuts import render
from django.urls import reverse
from django.conf import settings

from system.zfs.models import ZFS

from system.cluster.models import Cluster

import logging

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('system')


def zfs_snapshot(request, object_id, api=False):
    """ Dedicated view used to create a ZFS Snapshot """

    try:
        zfs_model = ZFS.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        if api:
            return JsonResponse({'error': _("Object does not exist.")}, status=404)
        return HttpResponseForbidden("Injection detected")

    zfs_model.create_snapshot()
    if api:
        return JsonResponse({
            'status': True
        }, status=204)
    return HttpResponseRedirect(reverse('system.zfs.list'))


def zfs_restore(request, object_id, api=False):
    """ Dedicated view used to restore a ZFS Snapshot """

    try:
        zfs_model = ZFS.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        if api:
            return JsonResponse({'error': _("Object does not exist.")}, status=404)
        return HttpResponseForbidden("Injection detected")

    zfs_model.restore_snapshot()
    if api:
        return JsonResponse({
            'status': True
        }, status=204)

    return HttpResponseRedirect(reverse('system.zfs.list'))


def zfs_refresh(request, api=False):
    """ Dedicated view used to update the ZFS list into mongoDB (system => MongoDB) """
    cluster = Cluster.objects.get()
    try:
        cluster.api_request('system.zfs.zfs.refresh', config=None)
    except Exception as e:
        logger.error("Error trying to refresh ZFS list")
        logger.exception(e)
        error = "API request failure: {}".format(str(e))
        if api:
            return JsonResponse({'status': False,
                                 'error': error}, status=500)
    if api:
        return JsonResponse({
            'status': True
        }, status=204)

    return HttpResponseRedirect(reverse('system.zfs.list'))


def zfs_delete(request, object_id, api=False):

    error = ""
    try:
        zfs_model = ZFS.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        if api:
            return JsonResponse({'error': _("Object does not exist.")}, status=404)
        return HttpResponseForbidden("Injection detected")

    if((request.method == "POST" and request.POST.get('confirm', "").lower() == "yes")
       or (api and request.method == "DELETE" and request.JSON.get('confirm', "").lower() == "yes")):

        try:
            logger.debug("Trying to delete ZFS Snapshot {} ({})".format(zfs_model, zfs_model.id))
            message = "ZFS snapshot {} ({}) deleted".format(zfs_model, zfs_model.id)

            # Delete asked object
            zfs_model.delete_snapshot()

            if api:
                return JsonResponse({
                    'status': True
                }, status=204)
            return HttpResponseRedirect(reverse('system.zfs.list'))

        except Exception as e:
            logger.error("Error trying to delete ZFS Snapshot '{}' : API|Database failure. "
                         "Details:".format(zfs_model))
            logger.exception(e)
            error = "API or Database request failure: {}".format(str(e))

            if api:
                return JsonResponse({'status': False,
                                     'error': error}, status=500)

    # If no confirmation message
    if api:
        return JsonResponse({'error': _("Please confirm with confirm=yes in JSON body.")}, status=400)

    # If GET request or POST request and API/Delete failure
    return render(request, 'system/generic_delete.html', {
        'menu_name': _("System -> ZFS Snapshot -> Delete"),
        'redirect_url': reverse("system.zfs.list"),
        'delete_url': reverse("system.zfs.delete", kwargs={'object_id': zfs_model.id}),
        'obj_inst': zfs_model,
        'error': error
    })
