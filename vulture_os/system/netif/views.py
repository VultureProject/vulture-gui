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
__doc__ = 'Network View'


from django.http import HttpResponseForbidden, HttpResponseRedirect, JsonResponse
from system.cluster.models import NetworkAddress, NetworkAddressNIC, Cluster
from system.netif.form import NetIfForm, NetIfSystemForm
from django.utils.translation import ugettext_lazy as _
from django.core.exceptions import ObjectDoesNotExist
from django.utils.crypto import get_random_string
from toolkit.api.responses import build_response
from django.shortcuts import render
from django.urls import reverse
from django.conf import settings


import logging

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('system')


def netif_refresh(request):
    """
    Read system configuration and refresh NIC list
    :param request:
    :return:
    """
    Cluster.api_request('toolkit.network.network.refresh_nic')
    return HttpResponseRedirect('/system/netif/')


def netif_edit(request, object_id=None, api=False):

    netif_model = None
    if object_id:
        try:
            netif_model = NetworkAddress.objects.get(pk=object_id)
        except ObjectDoesNotExist:
            if api:
                return JsonResponse({'error': _("Object does not exist.")}, status=404)
            return HttpResponseForbidden("Injection detected")

    # Netif already exists and is a system interface
    if netif_model and netif_model.is_system is True:
        if hasattr(request, 'JSON') and api:
            form = NetIfSystemForm(request.JSON or None, instance=netif_model)
        else:
            form = NetIfSystemForm(request.POST or None, instance=netif_model)
    # Netif doesn't exist or is not a system interface
    else:
        if hasattr(request, 'JSON') and api:
            if request.JSON.get('is_system') is True:
                form = NetIfSystemForm(request.JSON or None, instance=netif_model)
            else:
                form = NetIfForm(request.JSON or None, instance=netif_model)
        else:
            form = NetIfForm(request.POST or None, instance=netif_model)

    if request.method in ("POST", "PUT") and form.is_valid():
        netif = form.save(commit=False)
        netif.save()

        """ CARP settings are defined by default, even if they are not used """
        priority = 50
        pwd = get_random_string(20)

        """ This is a new network address """
        if not object_id:
            if api:
                nics = request.JSON.get('nic')
            else:
                nics = request.POST.getlist("nic")
            for nic in nics:
                NetworkAddressNIC.objects.create(
                    nic_id=nic,
                    network_address=netif,
                    carp_passwd=pwd,
                    carp_priority=priority
                )

                priority = priority + 50
        else:

            """ Add new NIC, if any """
            if api:
                nic_list = request.JSON.get('nic')
            else:
                nic_list = request.POST.getlist('nic')

            for nic in nic_list:
                try:
                    NetworkAddressNIC.objects.get(network_address=netif, nic_id=nic)
                except NetworkAddressNIC.DoesNotExist:
                    NetworkAddressNIC.objects.create(
                        nic_id=nic,
                        network_address=netif,
                        carp_passwd=pwd,
                        carp_priority=priority
                    )

                    priority = priority + 50

            """ Delete old NIC, if any """
            for current_networkadress_nic in NetworkAddressNIC.objects.filter(network_address=netif):

                """ If the current nic is not in the new config anymore:
                Remove it from NetworkAddressNIC """
                if str(current_networkadress_nic.nic.pk) not in nic_list:
                    current_networkadress_nic.delete()


        """ Call ifconfig to setup network IP address right now """
        Cluster.api_request('toolkit.network.network.ifconfig_call', netif.id)

        """ Write permanent network configuration on disk """
        Cluster.api_request('toolkit.network.network.write_network_config')

        """ Garbage collector to delete obsolete running ifconfig and configuration """
        Cluster.api_request('toolkit.network.network.address_cleanup')

        """ Update PF configurations """
        Cluster.api_request ("services.pf.pf.gen_config")

        if api:
            return build_response(netif.id, "api.system.netaddr", [])

        return HttpResponseRedirect('/system/netif/')

    # If request POST or PUT & form not valid - return error
    if api:
        logger.error("NetworkAddress api form error : {}".format(form.errors.get_json_data()))
        return JsonResponse(form.errors.get_json_data(), status=400)

    if netif_model:
        return render(request, 'system/netif_edit.html', {
            'form': form,
            'is_system': netif_model.is_system
        })
    else:
        return render(request, 'system/netif_edit.html', {
            'form': form,
            'is_system': False
        })


def netif_delete(request, object_id, api=False):
    """ Dedicated view used to delete a NetworkAddress """
    error = ""
    try:
        netif_model = NetworkAddress.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        if api:
            return JsonResponse({'error': _("Object does not exist.")}, status=404)
        return HttpResponseForbidden("Injection detected")

    if((request.method == "POST" and request.POST.get('confirm', "").lower() == "yes")
       or (api and request.method == "DELETE" and request.JSON.get('confirm', "").lower() == "yes")):

        try:
            logger.debug("Trying to delete NetworkAddress {} ({})".format(netif_model, netif_model.id))
            message = "NetworkAddress {} ({}) deleted".format(netif_model, netif_model.id)

            # Delete asked object
            netif_model.delete()

            """ Write permanent network configuration on disk """
            Cluster.api_request('toolkit.network.network.write_network_config')

            """ Garbage collector to delete obsolete running ifconfig and configuration """
            Cluster.api_request('toolkit.network.network.address_cleanup')

            """ Update PF configurations """
            Cluster.api_request ("services.pf.pf.gen_config")

            if api:
                return JsonResponse({
                    'status': True
                }, status=204)
            return HttpResponseRedirect(reverse('system.netif.list'))

        except Exception as e:
            logger.error("Error trying to delete NetworkAddress '{}' : API|Database failure. "
                         "Details:".format(netif_model))
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
        'menu_name': _("System -> Network address -> Delete"),
        'redirect_url': reverse("system.netif.list"),
        'delete_url': reverse("system.netif.delete", kwargs={'object_id': netif_model.id}),
        'obj_inst': netif_model,
        'error': error
    })
