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
__doc__ = 'Config View'


from django.http import HttpResponseRedirect, JsonResponse
from django.utils.translation import gettext as _
from gui.forms.form_utils import DivErrorList
from services.frontend.models import Frontend
from system.config.form import ConfigForm
from system.config.models import write_conf
from system.cluster.models import Cluster, Node
from system.exceptions import VultureSystemConfigError
from django.shortcuts import render
from django.urls import reverse

# Logger configuration imports
import logging
logger = logging.getLogger('services')


def build_response_config(module_url, command_list):
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
                'object_id': str(id), 'action': command,
            })
        }

    return JsonResponse(result, status=201)


def config_edit(request, object_id=None, api=False, update=False):
    config_model = Cluster.get_global_config()

    if hasattr(request, "JSON") and api:
        if update:
            request.JSON = {**config_model.to_dict(), **request.JSON}
        request_data = request.JSON
    else:
        request_data = request.POST

    form = ConfigForm(request_data or None, instance=config_model, error_class=DivErrorList)

    def render_form(**kwargs):
        save_error = kwargs.get('save_error')
        if api:
            if form.errors:
                return JsonResponse(form.errors.get_json_data(), status=400)
            if save_error:
                return JsonResponse({'error': save_error[0]}, status=500)
        return render(request, 'config/config.html', {'form': form, **kwargs})

    if request.method in ("POST", "PUT", "PATCH") and form.is_valid():
        config = form.save(commit=False)
        config.save()

        """ Write .ssh/authorized_keys if any change detected """
        if "ssh_authorized_key" in form.changed_data:
            params = [ "/usr/home/vlt-adm/.ssh/authorized_keys", request_data.get('ssh_authorized_key'), 'vlt-adm:wheel', '600' ]
            for node in Node.objects.all():
                try:
                    node.api_request('system.config.models.write_conf', config=params)
                except Exception as e:
                    raise VultureSystemConfigError("on node '{}'.\nRequest failure.".format(node.name))

        """ If customer name has changed, rewrite rsyslog templates """
        error = ""
        # If the internal Tenants config has changed, reload Rsyslog configuration of pstats
        if "internal_tenants" in form.changed_data:
            Cluster.api_request("services.rsyslogd.rsyslog.configure_pstats")
            Cluster.api_request("services.rsyslogd.rsyslog.restart_service")
        if "portal_cookie_name" in form.changed_data:
            # Reload Frontends with authenticated Workflows: session checks must be updated with the new cookie's name
            for frontend in Frontend.objects.filter(workflow__authentication__isnull=False).distinct():
                frontend.reload_conf()
        if "logs_ttl" in form.changed_data:
            res, mess = config_model.set_logs_ttl()
            if not res:
                return render_form(save_error=mess)
        if any(value in form.changed_data for value in ["pf_whitelist", "pf_blacklist"]):
            Cluster.api_request("services.pf.pf.gen_config")

        if error:
            return render_form(save_error=error)
        if api:
            return build_response_config("system.config.api", [])

        return HttpResponseRedirect('/system/config/')

    # If request PATCH or PUT & form not valid - return error
    if api:
        logger.error("Config api form error : {}".format(form.errors.get_json_data()))
        return JsonResponse(form.errors.get_json_data(), status=400)

    return render_form()


def pf_whitelist_blacklist(request, list_type=None):
    """
        Add or Delete an IP from PacketFilter Whitelist or Blacklist
        JSON Parameters:
            ip_address: IPv4/IPv6
            action: (str: add/delete)
    """

    #FIXME: Use decorators
    try:
        ip_address = request.JSON.get('ip_address')
        action = request.JSON.get('action')
    except:
        #We are coming from the GUI
        if not list_type:
            list_type = request.POST.get("list_type")

        ip_address = request.POST.get("ip_address")
        action = request.POST.get("action")

    if list_type not in ('blacklist', 'whitelist'):
        return JsonResponse({
            'status': False,
            'error': _('Invalid Packet Filter list')
        }, status=400)

    if action not in ('add', 'del'):
        return JsonResponse({
            'status': False,
            'error': _('Invalid action')
        }, status=400)

    if not ip_address:
        return JsonResponse({
            'status': False,
            'error': _('No ip address specified')
        }, status=400)

    config_model = Cluster.get_global_config()
    if list_type == "whitelist":
        pf_list = config_model.pf_whitelist.split(',')
    else:
        pf_list = config_model.pf_blacklist.split(',')

    if action == "add":
        if ip_address not in pf_list:
            pf_list.append(ip_address)
        else:
            return JsonResponse({
                'status': False,
                'error': _('address already present in list')
            }, status=400)
    elif action == "del":
        if ip_address in pf_list:
            pf_list.remove(ip_address)
        else:
            return JsonResponse({
                'status': False,
                'error': _('address not present in list')
            }, status=400)

    try:
        ConfigForm.validate_ip_list(pf_list)
        if list_type == "whitelist":
            config_model.pf_whitelist = ",".join(pf_list)
        else:
            config_model.pf_blacklist = ",".join(pf_list)

    except Exception as e:
        return JsonResponse({'status': False, 'error': str(e)}, status=500)

    config_model.save()
    Cluster.api_request("services.pf.pf.gen_config")
    return JsonResponse({'status': True, "data": ""})
