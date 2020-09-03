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
__author__ = "Kévin GUILLEMOT"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Tenants View'

from django.core.exceptions import ObjectDoesNotExist
from django.http import HttpResponseRedirect, JsonResponse, HttpResponseForbidden
from django.utils.translation import gettext as _
from gui.forms.form_utils import DivErrorList
from system.tenants.form import TenantsForm
from system.tenants.models import Tenants
from system.cluster.models import Cluster, Node
from django.shortcuts import render
from toolkit.api.responses import build_response
from base64 import b64encode
from applications.reputation_ctx.models import ReputationContext
from django.urls import reverse


# Logger configuration imports
import logging
logger = logging.getLogger('system')


def tenants_clone(request, object_id):
    """ LDAPRepository view used to clone an object
    N.B: Do not totally clone the object and save-it in MongoDB 
        because some attributes are unique constraints

    :param request: Django request object
    :param object_id: MongoDB object_id of an LDAPRepository object
    """
    """ If POST request, same as edit with no ID """
    if request.POST:
        return tenants_edit(request)

    try:
        tenants = Tenants.objects.get(pk=object_id)
    except Exception as e:
        logger.exception(e)
        return HttpResponseForbidden("Injection detected")

    tenants.pk = None
    tenants.name = "Copy_of_" + str(tenants.name)

    form = TenantsForm(None, instance=tenants, error_class=DivErrorList)

    return render(request, 'system/tenants_edit.html', {'form': form})


def tenants_edit(request, object_id=None, api=False, update=False):
    """ View used to edit/create a tenants config """
    tenant_model = None
    if object_id:
        try:
            tenant_model = Tenants.objects.get(pk=object_id)
        except ObjectDoesNotExist:
            if api:
                return JsonResponse({'error': _("Object does not exist.")}, status=404)
            return HttpResponseForbidden("Injection detected")

    """ Create form with object if exists, and request.POST (or JSON) if exists """
    if hasattr(request, "JSON") and api:
        if update and tenant_model:
            request.JSON = {**tenant_model.to_dict(), **request.JSON}
        form = TenantsForm(request.JSON, instance=tenant_model, error_class=DivErrorList)
    else:
        form = TenantsForm(request.POST or None, instance=tenant_model, error_class=DivErrorList)

    def render_form(**kwargs):
        # if not object_id:
        #     return render(request, 'system/cluster_add.html', {'form': form, **kwargs})
        save_error = kwargs.get('save_error')
        if api:
            if form.errors:
                return JsonResponse(form.errors.get_json_data(), status=400)
            if save_error:
                return JsonResponse({'error': save_error[0]}, status=500)
        return render(request, 'system/tenants_edit.html', {'form': form, **kwargs})

    # Save old attributes BEFORE IS_VALID
    if tenant_model:
        old_predator_apikey = str(tenant_model.predator_apikey)

    if request.method in ("POST", "PUT", "PATCH") and form.is_valid():
        predator_apikey_changed = "predator_apikey" in form.changed_data
        name_changed = "name" in form.changed_data

        # If predator api key changed
        if predator_apikey_changed and tenant_model:
            # Check if there is another Tenants Config using the old api key
            # If there is another tenant using the old api key, don't delete databases
            other_tenants =  Tenants.objects.filter(predator_apikey=old_predator_apikey).exclude(pk=tenant_model.pk).count()
            if other_tenants == 0:
                encoded_predator_apikey = b64encode(old_predator_apikey.encode('utf8')).decode('utf8')
                reputation_ctxs = ReputationContext.mongo_find(
                    {"filename": {"$regex": ".*_{}\.[a-z]+$".format(encoded_predator_apikey)}})
                filenames = []
                for feed in reputation_ctxs:
                    filenames.append(feed.absolute_filename)
                    feed.delete(delete=False)
                Cluster.api_request("system.config.models.delete_conf", filenames)

        # Update the api key
        tenant = form.save(commit=False)
        tenant.save()

        # If the predator api key changed (mmdb databases paths contain this key)
        # And old databases has been deleted
        if predator_apikey_changed and tenant_model and other_tenants == 0:
            # Download and save new reputation contexts
            Cluster.api_request("gui.crontab.feed.security_update", tenant.pk)

        # If name or predator api key changed
        if name_changed or predator_apikey_changed:
            # Reload Rsyslog conf of each frontends using this tenant
            tenant.reload_frontends_conf()

        # If name has changed, and if it is used in Global config
        if name_changed and tenant.config_set.count() > 0:
            # Reload pstats configuration of Cluster
            Cluster.api_request("services.rsyslogd.rsyslog.configure_pstats")

        if api:
            return build_response(tenant.id, "system.tenants.api", COMMAND_LIST)
        return HttpResponseRedirect('/system/tenants/')

    return render_form()


def tenants_delete(request, object_id, api=False):
    """ Delete Backend and related Listeners """
    error = ""
    try:
        tenant = Tenants.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        if api:
            return JsonResponse({'error': _("Object does not exist.")}, status=404)
        return HttpResponseForbidden("Injection detected")

    if ((request.method == "POST" and request.POST.get('confirm', "").lower() == "yes")
            or (api and request.method == "DELETE" and request.JSON.get('confirm', "").lower() == "yes")):

        try:
            assert tenant.frontend_set.count() == 0, "This tenants config is used by listener(s)"

            # If there is another Tenant config sharing the predator apikey
            # Don't delete reputation contexts
            if Tenants.objects.filter(predator_apikey=tenant.predator_apikey).exclude(pk=tenant.pk).count() == 0:
                encoded_predator_apikey = b64encode(tenant.predator_apikey.encode('utf8')).decode('utf8')
                reputation_ctxs = ReputationContext.mongo_find(
                    {"filename": {"$regex": ".*_{}\.[a-z]+$".format(encoded_predator_apikey)}})
                for feed in reputation_ctxs:
                    feed.delete()

            """ If everything's ok, delete the object """
            tenant.delete()
            logger.info("Tenants config '{}' deleted.".format(tenant))

            if api:
                return JsonResponse({
                    'status': True
                }, status=204)
            return HttpResponseRedirect(reverse('system.tenants.list'))

        except Exception as e:
            # If API request failure, bring up the error
            logger.error("Error trying to delete Tenants config '{}': API|Database failure. "
                        "Details:".format(tenant.name))
            logger.exception(e)
            error = "API or Database request failure: {}".format(str(e))

            if api:
                return JsonResponse({'status': False,
                                    'error': error}, status=500)
    if api:
        return JsonResponse({'error': _("Please confirm with confirm=yes in JSON body.")}, status=400)

    encoded_predator_apikey = b64encode(tenant.predator_apikey.encode('utf8')).decode('utf8')
    reputation_ctxs = [a['name'] for a in ReputationContext.objects.mongo_find({"filename": {"$regex": ".*_{}\.[a-z]+$".format(encoded_predator_apikey)}})]
    # If GET request or POST request and API/Delete failure
    return render(request, 'generic_delete.html', {
        'menu_name': _("System -> Tenants config -> Delete"),
        'redirect_url': reverse("system.tenants.list"),
        'delete_url': reverse("system.tenants.delete", kwargs={'object_id': tenant.id}),
        'obj_inst': tenant,
        'error': error,
        'used_by': [*tenant.frontend_set.all(), *reputation_ctxs],
    })


COMMAND_LIST = {
}
