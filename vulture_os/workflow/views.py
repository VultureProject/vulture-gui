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

__author__ = "Kevin GUILLEMOT, Olivier de Régis"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Listeners View'

# Django system imports
from django.http import JsonResponse, HttpResponseRedirect, HttpResponseNotFound
from django.utils.translation import gettext_lazy as _
from django.shortcuts import render
from django.conf import settings
from django.urls import reverse

# Django project imports
from darwin.access_control.models import AccessControl
from gui.forms.form_utils import DivErrorList
from system.cluster.models import Cluster
from workflow.models import Workflow, WorkflowACL
from workflow.form import WorkflowForm
from authentication.auth_access_control.models import AuthAccessControl
from authentication.user_portal.models import UserAuthentication

# Required exceptions imports
from django.core.exceptions import ObjectDoesNotExist
from services.frontend.models import Frontend
from applications.backend.models import Backend

# Extern modules imports
import validators
import json

# Logger configuration imports
import logging

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


class InvalidWorkflowError(Exception):
    pass


def workflow_delete(request, object_id, api=False):
    """ Delete Backend and related Listeners """
    error = ""
    try:
        workflow = Workflow.objects.get(id=object_id)
    except ObjectDoesNotExist:
        if api:
            return JsonResponse({'error': _("Object does not exist.")}, status=404)
        return HttpResponseNotFound()

    if((request.method == "POST" and request.POST.get('confirm', "").lower() == "yes") or (api and request.method == "DELETE" and request.JSON.get('confirm', "").lower() == "yes")):

        try:
            # FIXME : Retrieve Frontend conf

            # If POST request and no error: detete frontend
            frontend = workflow.frontend
            backend = workflow.backend
            filename = workflow.get_base_filename()
            workflow.delete()

            nodes = frontend.reload_conf()
            backend.reload_conf()

            Cluster.api_request('services.haproxy.haproxy.delete_conf', filename)

            for node in nodes:
                api_res = node.api_request("services.haproxy.haproxy.reload_service", run_delay=settings.SERVICE_RESTART_DELAY)
                if not api_res.get('status'):
                    logger.error("Workflow::edit: API error while trying to "
                                 "restart HAProxy service : {}".format(api_res.get('message')))
                    raise InvalidWorkflowError(api_res.get('message'))

            if api:
                return JsonResponse({
                    'status': True
                }, status=204)

            return HttpResponseRedirect(reverse('workflow.list'))

        except Exception as e:
            # If API request failure, bring up the error
            logger.error("Error trying to delete workflow with id '{}': API|Database failure. Details:".format(workflow.id))
            logger.exception(e)
            error = "API or Database request failure: {}".format(str(e))

            if api:
                return JsonResponse({
                    'status': False,
                    'error': error
                }, status=500)

    if api:
        return JsonResponse({'error': _("Please confirm with confirm=yes in JSON body.")}, status=400)

    # If GET request or POST request and API/Delete failure
    return render(request, 'generic_delete.html', {
        'redirect_url': reverse("workflow.list"),
        'delete_url': reverse("workflow.delete", kwargs={'object_id': object_id}),
        'obj_inst': workflow,
        'error': error
    })


def save_workflow(request, workflow_obj, object_id=None):
    """
        WARNING: Apply changes to the API as well !
    """
    workflow_acls = []
    before_policy = True
    order = 1
    previous_frontend = workflow_obj.frontend if hasattr(workflow_obj, "frontend") else None

    try:
        # TODO replace by proper form validation and saving!
        workflow_obj.workflow_json = json.loads(request.POST['workflow'])
        workflow_obj.name = request.POST['name']
        workflow_obj.enabled = request.POST['workflow_enabled'] == "true"
        workflow_obj.enable_cors_policy = request.POST.get('enable_cors_policy') == "true"
        workflow_obj.cors_allowed_methods = request.POST.getlist('cors_allowed_methods[]', ['*'])
        workflow_obj.cors_allowed_origins = request.POST.get('cors_allowed_origins', '*')
        workflow_obj.cors_allowed_headers = request.POST.get('cors_allowed_headers', '*')
        workflow_obj.cors_max_age = request.POST.get('cors_max_age', 600)

        if len(workflow_obj.cors_allowed_methods) > 1 and "*" in workflow_obj.cors_allowed_methods:
            workflow_obj.cors_allowed_methods.remove('*')

        # Get all current ACLs assigned to this Workflow (in_bulk allows to execute the queryset)
        old_workflow_acls = WorkflowACL.objects.filter(workflow=workflow_obj).in_bulk()

        workflow_obj.authentication = None
        workflow_obj.authentication_filter = None

        for step in workflow_obj.workflow_json:
            if step['data']['type'] == "frontend":
                frontend = Frontend.objects.get(pk=step['data']['object_id'])
                workflow_obj.frontend = frontend

                if frontend.mode == "http":
                    workflow_obj.fqdn = step['data']['fqdn']

                    if not validators.domain(workflow_obj.fqdn):
                        raise InvalidWorkflowError(_("This FQDN is not valid."))

                    workflow_obj.public_dir = step['data']['public_dir']
                    if workflow_obj.public_dir and len(workflow_obj.public_dir):
                        if workflow_obj.public_dir[0] != '/':
                            workflow_obj.public_dir = '/' + workflow_obj.public_dir
                        if workflow_obj.public_dir[-1] != '/':
                            workflow_obj.public_dir += '/'


            elif step['data']['type'] == 'backend':
                backend = Backend.objects.get(pk=step['data']['object_id'])
                workflow_obj.backend = backend

            elif step['data']['type'] == "acl":
                access_control = AccessControl.objects.get(pk=step['data']['object_id'])

                workflow_acl = WorkflowACL(
                    access_control=access_control,
                    action_satisfy=step['data']['action_satisfy'],
                    action_not_satisfy=step['data']['action_not_satisfy'],
                    redirect_url_satisfy=step['data']['redirect_url_satisfy'],
                    redirect_url_not_satisfy=step['data']['redirect_url_not_satisfy'],
                    before_policy=before_policy,
                    workflow=workflow_obj,
                    order=order
                )

                order += 1

                workflow_acls.append(workflow_acl)

            elif step['data']['type'] == "authentication":
                if step['data']['object_id']:
                    authentication = UserAuthentication.objects.get(pk=step['data']['object_id'])
                    workflow_obj.authentication = authentication
                else:
                    workflow_obj.authentication = None

            elif step['data']['type'] == "authentication_filter":
                if step['data']['object_id']:
                    authentication_filter = AuthAccessControl.objects.get(pk=step['data']['object_id'])
                    workflow_obj.authentication_filter = authentication_filter
                else:
                    workflow_obj.authentication_filter = None

        if (workflow_obj.name == ""):
            raise InvalidWorkflowError(_("A name is required"))
        if not workflow_obj.backend:
            raise InvalidWorkflowError(_("You need to select a backend"))
        if workflow_obj.authentication_filter and not workflow_obj.authentication:
            raise InvalidWorkflowError(_("If you set an 'authentication_filter', you need an 'authentication' object"))

        workflow_obj.save()
        for acl in old_workflow_acls.values():
            acl.delete()
        for workflow_acl in workflow_acls:
            workflow_acl.save()

        # Reloading configuration
        nodes = workflow_obj.frontend.get_nodes()
        for node in nodes:
            node.api_request("workflow.workflow.build_conf", workflow_obj.pk)

        # THEN reload backend and frontend configurations
        workflow_obj.backend.reload_conf()
        workflow_obj.frontend.reload_conf()

        # If Frontend changed, its configuration should also be updated
        if previous_frontend and workflow_obj.frontend != previous_frontend:
            previous_frontend.reload_conf()
            nodes.update(previous_frontend.get_nodes())

        for node in nodes:
            # Finally, Reload HAProxy on concerned nodes
            api_res = node.api_request("services.haproxy.haproxy.reload_service", run_delay=settings.SERVICE_RESTART_DELAY)
            if not api_res.get('status'):
                logger.error("Workflow::edit: API error while trying to "
                             "restart HAProxy service : {}".format(api_res.get('message')))
                raise InvalidWorkflowError(api_res.get('message'))

        return JsonResponse({'status': True})

    except InvalidWorkflowError as e:
        return JsonResponse({
            'status': False,
            'error': str(e)
        })

    except Exception as e:
        if settings.DEV_MODE:
            raise

        logger.critical(e, exc_info=1)
        return JsonResponse({
            'status': False,
            'error': _('An error has occurred')
        })


def workflow_edit(request, object_id=None, api=False):
    if object_id:
        try:
            workflow_obj = Workflow.objects.get(pk=object_id)
        except Workflow.DoesNotExist:
            if api:
                return JsonResponse({'error': _('Object does not exist')}, status=404)
            return HttpResponseNotFound()
    else:
        workflow_obj = Workflow()

    if hasattr(request, "JSON") and api:
        form = WorkflowForm(request.JSON or None, instance=workflow_obj, error_class=DivErrorList)
    else:
        form = WorkflowForm(request.POST or None, instance=workflow_obj, error_class=DivErrorList)

    if request.method == "GET":
        return render(request, "main/workflow_edit.html", {
            'object_id': object_id,
            'form': form
        })
    else:
        if request.method == "POST" and form.is_valid():
            return save_workflow(request, workflow_obj, object_id)
    return JsonResponse({"errors": form.errors.get_json_data()}, status=400)


COMMAND_LIST = {
}
