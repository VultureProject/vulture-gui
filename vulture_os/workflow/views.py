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
from django.utils.translation import ugettext_lazy as _
from django.shortcuts import render
from django.conf import settings
from django.urls import reverse

# Django project imports
from darwin.defender_policy.models import DefenderPolicy
from darwin.access_control.models import AccessControl
from system.cluster.models import Cluster
from workflow.models import Workflow, WorkflowACL
from authentication.base_repository import BaseRepository

# Required exceptions imports
from django.core.exceptions import ObjectDoesNotExist
from services.frontend.models import Frontend
from applications.backend.models import Backend

# Extern modules imports
from copy import deepcopy
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
            workflow.delete()

            nodes = frontend.reload_conf()
            backend.reload_conf()

            for node in nodes:
                api_res = node.api_request("services.haproxy.haproxy.restart_service")
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
        'workflow': workflow,
        'error': error
    })


def save_workflow(request, workflow_obj, object_id=None):
    """
        WARNING: Apply changes to the API as well !
    """
    workflow_acls = []
    before_policy = True
    order = 1

    old_defender_policy_id = None
    if workflow_obj.defender_policy:
        old_defender_policy_id = deepcopy(workflow_obj.defender_policy.pk)

    try:
        workflow = json.loads(request.POST['workflow'])
        workflow_name = request.POST['workflow_name']
        workflow_enabled = request.POST['workflow_enabled'] == "true"

        if (workflow_name == ""):
            raise InvalidWorkflowError(_("A name is required"))

        workflow_obj.enabled = workflow_enabled
        workflow_obj.name = workflow_name
        workflow_obj.workflow_json = workflow
        workflow_obj.save()

        old_workflow_acls = WorkflowACL.objects.filter(workflow=workflow_obj)
        old_workflow_acls.delete()

        for step in workflow:
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

                workflow_obj.save()

            elif step['data']['type'] == 'backend':
                backend = Backend.objects.get(pk=step['data']['object_id'])
                workflow_obj.backend = backend
                workflow_obj.save()

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
                workflow_acl.save()

            elif step['data']['type'] == "waf":
                if step['data']['object_id']:
                    defender_policy = DefenderPolicy.objects.get(pk=step['data']['object_id'])
                    workflow_obj.defender_policy = defender_policy
                else:
                    workflow_obj.defender_policy = None

                workflow_obj.save()

                before_policy = False
                order = 1

        if not workflow_obj.backend:
            raise InvalidWorkflowError(_("You need to select a backend"))

        # Reloading configuration
        nodes = workflow_obj.frontend.reload_conf()
        workflow_obj.backend.reload_conf()

        # We need to reload the new defender policy configuration if:
        # we set a defender policy and (if we create an object, or if we updated the policy, the FQDN or the
        # public directory)
        if workflow_obj.defender_policy:
            logger.info("Need to reload the Defender Policy SPOE configuration")
            Cluster.api_request(
                "darwin.defender_policy.policy.write_defender_backend_conf",
                workflow_obj.defender_policy.pk
            )
            Cluster.api_request(
                "darwin.defender_policy.policy.write_defender_spoe_conf",
                workflow_obj.defender_policy.pk
            )

        # We need to reload the old defender policy configuration if:
        # we set a defender policy previously, and the previous configuration is different from the new one
        if old_defender_policy_id and old_defender_policy_id != workflow_obj.defender_policy.pk:
            logger.info(
                "Old Defender policy {} SPOE configuration will be reloaded".format(old_defender_policy_id)
            )

            Cluster.api_request(
                "darwin.defender_policy.policy.write_defender_spoe_conf", old_defender_policy_id
            )

        # Reload HAProxy on concerned nodes
        for node in nodes:
            api_res = node.api_request("services.haproxy.haproxy.restart_service")
            if not api_res.get('status'):
                logger.error("Workflow::edit: API error while trying to "
                             "restart HAProxy service : {}".format(api_res.get('message')))
                raise InvalidWorkflowError(api_res.get('message'))

        return JsonResponse({'status': True})

    except InvalidWorkflowError as e:
        if not object_id:
            for workflow_acl in workflow_acls:
                workflow_acl.delete()

            try:
                workflow_obj.delete()
            except Exception:
                pass

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
            'error': _('An error has occured')
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

    if request.method == "GET":
        action = request.GET.get('action')
        if action == "dependencies":
            mode = request.GET.get('mode')

            if not mode:
                data = {
                    'frontends': [f.to_dict() for f in Frontend.objects.filter(enabled=True, mode__in=('http', 'tcp'))]
                }
            else:
                data = {
                    'acls': [a.to_template() for a in AccessControl.objects.filter(enabled=True)],
                    'backends': [b.to_dict() for b in Backend.objects.filter(enabled=True, mode=mode)],
                    'waf_policies': [w.to_template() for w in DefenderPolicy.objects.all()],
                    'authentications': [a.to_template() for a in BaseRepository.objects.all()],
                }

            return JsonResponse({
                'status': True,
                'data': data
            })

        elif action == "get_workflow":
            return JsonResponse({
                'status': True,
                'data': workflow_obj.to_dict(),
                'frontends': [f.to_dict() for f in Frontend.objects.filter(enabled=True)],
                'backends': [b.to_dict() for b in Backend.objects.filter(
                    enabled=True,
                    mode=workflow_obj.frontend.mode
                )],
            })

        return render(request, "main/workflow_edit.html", {
            'workflow': workflow_obj
        })

    elif request.method == "POST":
        return save_workflow(request, workflow_obj, object_id)


COMMAND_LIST = {
}
