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
__author__ = "Kevin GUILLEMOT Olivier de Régis"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Workflow API'


# Django system imports
from bson.objectid import ObjectId
from django.conf import settings
from django.http import JsonResponse
from django.utils.decorators import method_decorator
from django.utils.translation import ugettext_lazy as _
from darwin.access_control.models import AccessControl
from bson.errors import InvalidId
from django.views import View

# Django project imports
from django.views.decorators.csrf import csrf_exempt
from darwin.defender_policy.models import DefenderPolicy
from authentication.user_portal.models import UserAuthentication
from system.cluster.models import Cluster
from services.frontend.models import Frontend
from applications.backend.models import Backend
from gui.decorators.apicall import api_need_key
from workflow.models import Workflow, WorkflowACL
from workflow.views import COMMAND_LIST, workflow_delete

# Logger configuration imports
import validators
import logging
import uuid
import json
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api')


class InvalidWorkflowError(Exception):
    pass


def write_portal_template(node_logger, workflow_id):
    """ Method can raise - catched by Vultured (caller) """
    workflow = Workflow.objects.get(pk=workflow_id)
    workflow.write_portal_template()



def format_acl_from_api(tmp_acl, order, before_policy):
    try:
        acl = AccessControl.objects.get(pk=ObjectId(tmp_acl['id']))
        action_satisfy = int(tmp_acl['action_satisfy'])
        action_not_satisfy = int(tmp_acl['action_not_satisfy'])
        redirect_url_satisfy = tmp_acl.get('redirect_url_satisfy')
        redirect_url_not_satisfy = tmp_acl.get('redirect_url_not_satisfy')

        if action_satisfy not in (200, 403, 301, 302):
            return False, JsonResponse({
                'error': _('Actions must be one of 200, 301, 302 or 403')
            }, status=400)

        if action_not_satisfy not in (200, 403, 301, 302):
            return False, JsonResponse({
                'error': _('Actions must be one of 200, 301, 302 or 403')
            }, status=400)

        if action_satisfy != 200 and action_not_satisfy != 200:
            return False, JsonResponse({
                'error': _('One of the actions must be 200')
            }, status=400)

        if action_satisfy in (301, 302) and not redirect_url_satisfy:
            return False, JsonResponse({
                'error': _('You must define a redirect url if the action satisfy')
            }, status=400)

        if action_not_satisfy in (301, 302) and not redirect_url_not_satisfy:
            return False, JsonResponse({
                'error': _('You must define a redirect url if the action does not satisfy')
            }, status=400)

        workflow_acl = WorkflowACL(
            access_control=acl,
            action_satisfy=action_satisfy,
            action_not_satisfy=action_not_satisfy,
            redirect_url_satisfy=redirect_url_satisfy,
            redirect_url_not_satisfy=redirect_url_not_satisfy,
            before_policy=before_policy,
            order=order + 1
        )

        return True, workflow_acl

    except (AccessControl.DoesNotExist, InvalidId) as e:
        logger.critical(e, exc_info=1)
        return False, JsonResponse({
            'error': _('ACL with id {} does not exist'.format(tmp_acl['id']))
        }, status=404)

    except KeyError as err:
        error = _("ACL is not valid")
        if settings.DEV_MODE:
            error = str(err)

        return False, JsonResponse({
            'error': error
        }, status=400)


def format_acl(acl, parent):
    workflow_acl_id = str(uuid.uuid4())

    tmp_acl = {
        "id": workflow_acl_id,
        "parent": parent,
        "label": acl.access_control.name,
        "data": {
            "object_id": str(acl.access_control.pk),
            "name": acl.access_control.name,
            "type": "acl",
            "action_satisfy": acl.action_satisfy,
            "action_not_satisfy": acl.action_not_satisfy,
            "redirect_url_satisfy": acl.redirect_url_satisfy,
            "redirect_url_not_satisfy": acl.redirect_url_not_satisfy
        }
    }

    action_satisfy_id = "{}_satisfy_{}".format(workflow_acl_id, str(uuid.uuid4()))
    action_not_satisfy_id = "{}_not_{}".format(workflow_acl_id, str(uuid.uuid4()))

    if acl.action_satisfy == "200":
        parent = action_satisfy_id
    elif acl.action_not_satisfy == "200":
        parent = action_not_satisfy_id

    actions = [{
        "id": action_satisfy_id,
        "parent": workflow_acl_id,
        "data": {
            "type": "action",
            "satisfy": True,
            "action": acl.action_satisfy,
            "redirect_url": acl.redirect_url_satisfy if acl.redirect_url_satisfy else ""
        }
    }, {
        "id": action_not_satisfy_id,
        "parent": workflow_acl_id,
        "data": {
            "type": "action",
            "satisfy": False,
            "action": acl.action_not_satisfy,
            "redirect_url": acl.redirect_url_not_satisfy if acl.redirect_url_not_satisfy else ""
        }
    }]

    return parent, tmp_acl, actions


def generate_workflow(workflow):
    mode = workflow.frontend.mode

    workflow_frontend_id = str(uuid.uuid4())

    data = [{
        "id": "#",
        "label": workflow.fqdn + workflow.public_dir if mode == "http" else "start",
        "data": {
            "type": "start"
        }
    }, {
        "id": workflow_frontend_id,
        "parent": "#",
        "data": {
            "object_id": str(workflow.frontend.pk),
            "listeners": workflow.frontend.to_dict()['listeners'],
            'type': 'frontend',
            'mode': mode,
            'fqdn': workflow.fqdn,
            'public_dir': workflow.public_dir
        }
    }]

    parent = workflow_frontend_id
    for acl in workflow.workflowacl_set.filter(before_policy=True):
        parent, tmp, actions = format_acl(acl, parent)
        data.append(tmp)
        for a in actions:
            data.append(a)

    workflow_policy_id = str(uuid.uuid4())
    data.append({
        'id': workflow_policy_id,
        'parent': parent,
        'data': {
            'type': 'waf',
            'object_id': workflow.defender_policy.pk if workflow.defender_policy else None,
            'name': workflow.defender_policy.name if workflow.defender_policy else "No policy"
        }
    })

    parent = workflow_policy_id

    user_authentication_id = str(uuid.uuid4())
    data.append({
        'id': user_authentication_id,
        'parent': parent,
        'data': {
            'type': 'authentication',
            'object_id': workflow.authentication.pk if workflow.authentication else None,
            'name': workflow.authentication.name if workflow.authentication else "No authentication"
        }
    })

    parent = user_authentication_id

    for acl in workflow.workflowacl_set.filter(before_policy=False):
        parent, tmp, actions = format_acl(acl, parent)
        data.append(tmp)
        for a in actions:
            data.append(a)

    data.append({
        "id": str(uuid.uuid4()),
        "parent": parent,
        "label": workflow.backend.name,
        "data": {
            "object_id": str(workflow.backend.pk),
            "name": workflow.backend.name,
            "type": "backend",
            "servers": workflow.backend.to_dict()['servers']
        }
    })

    return data


def workflow_edit(request, object_id, action=None):
    try:
        defender_policy = False
        authentication = False
        fqdn = ""
        public_dir = "/"

        if hasattr(request, "JSON"):
            enabled = request.JSON.get('enabled') is not False
            form_data = request.JSON
        else:
            enabled = request.POST.get('enabled') is not False
            form_data = request.POST

        try:
            frontend = Frontend.objects.get(pk=form_data['frontend'])

            if frontend.mode == "http":
                try:
                    fqdn = form_data['fqdn']
                    if not validators.domain(fqdn):
                        return JsonResponse({
                            'error': _('This FQDN is not valid')
                        }, status=400)

                    public_dir = form_data['public_dir']
                    if public_dir and len(public_dir):
                        if public_dir[0] != '/':
                            public_dir = '/' + public_dir
                        if public_dir[-1] != '/':
                            public_dir += '/'

                except KeyError:
                    return JsonResponse({
                        'error': _('For a HTTP Frontend, you must define a FQDN & a public_dir')
                    }, status=400)
        except Frontend.DoesNotExist:
            return JsonResponse({
                'error': _('frontend with id {} does not exist'.format(form_data['frontend']))
            }, status=404)
        except KeyError:
            return JsonResponse({
                'error': _('You must define a frontend for a workflow')
            }, status=400)

        try:
            backend = Backend.objects.get(pk=form_data['backend'])

            if frontend.mode != backend.mode:
                return JsonResponse({
                    'error': _('Frontend and Backend must be in the same mode.')
                }, status=400)
        except Backend.DoesNotExist:
            return JsonResponse({
                'error': _('Backend with id {} does not exist'.format(form_data['backend']))
            }, status=400)
        except KeyError:
            return JsonResponse({
                'error': _('You must define a backend for a workflow')
            }, status=400)

        if form_data.get('defender_policy'):
            try:
                defender_policy = DefenderPolicy.objects.get(pk=form_data['defender_policy'])
            except DefenderPolicy.DoesNotExist:
                return JsonResponse({
                    'error': _('Defender Policy with id {} does not exist'.format(form_data['defender_policy']))
                }, status=400)

        if form_data.get('authentication'):
            try:
                authentication = UserAuthentication.objects.get(pk=form_data['authentication'])
            except UserAuthentication.DoesNotExist:
                return JsonResponse({
                    "error": _("User Authentication does not exist")
                }, status=400)

        try:
            if object_id:
                workflow = Workflow.objects.get(pk=object_id)
            else:
                workflow = Workflow()

            workflow.enabled = enabled
            try:
                workflow.name = form_data['name']
            except KeyError:
                return JsonResponse({
                    'error': _("Please provide a name for this workflow")
                }, status=400)

            workflow.fqdn = fqdn
            workflow.public_dir = public_dir
            workflow.frontend = frontend
            workflow.backend = backend

            workflow_acls = []

            if defender_policy:
                workflow.defender_policy = defender_policy

            if authentication:
                workflow.authentication = authentication

            workflow.workflowacl_set.all().delete()

            acl_frontend = form_data.get("acl_frontend", [])
            if isinstance(form_data.get('acl_frontend'), str):
                acl_frontend = json.loads(acl_frontend)
            
            acl_backend = form_data.get("acl_backend", [])
            if isinstance(form_data.get('acl_backend'), str):
                acl_backend = json.loads(acl_backend)

            acl_list = []
            for i, tmp_acl in enumerate(acl_frontend):
                status, acl = format_acl_from_api(tmp_acl, i, before_policy=True)
                if not status:
                    return acl

                acl.workflow = workflow
                workflow_acls.append(acl)
                acl_list.append(acl)

            for i, tmp_acl in enumerate(acl_backend):
                status, acl = format_acl_from_api(tmp_acl, i, before_policy=False)
                if not status:
                    return acl

                acl.workflow = workflow
                workflow_acls.append(acl)
                acl_list.append(acl)

            workflow.save()
            for acl in acl_list:
                acl.save()

            workflow.workflow_json = generate_workflow(workflow)
            workflow.save()

            nodes = workflow.frontend.reload_conf()
            workflow.backend.reload_conf()
            workflow.save_conf()

            if workflow.defender_policy:
                logger.info("Need to reload the Defender Policy SPOE configuration")
                Cluster.api_request(
                    "darwin.defender_policy.policy.write_defender_backend_conf",
                    workflow.defender_policy.pk
                )
                Cluster.api_request(
                    "darwin.defender_policy.policy.write_defender_spoe_conf",
                    workflow.defender_policy.pk
                )

            # Reload HAProxy on concerned nodes
            for node in nodes:
                api_res = node.api_request("services.haproxy.haproxy.restart_service")
                if not api_res.get('status'):
                    logger.error("Workflow::edit: API error while trying to "
                                    "restart HAProxy service : {}".format(api_res.get('message')))
                    for workflow_acl in workflow.workflowacl_set.all():
                        workflow_acl.delete()

                    try:
                        workflow.delete()
                    except Exception:
                        pass

                    return JsonResponse({
                        'error': api_res.get('message')
                    }, status=500)

            return JsonResponse({
                'message': _('Workflow saved')
            }, status=201)

        except KeyError as err:
            return JsonResponse({
                'error': _('Partial data')
            }, status=400)

    except Exception as e:
        logger.critical(e, exc_info=1)
        if settings.DEV_MODE:
            error = str(e)
        else:
            error = _("An error has occurred")

    return JsonResponse({
        'error': error
    }, status=500)

@method_decorator(csrf_exempt, name='dispatch')
class WorkflowAPIv1(View):
    @api_need_key('cluster_api_key')
    def get(self, request, object_id=None):
        try:
            name = request.GET.get('name')

            if object_id:
                res = Workflow.objects.get(pk=object_id).to_dict()

            elif name:
                res = Workflow.objects.get(name=name).to_dict()

            else:
                res = [s.to_dict() for s in Workflow.objects.all()]

            return JsonResponse({
                'data': res
            })

        except Workflow.DoesNotExist:
            return JsonResponse({
                'error': _('Object does not exist')
            }, status=404)

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'error': error
            }, status=500)

    @api_need_key('cluster_api_key')
    def post(self, request, object_id=None):
        return workflow_edit(request, object_id)

    @api_need_key("cluster_api_key")
    def put(self, request, object_id):
        return workflow_edit(request, object_id)

    @api_need_key('cluster_api_key')
    def delete(self, request, object_id):
        try:
            return workflow_delete(request, object_id, api=True)

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'error': error
            }, status=500)
