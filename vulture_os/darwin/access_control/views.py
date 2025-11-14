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
__doc__ = 'Access Control views'


from django.http import JsonResponse
from django.http.response import HttpResponseNotFound
from django.utils.crypto import get_random_string
from toolkit.mongodb.postgres_base import PostgresBase
from django.utils.translation import gettext as _
from django.shortcuts import render
from django.conf import settings

from darwin.access_control.form import AccessControlForm, AccessControlRuleForm
from darwin.access_control.models import AccessControl
from services.exceptions import ServiceTestConfigError
from applications.backend.models import Backend
from system.cluster.models import Cluster
from workflow.models import Workflow
import logging
import json


logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


def access_control_get(request):
    try:
        log_id = request.POST.get('log_id')

        if log_id:
            client = PostgresBase()
            log_line = client.execute_request("logs", "haproxy", {'_id': log_id}, first=True)
            log_line['_id'] = str(log_line['_id'])

            return JsonResponse({
                'status': True,
                'log_line': log_line
            })

        pk = request.POST.get('pk')
        if pk:
            try:
                acl = AccessControl.objects.get(pk=pk).to_template()
            except AccessControl.DoesNotExist:
                return JsonResponse({
                    'status': False,
                    'error': _('ACL does not exist')
                })
        else:
            acl = [a.to_template() for a in AccessControl.objects.all()]

        return JsonResponse({
            'status': True,
            'acl': acl
        })

    except Exception as e:
        logger.critical(e, exc_info=1)
        if settings.DEV_MODE:
            raise

        return JsonResponse({
            'status': False,
            'error': _('An error occurred')
        })


def access_control_edit(request, object_id=None, api=None):
    try:
        access_control = None
        if object_id:
            try:
                access_control = AccessControl.objects.get(pk=object_id)
            except AccessControl.DoesNotExist:
                if api:
                    return JsonResponse({'error': _("Object does not exist.")}, status=404)
                else:
                    return HttpResponseNotFound(_("Object not found"))

        if hasattr(request, "JSON") and api:
            form = AccessControlForm(request.JSON or None, instance=access_control)
        else:
            form = AccessControlForm(request.POST or None, instance=access_control)

        if request.method == "GET":
            log_id = request.GET.get('log_id')
            return render(request, 'access_control_edit.html', {
                'access_control': access_control,
                'log_id': log_id,
                'form': form
            })

        try:
            if form.is_valid():
                ac = form.save(commit=False)

                if api:
                    data = request.JSON
                    rules = data.get("or_lines", [])
                else:
                    data = request.POST
                    rules = json.loads(data.get("or_lines", ""))

                for rule in rules:
                    for line in rule['lines']:
                        rule_form = AccessControlRuleForm(line or None)
                        if not rule_form.is_valid():
                            return JsonResponse({
                                'status': False,
                                'error': rule_form.errors
                            }, status=400)

                ac.rules = rules
                ac.acls = ac.generate_test_conf()

                try:
                    ac.test_conf()
                except ServiceTestConfigError as e:
                    return JsonResponse({
                        'status': False,
                        'error': str(e)
                    }, status=400)

                ac.save()

                nodes = set()
                reload_all = False
                for workflow in Workflow.objects.filter(workflowacl__access_control=ac, workflowacl__before_policy=True).distinct():
                    for node in workflow.frontend.get_nodes():
                        node.api_request("workflow.workflow.build_conf", workflow.pk)
                        nodes.add(node)

                for backend in Backend.objects.filter(
                    workflow__workflowacl__access_control=ac,
                    # This is still necessary, because Workflow ACLs can still be assigned to backends, but only via API...
                    workflow__workflowacl__before_policy=False).distinct():
                    backend.configuration = backend.generate_conf()
                    backend.save_conf()
                    # In case some backends own ACLs, every haproxy will have to be reloaded
                    reload_all = True

                if reload_all:
                    api_res = Cluster.api_request("services.haproxy.haproxy.reload_service", run_delay=settings.SERVICE_RESTART_DELAY)
                    if not api_res.get('status'):
                        logger.error("Access_Control::edit: API error while trying to "
                                "restart HAProxy service : {}".format(api_res.get('message')))
                else:
                    for node in nodes:
                        api_res = node.api_request("services.haproxy.haproxy.reload_service", run_delay=settings.SERVICE_RESTART_DELAY)
                        if not api_res.get('status'):
                            logger.error("Access_Control::edit: API error while trying to "
                                        "restart HAProxy service : {}".format(api_res.get('message')))

                return JsonResponse({
                    'status': True,
                    'message': _('ACL saved')
                })

            if api:
                logger.error("AccessControl api form error : {}".format(form.errors.get_json_data()))
                return JsonResponse(form.errors.get_json_data(), status=400)

        except ValueError as e:
            logger.critical(e, exc_info=1)
            if settings.DEV_MODE:
                raise

            return JsonResponse({
                'status': False,
                'error': _('JSON failed to load')
            })

        return JsonResponse({
            'status': False,
            'errors': form.errors
        })

    except Exception as e:
        if settings.DEV_MODE:
            raise

        logger.error(e, exc_info=1)
        return JsonResponse({
            'status': False,
            'error': _('An error has occurred')
        })


def access_control_clone(request):
    try:
        pk = request.POST.get('pk')

        access_control = AccessControl.objects.get(pk=pk)
        access_control.pk = None
        access_control.name = "Clone of {} {}".format(access_control.name, get_random_string(length=4))
        access_control.save()

        return JsonResponse({
            'status': True
        })

    except AccessControl.DoesNotExist:
        return JsonResponse({
            'status': False,
            'error': _('ACL does not exist')
        })

    except Exception as e:
        logger.critical(e, exc_info=1)
        if settings.DEV_MODE:
            raise

        return JsonResponse({
            'status': False,
            'error': _('An error occurred')
        })
