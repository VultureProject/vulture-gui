#!/home/vlt-os/env/bin/python
"""This file is part of Vulture 3.

Vulture 3 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Vulture 3 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Vulture 3.  If not, see http://www.gnu.org/licenses/.
"""

__author__ = "Théo BERTIN"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'MMcapture view'

from django.conf import settings
from django.http import JsonResponse, HttpResponseForbidden, HttpResponseRedirect
from django.utils.translation import ugettext as _
from django.shortcuts import render

# Django project imports
from darwin.inspection.form import InspectionPolicyForm, InspectionRuleForm
from darwin.inspection.models import InspectionPolicy, InspectionRule, PACKET_INSPECTION_TECHNO
from system.cluster.models import Cluster

# Extern modules imports
from json import loads as json_loads

# Required exceptions imports
from django.core.exceptions import ObjectDoesNotExist

import logging

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


def inspection_rules(request):
    try:
        return render(request, 'inspection_rules.html')
    except Exception as e:
        if settings.DEV_MODE:
            raise

        logger.error(e, exc_info=1)
        return JsonResponse({
            'status': False,
            'error': _('An error has occurred')
        })


def fetch_rules(request):
    node = Cluster.get_current_node()
    if node:
        res = node.api_request("toolkit.yara.yara.fetch_yara_rules")
        if res.get('status'):
            return JsonResponse({
                'status': res.get('status'),
                'message': "successfully started update task"
            })
        else:
            logger.error(res.get('message'))
            return JsonResponse({
                'status': False,
            })
    else:
        return JsonResponse({
            'status': False,
            'error': _('An error occurred')
        })

def edit_inspection_policy(request, object_id=None):
    if object_id:
        try:
            inspection_policy = InspectionPolicy.objects.get(pk=object_id)
        except ObjectDoesNotExist as e:
            logger.exception(e)
            return HttpResponseForbidden("Injection detected")
    else:
        inspection_policy = None

    try:
        if object_id:
            form = InspectionPolicyForm(request.POST or None, instance=inspection_policy)
        else:
            form = InspectionPolicyForm(request.POST or None)
    except Exception as e:
        logger.exception(e)
        raise

    if request.method == "GET":
        return render(request, 'inspection_policy_edit.html', { 'form': form })

    try:
        if not form.is_valid():
            return render(request, 'inspection_policy_edit.html', {'form': form})

        policy = form.save(commit=False)
        rules = json_loads(request.POST.get("rules", "[]"))
        policy.rules = rules
        policy.compilable = "UNKNOWN"
        policy.save()
        policy.try_compile()
        # If everything succeed, redirect to list view
        return HttpResponseRedirect('/darwin/inspection/')

    except Exception as e:
        logger.exception(e)
        raise


def edit_inspection_rule(request, object_id=None):
    if object_id:
        try:
            inspection_rule = InspectionRule.objects.get(pk=object_id)
        except ObjectDoesNotExist as e:
            logger.exception(e)
            return HttpResponseForbidden("Injection detected")
    else:
        inspection_rule = None

    try:
        if object_id:
            form = InspectionRuleForm(request.POST or None, instance=inspection_rule)
        else:
            form = InspectionRuleForm(request.POST or None)
    except Exception as e:
        logger.exception(e)
        raise

    if request.method == "GET":
        return render(request, 'inspection_rule_edit.html', {'form': form})

    try:
        if not form.is_valid():
            return render(request, 'inspection_rule_edit.html', {'form': form})

        rule = form.save(commit=False)
        rule.save()
        # If everything succeed, redirect to list view
        return HttpResponseRedirect('/darwin/inspection/')

    except Exception as e:
        logger.exception(e)
        raise


def clone_inspection_policy(request):
    pk = request.POST.get('pk')
    logger.info("pk is {}".format(pk))

    if not pk:
        return JsonResponse({
            'status': False,
            'error': _("'pk' required to clone object")
        })

    try:
        inspection_policy = InspectionPolicy.objects.get(pk=pk)
    except ObjectDoesNotExist:
        return JsonResponse({
            'status': False,
            'error': _("Policy does not exist")
        })

    try:
        inspection_policy.pk = None
        inspection_policy.name = str(inspection_policy.name) + '_copy'
        inspection_policy.save()
    except Exception as e:
        return JsonResponse({
            'status': False,
            'error': _("An error occurred")
        })

    return JsonResponse({
        'status': True
    })


def clone_inspection_rule(request):
    pk = request.POST.get('pk')
    logger.info("pk is {}".format(pk))

    if not pk:
        return JsonResponse({
            'status': False,
            'error': _("'pk' required to clone object")
        })

    try:
        inspection_rule = InspectionRule.objects.get(pk=pk)
    except ObjectDoesNotExist:
        return JsonResponse({
            'status': False,
            'error': _("Rule does not exist")
        })

    try:
        inspection_rule.pk = None
        inspection_rule.name = str(inspection_rule.name) + '_copy'
        inspection_rule.source = "custom"
        inspection_rule.save()
    except Exception as e:
        return JsonResponse({
            'status': False,
            'error': _("An error occurred")
        })

    return JsonResponse({
        'status': True
    })