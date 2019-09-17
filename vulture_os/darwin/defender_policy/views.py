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
__doc__ = 'Darwin Policy views'


# Logger configuration imports
import logging

from darwin.log_viewer.models import DefenderRuleset
from darwin.defender_policy.form import DefenderPolicyForm, DefenderRulesetForm
from darwin.defender_policy.models import DefenderPolicy
from django.conf import settings
# Required exceptions imports
from django.core.exceptions import ObjectDoesNotExist
# Django system imports
from django.http import HttpResponseForbidden, HttpResponseRedirect, JsonResponse
from django.shortcuts import render
# Django project imports
from gui.forms.form_utils import DivErrorList
from system.cluster.models import Cluster

# Extern modules imports
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


def defender_policy_clone(request, object_id):
    """ DefenderPolicy view used to clone an object

    :param request: Django request object
    :param object_id: MongoDB object_id of an LDAPRepository object
    """
    """ If POST request, same as edit with no ID """
    if request.POST:
        return defender_policy_edit(request)

    try:
        policy = DefenderPolicy.objects.get(pk=object_id)
    except Exception as e:
        logger.exception(e)
        return HttpResponseForbidden("Injection detected")

    policy.pk = None
    policy.name = "Copy_of_" + str(policy.name)

    form = DefenderPolicyForm(None, instance=policy, error_class=DivErrorList)

    return render(request, 'defender_policy_edit.html', {'form': form})


def defender_policy_edit(request, object_id=None):
    policy = None

    if object_id:
        try:
            policy = DefenderPolicy.objects.get(pk=object_id)
        except ObjectDoesNotExist:
            return HttpResponseForbidden("Injection detected")

    form = DefenderPolicyForm(request.POST or None, instance=policy, error_class=DivErrorList)

    if request.method == "POST" and form.is_valid():
        # Save the form to get an id if there is not already one
        policy = form.save(commit=False)

    """ If no error in filter forms """
    if request.method == "POST" and not form.errors:
        # Save the policy before filters
        policy.save()

        # If it's a new object
        if not object_id:
            # Write backend defender config
            Cluster.api_request("darwin.defender_policy.policy.write_defender_backend_conf", policy.id)

        Cluster.api_request("darwin.defender_policy.policy.write_defender_conf", policy.id)

        # If everything succeed, redirect to list view
        return HttpResponseRedirect('/darwin/defender_policy/')

    return render(request, 'defender_policy_edit.html', {'form': form})


def get_defender_raw_rule_set(request):
    try:
        if request.method != 'GET':
            return JsonResponse({'status': False, 'error': 'Method not allowed'}, status=405)

        defender_ruleset_choices = []
        size = 10
        offset = int(request.GET.get('page', 0)) * size
        search_query = request.GET.get('search', None)

        if search_query is None:
            defender_ruleset_list = DefenderRuleset.objects.all()
        else:
            defender_ruleset_list = DefenderRuleset.objects.filter(name__contains=search_query)

        is_more_list = defender_ruleset_list[offset + size + 1:offset + size + 2]
        is_more = len(is_more_list) > 0
        defender_ruleset_list = defender_ruleset_list[offset:offset + size]

        for defender_ruleset in defender_ruleset_list:
            defender_ruleset_choices.append({
                'id': defender_ruleset.pk,
                'text': defender_ruleset.name
            })

        to_return = {
            'results': defender_ruleset_choices,
            'pagination': {
                'more': is_more
            },
            'status': True
        }

        return JsonResponse(to_return, status=200)

    except Exception as error:
        logger.exception(error)

        return JsonResponse({'status': False, 'error': str(error)}, status=500)


def save_defender_raw_rule_set(request, object_id):
    try:
        if object_id is None:
            return JsonResponse({'status': False, 'error': 'Missing Mod Defender ruleset ID'})

        try:
            defender_ruleset = DefenderRuleset.objects.get(pk=object_id)
        except DefenderRuleset.DoesNotExist:
            error_message = 'Mod Defender with ID "{}" not found'.format(object_id)
            logger.error(error_message)

            return JsonResponse({'status': False, 'error': error_message}, status=404)

        # if the user wants to get the list or raw rules (via the GET HTTP method)
        if request.method == 'GET':
            return JsonResponse({'status': True, 'raw_rules': defender_ruleset.raw_rules}, status=200)

        # if not, he wants to save the raw rules he sent
        try:
            raw_rules = request.POST['raw_rules']
        except KeyError:
            return JsonResponse({'status': False, 'error': 'Missing raw rules'})

        defender_ruleset.raw_rules = raw_rules
        defender_ruleset.save()

        policy_list = DefenderPolicy.objects.filter(defender_ruleset=defender_ruleset)

        for policy in policy_list:
            Cluster.api_request('darwin.defender_policy.policy.write_defender_conf', policy.pk)

        return JsonResponse({'status': True, 'message': 'Mod Defender ruleset correctly updated'})
    except Exception as error:
        logger.exception(error)

        return JsonResponse({'status': False, 'error': str(error)})


def defender_ruleset_clone(request, object_id):
    """ DefenderRuleset view used to clone an object

    :param request: Django request object
    :param object_id: MongoDB object_id of an LDAPRepository object
    """
    """ If POST request, same as edit with no ID """
    if request.POST:
        return defender_ruleset_edit(request)

    try:
        ruleset = DefenderRuleset.objects.get(pk=object_id)
    except Exception as e:
        logger.exception(e)
        return HttpResponseForbidden("Injection detected")

    ruleset.pk = None
    ruleset.name = "Copy_of_" + str(ruleset.name)

    form = DefenderRulesetForm(None, instance=ruleset, error_class=DivErrorList)

    return render(request, 'defender_ruleset_edit.html', {'form': form})


def defender_ruleset_edit(request, object_id=None):
    ruleset = None

    if object_id:
        try:
            ruleset = DefenderRuleset.objects.get(pk=object_id)
        except ObjectDoesNotExist:
            return HttpResponseForbidden("Injection detected")

    form = DefenderRulesetForm(request.POST or None, instance=ruleset, error_class=DivErrorList)

    if request.method == "POST" and form.is_valid():
        # Save the form to get an id if there is not already one
        form.save(commit=False)

    """ If no error in filter forms """
    if request.method == "POST" and not form.errors:
        # Save the policy before filters
        form.save()

        if object_id:
            policy_list = DefenderPolicy.objects.filter(defender_ruleset=ruleset)

            for policy in policy_list:
                Cluster.api_request("darwin.defender_policy.policy.write_defender_conf", policy.id)

        # If everything succeed, redirect to list view
        return HttpResponseRedirect('/darwin/defender_ruleset/')

    return render(request, 'defender_ruleset_edit.html', {'form': form})
