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

from darwin.policy.form import (DarwinPolicyForm, FilterPolicyForm, FilterPolicyReputationForm,
                                FilterPolicyHostlookupForm, FilterPolicyDGAForm, FilterPolicyUserAgentForm,
                                FilterPolicyContentInspectionForm, FilterPolicyTAnomalyForm, FilterPolicyConnectionForm)
from darwin.policy.models import DarwinPolicy, DarwinFilter, FilterPolicy
from django.conf import settings
# Required exceptions imports
# Django system imports
from django.http import HttpResponseForbidden, HttpResponseRedirect, JsonResponse
from django.shortcuts import render
# Django project imports
from gui.forms.form_utils import DivErrorList
from services.darwin.darwin import DARWIN_PATH
from system.cluster.models import Cluster, Node

# Extern modules imports
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


FILTER_POLICY_FORMS = {
    "reputation": FilterPolicyReputationForm,
    "dga": FilterPolicyDGAForm,
    "user_agent": FilterPolicyUserAgentForm,
    "content_inspection": FilterPolicyContentInspectionForm,
    "tanomaly": FilterPolicyTAnomalyForm,
    "anomaly": FilterPolicyForm,
    "connection": FilterPolicyConnectionForm,
    "hostlookup": FilterPolicyHostlookupForm,
}


def policy_clone(request, object_id):
    """ DarwinPolicy view used to clone an object

    :param request: Django request object
    :param object_id: MongoDB object_id of an LDAPRepository object
    """
    """ If POST request, same as edit with no ID """
    if request.POST:
        return policy_edit(request)

    try:
        policy = DarwinPolicy.objects.get(pk=object_id)
    except Exception as e:
        logger.exception(e)
        return HttpResponseForbidden("Injection detected")

    policy.pk = None
    policy.name = "Copy_of_" + str(policy.name)

    form = DarwinPolicyForm(None, instance=policy, error_class=DivErrorList)

    return render(request, 'policy_edit.html', {'form': form})


def policy_edit(request, object_id=None):
    policy = None
    filter_policy_form_list = []

    if object_id:
        try:
            policy = DarwinPolicy.objects.get(pk=object_id)
        except DarwinPolicy.DoesNotExist:
            return HttpResponseForbidden("Injection detected")
    else:
        policy = DarwinPolicy()

    form = DarwinPolicyForm(request.POST or None, instance=policy, error_class=DivErrorList)

    if request.method == "POST" and form.is_valid():
        # Save the form to get an id if there is not already one
        policy = form.save()

    """ For each darwin filter """
    for darwin_filter in DarwinFilter.objects.exclude(name__in=['logs', 'session']).order_by('name'):
        """ Retrieve the FilterPolicy or create-it """
        try:
            if policy.id:
                instance_f, created = FilterPolicy.objects.get_or_create(policy=policy, filter=darwin_filter)
            else:
                instance_f = FilterPolicy(policy=policy, filter=darwin_filter)
        except Exception as e:
            logger.info(e)

        filter_policy_form_class = FILTER_POLICY_FORMS.get(darwin_filter.name, FilterPolicyForm)
        kwargs = {'instance': instance_f, 'error_class': DivErrorList}

        if request.method == "POST":
            """ Retrieve POST args of that filter """
            args = {}
            for key, val in request.POST.items():
                if key.startswith(darwin_filter.name + '_'):
                    args[key[len(darwin_filter.name) + 1:]] = val
            """ Instantiate & validate the args from the object """
            filter_policy_form = filter_policy_form_class(
                args,
                initial=instance_f.config,
                **kwargs
            )

            if not filter_policy_form.is_valid():
                form.add_error(None, "Error in filter named '{}'".format(darwin_filter.name))
        else:
            initial_dict = kwargs.get("initial", {})

            for key, value in instance_f.config.items():
                try:
                    initial_dict[key] = value
                except KeyError:
                    pass

            kwargs["initial"] = initial_dict
            filter_policy_form = filter_policy_form_class(**kwargs)

        # Save forms in case we re-print the page
        filter_policy_form_list.append(filter_policy_form)

    """ If no error in filter forms """
    if request.method == "POST" and not form.errors:
        # Save the policy before filters
        policy.save()

        try:
            need_reload = False

            """ Save the objects """
            for filter_policy_form in filter_policy_form_list:
                filter_policy = filter_policy_form.save(commit=False)

                """ Save the object """
                filter_policy.policy = policy

                for node in Node.objects.all().only('name'):
                    filter_policy.status[node.name] = "WAITING"

                filter_policy.save()

                filter_policy.conf_path = "{darwin_path}/f{filter_name}/f{filter_name}_{policy_id}.conf".format(
                    darwin_path=DARWIN_PATH,
                    filter_name=filter_policy.filter.name,
                    policy_id=filter_policy.policy.pk
                )

                filter_config = filter_policy_form.to_config()
                filter_policy.config = filter_config
                filter_policy.save()

                Cluster.api_request("services.darwin.darwin.write_policy_conf", filter_policy.pk)

                # check if the object has been created, or if any value in the configuration changed
                if not object_id or bool(set(filter_config.keys()) & set(filter_policy_form.changed_data)):
                    need_reload = True

                if 'enabled' in filter_policy_form.changed_data:
                    need_reload = True

                elif filter_policy.enabled and filter_policy_form.changed_data and object_id:
                    need_reload = True

            # If the object is new or has been modified
            if not object_id or need_reload:
                Cluster.api_request("services.darwin.darwin.build_conf")
                for frontend in policy.frontend_set.all():
                    # regenerate rsyslog conf for each frontend associated with darwin policy
                    Cluster.api_request('services.rsyslogd.rsyslog.build_conf', frontend.pk)

            # If everything succeed, redirect to list view
            return HttpResponseRedirect('/darwin/policy/')
        except Exception as error:
            if object_id:
                try:
                    policy.delete()
                except Exception:
                    pass

            raise  # There was no try/catch before, so we raise here to reproduce the same behavior

    return render(request, 'policy_edit.html',
                  {'form': form, 'filterpolicies': filter_policy_form_list})
