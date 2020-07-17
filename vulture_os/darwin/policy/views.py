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

from darwin.policy.form import (DarwinPolicyForm, FilterPolicyForm,
                                FilterPolicyHostlookupForm, FilterPolicyDGAForm,
                                FilterPolicyContentInspectionForm, FilterPolicyTAnomalyForm, FilterPolicyConnectionForm)
from darwin.policy.models import DarwinPolicy, DarwinFilter, FilterPolicy
from django.conf import settings

# Django system imports
from django.http import HttpResponseForbidden, HttpResponseRedirect, JsonResponse
from django.shortcuts import render

# Django project imports
from gui.forms.form_utils import DivErrorList
from system.cluster.models import Cluster, Node

# Required exceptions imports
from django.core.exceptions import ObjectDoesNotExist
from services.exceptions import ServiceConfigError, ServiceError, ServiceReloadError
from system.exceptions import VultureSystemError

# Extern modules imports
from json import loads as json_loads
from sys import exc_info
from traceback import format_exception

# Logger configuration imports
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


FILTER_POLICY_FORMS = {
    "dga": FilterPolicyDGAForm,
    "content_inspection": FilterPolicyContentInspectionForm,
    "tanomaly": FilterPolicyTAnomalyForm,
    "anomaly": FilterPolicyForm,
    "connection": FilterPolicyConnectionForm,
    "hostlookup": FilterPolicyHostlookupForm,
}

COMMAND_LIST = {}


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

    policy_id = policy.pk
    policy.pk = None
    policy.name = "Copy_of_" + str(policy.name)

    form = DarwinPolicyForm(None, instance=policy, error_class=DivErrorList)

    filter_policy_form_list = []
    for filter in FilterPolicy.objects.filter(policy=policy_id):
        filter_policy_form_class = FILTER_POLICY_FORMS.get(filter.filter.name, FilterPolicyForm)
        filter_policy_form = filter_policy_form_class(
            instance=filter
        )
        filter_policy_form_list.append(filter_policy_form)

    return render(request, 'policy_edit.html', {'form': form, 'filterpolicies': filter_policy_form_list})


def policy_edit(request, object_id=None, api=False):
    policy = None
    filter_list = []
    filter_form_list = []
    if object_id:
        try:
            policy = DarwinPolicy.objects.get(pk=object_id)
        except DarwinPolicy.DoesNotExist:
            if api:
                return JsonResponse({'error': ("Object does not exist.")}, status=404)
            return HttpResponseForbidden("Injection detected")

    if hasattr(request, "JSON") and api:
        form = DarwinPolicyForm(request.JSON or None, instance=policy, error_class=DivErrorList)
    else:
        form = DarwinPolicyForm(request.POST or None, instance=policy, error_class=DivErrorList)

    def render_form(policy, **kwargs):
        save_error = kwargs.get('save_error')
        if api:
            if form.errors:
                return JsonResponse(form.errors.get_json_data(), status=400)
            if save_error:
                return JsonResponse({'error': save_error[0]}, status=500)

        if not filter_form_list and policy:
            for f_tmp in FilterPolicy.objects.filter(policy=policy).exclude(is_internal=True):
                filter_form_class = FILTER_POLICY_FORMS.get(f_tmp.filter.name, None)
                if filter_form_class:
                    filter_form_list.append(filter_form_class(instance=f_tmp))
                else:
                    logger.error("Unknown filter type in database: {}".format(f_tmp.name))
        return render(request, 'policy_edit.html',
                      {'form': form, 'filterpolicyform': FilterPolicyForm(),
                      'filterpolicies': filter_form_list,
                      "filter_types": FILTER_POLICY_FORMS.keys(), **kwargs})

    if request.method in ("POST", "PUT"):
        filter_objs = []
        if form.data.get('mode') == "http":
            """ Handle JSON formatted request filters """
            try:
                if api:
                    filter_ids = request.JSON.get('filters', [])
                    assert isinstance(filter_ids, list), "filters field must be a list."
                else:
                    filter_ids = json_loads(request.POST.get('filters', "[]"))
            except Exception as e:
                return render_form(policy, save_error=["Error in Request-filters field : {}".format(e),
                                                        str.join('', format_exception(*exc_info()))])

            """ For each filter in list """
            for filt in filter_ids:
                """ If id is given, retrieve object from mongo """
                try:
                    instance_f = FilterPolicy.objects.get(pk=filt['id']) if filt['id'] else None
                except ObjectDoesNotExist:
                    form.add_error(None, "Request-filter with id {} not found. Injection detected ?")
                    continue
                """ Search for the right Form class """
                filter_form_class = FILTER_POLICY_FORMS.get(filt['name'], None)
                if not filter_form_class:
                    form.add_error(None, "Request-filter with name {} not found. Injection detected ?".format(filt['name']))
                    continue
                """ And instantiate form with the object, or None """
                filter_f = filter_form_class(filt, instance=instance_f)

                if not filter_f.is_valid():
                    if api:
                        form.add_error(None, filter_f.errors.get_json_data())
                    else:
                        form.add_error('filters', filter_f.errors.as_ul())
                    continue
                # Save forms in case we re-print the page
                filter_form_list.append(filter_f)
                # And save objects list, to save them later, when Frontend will be saved
                filter_objs.append(filter_f.save(commit=False))

        # If errors has been added in form
        if not form.is_valid():
            logger.error("Form errors: {}".format(form.errors.as_json()))
            return render_form(policy)

        # Save the form to get an id if there is not already one
        policy = form.save(commit=False)

        """ If the conf is OK, save the Backend object """
        # Is that object already in db or not
        first_save = not policy.id
        try:
            logger.debug("Saving policy")
            policy.save()
            logger.debug("Policy '{}' (id={}) saved in MongoDB.".format(policy.name, policy.id))

            for filt in policy.filters.all():
                if filt not in filter_objs:
                    policy.filters.remove(filt)

        except (VultureSystemError, ServiceError) as e:
            """ Error saving configuration file """
            """ The object has been saved, delete-it if needed """
            if first_save:
                policy.delete()

            logger.exception(e)
            return render_form(policy, save_error=[str(e), e.traceback])

        except Exception as e:
            """ If we arrive here, the object has not been saved """
            logger.exception(e)
            return render_form(policy, save_error=["Failed to save object in database :\n{}".format(e),
                                                    str.join('', format_exception(*exc_info()))])

        if api:
            return build_response()
        return HttpResponseRedirect('/darwin/policy/')

    return render_form(policy)










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
        policy = form.save(commit=False)

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

                filter_config = filter_policy_form.to_config()
                filter_policy.config = filter_config
                filter_policy.save()

                # check if the object has been created, or if any value in the configuration changed
                if not object_id or bool(set(filter_config.keys()) & set(filter_policy_form.changed_data)):
                    need_reload = True

                if 'enabled' in filter_policy_form.changed_data:
                    need_reload = True

                elif filter_policy.enabled and filter_policy_form.changed_data and object_id:
                    need_reload = True


            Cluster.api_request("services.darwin.darwin.write_policy_conf", policy.pk)
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
