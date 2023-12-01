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
__author__ = "Kevin GUILLEMOT"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'LDAP Repository views'


# Django system imports
from django.conf import settings
from django.http import HttpResponseBadRequest, HttpResponseForbidden, HttpResponseRedirect, JsonResponse
from django.http.response import HttpResponseNotFound
from django.shortcuts import render

# Django project imports
from toolkit.api.responses import build_response, build_form_errors
from gui.forms.form_utils import DivErrorList

# Required exceptions imports
from django.core.exceptions import ObjectDoesNotExist
from authentication.ldap.form import LDAPRepositoryForm, LDAPCustomAttributeMappingForm
from authentication.ldap.models import LDAPRepository, LDAPCustomAttributeMapping

# Extern modules imports
from json import loads as json_loads

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


def ldap_clone(request, object_id):
    """ LDAPRepository view used to clone an object
    N.B: Do not totally clone the object and save-it in MongoDB
        because some attributes are unique constraints

    :param request: Django request object
    :param object_id: MongoDB object_id of an LDAPRepository object
    """
    """ If POST request, same as edit with no ID """
    if request.POST:
        return ldap_edit(request)

    try:
        ldap = LDAPRepository.objects.get(pk=object_id)
    except Exception as e:
        logger.exception(e)
        return HttpResponseNotFound("Object not found")

    ldap.pk = None
    ldap.name = "Copy_of_" + str(ldap.name)

    form = LDAPRepositoryForm(None, instance=ldap, error_class=DivErrorList)

    return render(request, 'authentication/ldap_edit.html', {'form': form})


def ldap_edit(request, object_id=None, api=False):
    ldap = None
    custom_attributes = list()
    list_cattr_ids_to_delete = list()
    if object_id:
        try:
            ldap = LDAPRepository.objects.prefetch_related('ldapcustomattributemapping_set').get(pk=object_id)
            # Get a list of current custom attribute associated to objects
            # They will be deleted if not found in the query anymore
            list_cattr_ids_to_delete = list(ldap.ldapcustomattributemapping_set.all().values_list('id', flat=True))
        except ObjectDoesNotExist:
            return HttpResponseNotFound('Object not found')

    if hasattr(request, "JSON") and api:
        form = LDAPRepositoryForm(request.JSON or None, instance=ldap, error_class=DivErrorList)
    else:
        form = LDAPRepositoryForm(request.POST or None, instance=ldap, error_class=DivErrorList)

    def render_form(repo, **kwargs):
        if api:
            logger.error("Frontend api form error : {}".format(form.errors.get_json_data()))
            return JsonResponse({"errors": build_form_errors(form.errors)}, status=400)

        if not custom_attributes and repo:
            for mapping in repo.ldapcustomattributemapping_set.all():
            # for mapping in LDAPCustomAttributeMapping.objects.filter(repository=repo):
                custom_attributes.append(LDAPCustomAttributeMappingForm(instance=mapping))

        return render(request, 'authentication/ldap_edit.html',
                      {'form': form,
                       'custom_attributes': custom_attributes,
                       'custom_attributes_form': LDAPCustomAttributeMappingForm(),
                       'object_id': object_id,
                       **kwargs})

    if request.method == "POST":
        if request.POST.get('connection_test'):
            if form.connection_is_valid():
                conf = form.save(commit=False)
                ldap_client = conf.get_client()
                result = ldap_client.test_ldap_connection()
                if not result.get('status'):
                    return render_form(ldap, connection_error=result.get('reason'))
                else:
                    return render_form(ldap, success="Successful connection")
            else:
                return render_form(ldap)

    if request.method in ("POST", "PUT") and form.is_valid():
        # Save the form to get an id if there is not already one
        ldap = form.save(commit=False)

        try:
            if api and hasattr(request, "JSON"):
                custom_attributes_data = request.JSON.get('custom_attributes', [])
                assert isinstance(custom_attributes_data, list), "custom_attributes field must be a list."
            else:
                custom_attributes_data = json_loads(request.POST.get('custom_attributes', "[]"))
        except Exception as e:
            return render_form(ldap, save_error=["Error while getting custom attributes: {}".format(e)])

        for cattr_data in custom_attributes_data:
            try:
                cattr_instance = LDAPCustomAttributeMapping.objects.get(id=cattr_data['id']) if cattr_data.get('id') else None
                if cattr_instance and cattr_instance.id in list_cattr_ids_to_delete:
                    # Custom Attribute is still associated to object, won't be deleted
                    list_cattr_ids_to_delete.remove(cattr_instance.id)
            except ObjectDoesNotExist:
                form.add_error(None, f"Could not find custom attribute object with id {cattr_data['id']}")
                continue

            cattr_form = LDAPCustomAttributeMappingForm(cattr_data, instance=cattr_instance)

            if not cattr_form.is_valid():
                custom_attributes.append(cattr_form)
                form.add_error(None, "Errors found in custom user attributes, please check your values")
                continue

            custom_attributes.append(cattr_form)
            cattr_obj = cattr_form.save(commit=False)
            cattr_obj.repository = ldap
            cattr_form.save()

        # If errors has been added in form
        if not form.is_valid():
            return render_form(ldap)

        # Remove all Custom Attributes that existed for the object, but were no longer present in the query
        logger.debug(f"Removing obsolete Custom attributes for {ldap}: {list_cattr_ids_to_delete}")
        LDAPCustomAttributeMapping.objects.filter(id__in=list_cattr_ids_to_delete).delete()

        # Really save object in DB
        ldap.save()
        # If everything succeed, redirect to list view
        if api:
            return build_response(ldap.id, "authentication.api.ldap", [])

        return HttpResponseRedirect('/authentication/ldap/')

    return render_form(ldap)


# TODO @group_required('administrator', 'system_manager')
def user_search_test(request):
    # TODO SECURITY CLEAN FOR USERNAME AND PASSWORD, to prevent LDAP Injection
    username = request.POST.get('username')
    password = request.POST.get('password')
    instance = None
    if request.POST.get('id'):
        instance = LDAPRepository.objects.get(pk=request.POST.get('id'))
    form = LDAPRepositoryForm(request.POST, instance=instance)
    if form.user_search_is_valid():
        conf = form.save(commit=False)
        ldap_client = conf.get_client()
        status = ldap_client.test_user_connection(username, password)
    else:
        status = {
            'status': False,
            'reason': "Some fields are missing or wrong.",
            'form_errors': form.errors
        }
    return JsonResponse(status)


# TODO @group_required('administrator', 'system_manager')
def group_search_test(request):
    group_name = request.POST.get('group_name')
    instance = None
    if request.POST.get('id'):
        instance = LDAPRepository.objects.get(pk=request.POST.get('id'))
    form = LDAPRepositoryForm(request.POST, instance=instance)
    if form.group_search_is_valid():
        conf = form.save(commit=False)
        ldap_client = conf.get_client()
        status = ldap_client.test_group_search(group_name)
    else:
        status = {
            'status': False,
            'reason': "form is not valid",
            'form_errors': form.errors.as_ul()
        }

    return JsonResponse(status)
