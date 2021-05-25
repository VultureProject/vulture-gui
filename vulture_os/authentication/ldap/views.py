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
from authentication.ldap.form import LDAPRepositoryForm
from authentication.ldap.models import LDAPRepository

# Extern modules imports

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
    if object_id:
        try:
            ldap = LDAPRepository.objects.get(pk=object_id)
        except ObjectDoesNotExist:
            return HttpResponseNotFound('Object not found')

    if hasattr(request, "JSON") and api:
        form = LDAPRepositoryForm(request.JSON or None, instance=ldap, error_class=DivErrorList)
    else:
        form = LDAPRepositoryForm(request.POST or None, instance=ldap, error_class=DivErrorList)

    def render_form(objectid=None, **kwargs):
        if api:
            logger.error("Frontend api form error : {}".format(form.errors.get_json_data()))
            return JsonResponse({"errors": build_form_errors(form.errors)}, status=400)

        return render(request, 'authentication/ldap_edit.html',
                      {'form': form, 'object_id': objectid, **kwargs})

    if request.method == "POST":
        if request.POST.get('connection_test'):
            if form.connection_is_valid():
                conf = form.save(commit=False)
                ldap_client = conf.get_client()
                result = ldap_client.test_ldap_connection()
                if not result.get('status'):
                    return render_form(connection_error=result.get('reason'))
                else:
                    return render_form(success="Successful connection")
            else:
                return render_form(ldap.id if ldap else None)

    if request.method in ("POST", "PUT") and form.is_valid():
        # Save the form to get an id if there is not already one
        ldap = form.save(commit=False)
        ldap.save()
        # If everything succeed, redirect to list view
        if api:
            return build_response(ldap.id, "authentication.api.ldap", [])

        return HttpResponseRedirect('/authentication/ldap/')

    return render_form(ldap.id if ldap else None)


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
