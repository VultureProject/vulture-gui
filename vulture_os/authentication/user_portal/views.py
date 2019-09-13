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
from django.shortcuts import render
from django.urls import reverse

# Django project imports
from gui.forms.form_utils import DivErrorList

# Required exceptions imports
from django.core.exceptions import ObjectDoesNotExist
from authentication.user_portal.form import UserAuthenticationForm
from authentication.user_portal.models import UserAuthentication

# Extern modules imports

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


def user_authentication_clone(request, object_id):
    """ UserAuthentication view used to clone an object
    N.B: Do not totally clone the object and save-it in MongoDB 
        because some attributes are unique constraints
 
    :param request: Django request object
    :param object_id: MongoDB object_id of a UserAuthentication object
    """
    """ If POST request, same as edit with no ID """
    if request.POST:
        return user_authentication_edit(request)

    try:
        profile = UserAuthentication.objects.get(pk=object_id)
    except Exception as e:
        logger.exception(e)
        return HttpResponseForbidden("Injection detected")

    profile.pk = None
    profile.name = "Copy_of_" + str(profile.name)

    form = UserAuthenticationForm(None, instance=profile, error_class=DivErrorList)

    return render(request, 'authentication/user_authentication_edit.html', {'form': form})


def user_authentication_edit(request, object_id=None):
    profile = None
    if object_id:
        try:
            profile = UserAuthentication.objects.get(pk=object_id)
        except ObjectDoesNotExist:
            return HttpResponseForbidden("Injection detected")

    form = UserAuthenticationForm(request.POST or None, instance=profile, error_class=DivErrorList)

    if request.method == "POST" and form.is_valid():
        # Save the form to get an id if there is not already one
        profile = form.save(commit=False)
        profile.save()

        # If everything succeed, redirect to list view
        return HttpResponseRedirect(reverse("portal.user_authentication.list"))

    return render(request, 'authentication/user_authentication_edit.html', {'form': form})


# TODO @group_required('administrator', 'system_manager')
# FIXME :: sso_test
def group_search_test(request):
    group_name = request.POST.get('group_name')
    form = LDAPRepositoryForm(request.POST)
    if form.group_search_is_valid():
        conf = form.save(commit=False)
        ldap_client = LDAPClient(conf)
        status = ldap_client.test_group_search(group_name)
    else:
        status = {
            'status': False,
            'reason': "some required fields are missing",
            'form_errors': form.errors
        }

    return JsonResponse(status)
