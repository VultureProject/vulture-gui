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
__doc__ = 'Kerberos Repository views'


# Django system imports
from django.conf import settings
from django.http import HttpResponseForbidden, HttpResponseRedirect, JsonResponse
from django.shortcuts import render

# Django project imports
from gui.forms.form_utils import DivErrorList

# Required exceptions imports
from django.core.exceptions import ObjectDoesNotExist
from authentication.kerberos.form import KerberosRepositoryForm
from authentication.kerberos.models import KerberosRepository

# Extern modules imports

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


def kerberos_clone(request, object_id):
    """ KerberosRepository view used to clone an object
    N.B: Do not totally clone the object and save-it in MongoDB 
        because some attributes are unique constraints
 
    :param request: Django request object
    :param object_id: MongoDB object_id of an KerberosRepository object
    """
    """ If POST request, same as edit with no ID """
    if request.POST:
        return kerberos_edit(request)

    try:
        kerberos = KerberosRepository.objects.get(pk=object_id)
    except Exception as e:
        logger.exception(e)
        return HttpResponseForbidden("Injection detected")

    kerberos.pk = None
    kerberos.name = "Copy_of_" + str(kerberos.name)

    form = KerberosRepositoryForm(None, instance=kerberos, error_class=DivErrorList)

    return render(request, 'authentication/kerberos_edit.html', {'form': form})


def kerberos_edit(request, object_id=None):
    kerberos = None
    if object_id:
        try:
            kerberos = KerberosRepository.objects.get(pk=object_id)
        except ObjectDoesNotExist:
            return HttpResponseForbidden("Injection detected")

    form = KerberosRepositoryForm(request.POST or None, request.FILES or None, instance=kerberos,  # Do not modify
                                  error_class=DivErrorList)

    def render_form(objectid=None, **kwargs):
        return render(request, 'authentication/kerberos_edit.html',
                      {'form': form, 'object_id': objectid, **kwargs})

    if request.method == "POST" and form.is_valid():
        # Save the form to get an id if there is not already one
        kerberos = form.save(commit=False)
        kerberos.save()

        # If everything succeed, redirect to list view
        return HttpResponseRedirect('/authentication/kerberos/')

    return render_form(kerberos.id if kerberos else None)


# TODO @group_required('administrator', 'system_manager')
def user_search_test(request):
    # TODO SECURITY CLEAN FOR USERNAME AND PASSWORD, to prevent Kerberos Injection
    username = request.POST.get('username')
    if not username:
        return JsonResponse({'status': False, 'reason': "Username is missing."})
    password = request.POST.get('password')
    if not password:
        return JsonResponse({'status': False, 'reason': "Password is missing."})
    form = KerberosRepositoryForm(request.POST, request.FILES)
    if form.is_valid():
        conf = form.save(commit=False)
        kerberos_client = conf.get_client()
        status = kerberos_client.test_user_connection(username, password)
    else:
        status = {
            'status': False,
            'reason': "Some fields are missing or wrong",
            'form_errors': form.errors
        }
    return JsonResponse(status)
