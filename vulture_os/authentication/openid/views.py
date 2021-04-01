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
__doc__ = 'OpenID Repository views'


# Django system imports
from django.conf import settings
from django.http import HttpResponseBadRequest, HttpResponseForbidden, HttpResponseRedirect, JsonResponse
from django.shortcuts import render

# Django project imports
from gui.forms.form_utils import DivErrorList

# Required exceptions imports
from django.core.exceptions import ObjectDoesNotExist
from authentication.openid.form import OpenIDRepositoryForm
from authentication.openid.models import OpenIDRepository

# Extern modules imports

# Logger configuration imports
import logging

from toolkit.api.responses import build_response
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


def clone(request, object_id):
    """ LDAPRepository view used to clone an object
    N.B: Do not totally clone the object and save-it in MongoDB 
        because some attributes are unique constraints
 
    :param request: Django request object
    :param object_id: MongoDB object_id of an LDAPRepository object
    """
    """ If POST request, same as edit with no ID """
    if request.POST:
        return edit(request)

    try:
        openid = OpenIDRepository.objects.get(pk=object_id)
    except Exception as e:
        logger.exception(e)
        return HttpResponseForbidden("Injection detected")

    openid.pk = None
    openid.name = "Copy_of_" + str(openid.name)

    form = OpenIDRepositoryForm(None, instance=openid, error_class=DivErrorList)

    return render(request, 'authentication/openid_edit.html', {'form': form})


def edit(request, object_id=None, api=False):
    repo = None
    if object_id:
        try:
            repo = OpenIDRepository.objects.get(pk=object_id)
        except ObjectDoesNotExist:
            return HttpResponseForbidden("Injection detected")

    if hasattr(request, "JSON") and api:
        form = OpenIDRepositoryForm(request.JSON or None, instance=repo, error_class=DivErrorList)
    else:
        form = OpenIDRepositoryForm(request.POST or None, instance=repo, error_class=DivErrorList)

    if request.method in ("POST", "PUT") and form.is_valid():
        # Save the form to get an id if there is not already one
        repo = form.save(commit=False)
        repo.save()

        # If everything succeed, redirect to list view
        if api:
            return build_response(repo.id, "authentication.openid.api", [])

        return HttpResponseRedirect('/authentication/openid/')

    return render(request, 'authentication/openid_edit.html', {'form': form})


def test_provider(request):
    form = OpenIDRepositoryForm(request.POST)

    if not form.is_valid():
        return JsonResponse({'status': False,
                             'form_errors': form.errors})

    provider = form.save(commit=False)

    try:
        return JsonResponse({'status':True, 'data':provider.retrieve_config(test=True)})
    except Exception as e:
        logger.exception(e)
        return JsonResponse({'status': False, 'error': str(e)})
