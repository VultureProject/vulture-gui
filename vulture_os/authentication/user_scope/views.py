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
__doc__ = 'UserScope management views'

# Django system imports
from django.conf import settings
from django.http import HttpResponseRedirect, JsonResponse
from django.http.response import HttpResponseNotFound
from django.utils.translation import gettext_lazy as _
from django.shortcuts import render
from django.urls import reverse

# Django project imports
from gui.forms.form_utils import DivErrorList
from toolkit.api.responses import build_response

# Required exceptions imports
from django.core.exceptions import ObjectDoesNotExist
from authentication.user_scope.form import UserScopeForm
from authentication.user_scope.models import UserScope, RepoAttributeForm

# Extern modules imports
from json import loads as json_loads
from traceback import format_exception
from sys import exc_info

# Logger configuration imports
import logging

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


def user_scope_clone(request, object_id):
    """ UserScope view used to clone an object
    N.B: Do not totally clone the object and save-it in MongoDB 
        because some attributes are unique constraints

    :param request: Django request object
    :param object_id: MongoDB object_id of a UserScope object
    """
    """ If POST request, same as edit with no ID """
    if request.POST:
        return user_scope_edit(request)

    try:
        profile = UserScope.objects.get(pk=object_id)
    except Exception as e:
        logger.exception(e)
        return HttpResponseNotFound("Object not found")

    profile.pk = None
    profile.name = "Copy_of_" + str(profile.name)

    repo_attrs_form_list = []
    for p in profile.get_repo_attributes():
        repo_attrs_form_list.append(RepoAttributeForm(instance=p))

    form = UserScopeForm(None, instance=profile, error_class=DivErrorList)
    return render(request, 'authentication/user_scope_edit.html', {
        'form': form,
        'repo_attributes': repo_attrs_form_list,
        'repo_attribute_form': RepoAttributeForm()
    })


def user_scope_edit(request, object_id=None, api=False):
    profile = None
    repo_attrs_form_list = []
    repo_attrs_objs = []
    if object_id:
        try:
            profile = UserScope.objects.get(pk=object_id)
        except ObjectDoesNotExist:
            return HttpResponseNotFound(_("Object not found"))

    """ Create form with object if exists, and request.POST (or JSON) if exists """
    # Do NOT remove this line
    empty = {} if api else None
    if hasattr(request, "JSON") and api:
        form = UserScopeForm(request.JSON or {}, instance=profile, error_class=DivErrorList)
    else:
        form = UserScopeForm(request.POST or empty, instance=profile, error_class=DivErrorList)

    def render_form(profile, **kwargs):
        save_error = kwargs.get('save_error')
        if api:
            if form.errors:
                return JsonResponse(form.errors.get_json_data(), status=400)
            if save_error:
                return JsonResponse({'error': save_error[0]}, status=500)

        if not repo_attrs_form_list and profile:
            for p in profile.get_repo_attributes():
                repo_attrs_form_list.append(RepoAttributeForm(instance=p))

        return render(request, 'authentication/user_scope_edit.html',
                      {'form': form,
                       'repo_attributes': repo_attrs_form_list,
                       'repo_attribute_form': RepoAttributeForm(),
                       **kwargs})

    if request.method in ("POST", "PUT"):
        """ Handle repo attributes (user scope) """
        try:
            if api and hasattr(request, "JSON"):
                repo_attrs = request.JSON.get('repo_attributes', [])
                assert isinstance(repo_attrs, list), "Repo attributes field must be a list."
            else:
                repo_attrs = json_loads(request.POST.get('repo_attributes', "[]"))
        except Exception as e:
            if api:
                return JsonResponse({
                    "error": "".join(format_exception(*exc_info()))
                }, status=400)
            return render_form(profile, save_error=["Error in Repo_Attributes field : {}".format(e),
                                                    str.join('', format_exception(*exc_info()))])

        """ For each Health check header in list """
        for repo_attr in repo_attrs:
            repoattrform = RepoAttributeForm(repo_attr, error_class=DivErrorList)
            if not repoattrform.is_valid():
                if api:
                    form.add_error(None, repoattrform.errors.get_json_data())
                else:
                    form.add_error('repo_attributes', repoattrform.errors.as_ul())
                continue
            # Save forms in case we re-print the page
            repo_attrs_form_list.append(repoattrform)
            repo_attrs_objs.append(repoattrform.save(commit=False))

        if form.is_valid():
            # Save the form to get an id if there is not already one
            profile = form.save(commit=False)
            for repo_attr in repo_attrs_objs:
                repo_attr.save()
            profile.repo_attributes = repo_attrs_objs
            profile.save()

            # If everything succeed, redirect to list view
            if api:
                return build_response(profile.id, "api.authentication.user_scope", [])
            return HttpResponseRedirect(reverse("authentication.user_scope.list"))

    return render_form(profile)

