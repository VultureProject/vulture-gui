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
__doc__ = 'Parsers View'

# Django system imports
from django.conf import settings
from django.http import (JsonResponse, HttpResponseBadRequest, HttpResponseForbidden, HttpResponseRedirect,
                         HttpResponseNotAllowed)
from django.shortcuts import render
from django.urls import reverse
from django.utils.translation import ugettext_lazy as _

# Django project imports
from gui.forms.form_utils import DivErrorList
from applications.parser.form import ParserForm
from applications.parser.models import Parser
from toolkit.api.responses import build_response

# Required exceptions imports
from django.core.exceptions import ObjectDoesNotExist
from services.exceptions import ServiceConfigError, ServiceError, ServiceReloadError
from system.exceptions import VultureSystemError

# Extern modules imports
from sys import exc_info
from traceback import format_exception

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


def parser_clone(request, object_id):
    """ Backend view used to clone a Backend object
    N.B: Do not totally clone the object and save-it in MongoDB 
        because some attributes are unique constraints
 
    :param request: Django request object
    :param object_id: MongoDB object_id of a Backend object
    """
    if not object_id:
        return HttpResponseRedirect('/apps/parser/')

    """ Retrieve object from id in MongoDB """
    try:
        parser = Parser.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        return HttpResponseForbidden("Injection detected")

    parser.pk = None
    parser.name = 'Copy of {}'.format(parser.name)
    form = ParserForm(None, instance=parser, error_class=DivErrorList)

    return render(request, 'apps/parser_edit.html',
                  {'form': form, 'cloned': True})


def parser_delete(request, object_id, api=False):
    """ Delete Backend and related Listeners """
    error = ""
    try:
        parser = Parser.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        if api:
            return JsonResponse({'error': _("Object does not exist.")}, status=404)
        return HttpResponseForbidden("Injection detected")

    if ((request.method == "POST" and request.POST.get('confirm', "").lower() == "yes")
            or (api and request.method == "DELETE" and request.JSON.get('confirm', "").lower() == "yes")):

        try:
            # Firstly, try to delete the conf before deleting the object
            parser.delete_conf()

            """ Delete the object """
            parser_name = parser.name
            parser.delete()
            logger.info("Parser '{}' deleted.".format(parser_name))
        except Exception as e:
            error = "Fail to delete the object : {}".format(e)
            if api:
                return JsonResponse({
                    'status': False,
                    'error': str(e)
                }, status=500)
        else:
            if api:
                return JsonResponse({
                    'status': True
                }, status=204)
            return HttpResponseRedirect(reverse('applications.parser.list'))

    if api:
        return JsonResponse({'error': _("Please confirm with confirm=yes in JSON body.")}, status=400)

    # If GET request or POST request and API/Delete failure
    return render(request, 'generic_delete.html', {
        'menu_name': _("Applications -> Parsers -> Delete"),
        'redirect_url': reverse("applications.parser.list"),
        'delete_url': reverse("applications.parser.delete", kwargs={'object_id': parser.id}),
        'obj_inst': parser,
        'error': error,
        'used_by': []
    })


def parser_edit(request, object_id=None, api=False):
    parser = None
    if object_id:
        try:
            parser = Parser.objects.get(pk=object_id)
        except ObjectDoesNotExist:
            if api:
                return JsonResponse({'error': _("Object does not exist.")}, status=404)
            return HttpResponseForbidden("Injection detected")

    """ Create form with object if exists, and request.POST (or JSON) if exists """
    if hasattr(request, "JSON") and api:
        form = ParserForm(request.JSON or None, instance=parser, error_class=DivErrorList)
    else:
        form = ParserForm(request.POST or None, instance=parser, error_class=DivErrorList)

    def render_form(**kwargs):
        save_error = kwargs.get('save_error')
        if api:
            if form.errors:
                return JsonResponse(form.errors.get_json_data(), status=400)
            if save_error:
                return JsonResponse({'error': save_error[0]}, status=500)

        return render(request, 'apps/parser_edit.html',
                      {'form': form, **kwargs})

    if request.method in ("POST", "PUT", "PATCH"):

        # If errors has been added in form
        if not form.is_valid():
            logger.error("Form errors: {}".format(form.errors.as_json()))
            if api:
                return JsonResponse(form.errors.get_json_data(), status=400)
            return render_form()

        # Save the form to get an id if there is not already one
        parser = form.save(commit=False)

        """ Generate the non-yet saved object conf """
        try:
            logger.debug("Trying  '{}'".format(parser.name))
            content = parser.test_conf()
            logger.info("Parser '{}' conf ok".format(parser.name))
        except VultureSystemError as e:
            logger.exception(e)
            return render_form(save_error=[str(e), e.traceback])

        except Exception as e:
            logger.exception(e)
            return render_form(save_error=["No referenced error",
                                                           str.join('', format_exception(*exc_info()))])

        """ If the conf is saved, save the Parser object """
        logger.debug("Saving parser")
        parser.save()
        logger.debug("Parser '{}' (id={}) saved in MongoDB.".format(parser.name, parser.id))

        first_save = not object_id
        try:
            parser.save_conf()
        except (VultureSystemError, ServiceError) as e:
            """ Error saving configuration file """
            """ The object has been saved, delete-it if needed """
            if first_save:
                parser.delete()

            logger.exception(e)
            return render_form(save_error=[str(e), e.traceback])

        except Exception as e:
            """ If we arrive here, the object has not been saved """
            logger.exception(e)
            return render_form(save_error=["Failed to save object in database :\n{}".format(e),
                                                    str.join('', format_exception(*exc_info()))])

        if api:
            return build_response(parser.id, "applications.parser.api", COMMAND_LIST)
        return HttpResponseRedirect('/apps/parser/')

    return render_form()


COMMAND_LIST = {
}
