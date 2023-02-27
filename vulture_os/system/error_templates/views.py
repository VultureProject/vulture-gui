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
__doc__ = 'Log Forwarders View'


# Django system imports
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.db.models import Q
from django.http import HttpResponseBadRequest, HttpResponseForbidden, HttpResponseRedirect, JsonResponse
from django.shortcuts import render
from django.utils.decorators import method_decorator
from django.views.generic import View

# Django project imports
from system.error_templates.form import ErrorTemplateForm
from system.error_templates.models import ErrorTemplate
from gui.forms.form_utils import DivErrorList

# Required exceptions imports
from django.core.exceptions import ObjectDoesNotExist
from services.exceptions import ServiceError
from system.exceptions import VultureSystemError

# Extern modules imports

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


class ListErrorTemplate(View):

    template_name="system/templates.html"

    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def get(self, request, **kwargs):
        if not request.META.get('HTTP_X_REQUESTED_WITH') == 'XMLHttpRequest':
            return render(request, self.template_name)
        return HttpResponseBadRequest()

    def post(self, request, **kwargs):
        if not request.META.get('HTTP_X_REQUESTED_WITH') == 'XMLHttpRequest':
            return HttpResponseBadRequest()

        search = request.POST['sSearch']
        s = Q()
        if search:
            s = Q(name__icontains=search)

        objs = []
        for obj in ErrorTemplate.objects.all():
            objs.append(obj.to_template())

        max_objs = len(objs)

        return JsonResponse({
            "status": True,
            "iTotalRecords": max_objs,
            "iTotalDisplayRecords": max_objs,
            "aaData": objs
        })


def template_clone(request, object_id):
    """ LogFwd view used to clone an object
    N.B: Do not totally clone the object and save-it in MongoDB 
        because some attributes are unique constraints
 
    :param request: Django request object
    :param object_id: MongoDB object_id of an ErrorTemplate object
    """
    """ If POST request, same as edit with no ID """
    if request.POST:
        return template_edit(request)

    try:
        template = ErrorTemplate.objects.get(pk=object_id)
    except Exception as e:
        logger.exception(e)
        return HttpResponseForbidden("Injection detected")

    template.pk = None
    template.name = "Copy_of_" + str(template.name)

    form = ErrorTemplateForm(None, instance=template, error_class=DivErrorList)

    return render(request, 'system/template_edit.html', {'form': form})


def template_edit(request, object_id=None):
    template = None
    if object_id:
        try:
            template = ErrorTemplate.objects.get(pk=object_id)
        except ObjectDoesNotExist:
            return HttpResponseForbidden("Injection detected")

    form = ErrorTemplateForm(request.POST or None, instance=template, error_class=DivErrorList)

    def render_form(**kwargs):
        return render(request, 'system/template_edit.html', {'form': form, **kwargs})

    if request.method == "POST" and form.is_valid():
        # Save the form to get an id if there is not already one
        obj = form.save(commit=False)
        obj.save()

        """ Write template files """
        api_res = obj.write_conf()
        if not api_res.get('status'):
            return render_form(save_error=["Error on API request trying to write templates conf",
                                           api_res.get('message')])

        """ If the object is not new """
        if object_id:
            """ And if it is used by a frontend """
            if template.frontend_set.count() > 0:
                # Retrieve nodes concerned with those frontend(s)
                frontends = template.frontend_set.all()
                nodes = set()

                """ Write Frontend conf if needed """
                for frontend in frontends:
                    if form.has_changed() and any(field.endswith("_mode") for field in form.changed_data):
                        frontend.configuration = {}
                        # Conf differs for nodes
                        for node in frontend.get_nodes():
                            try:
                                frontend.configuration[node.name] = frontend.generate_conf(node=node)
                                frontend.save_conf(node)
                            except (ServiceError, VultureSystemError) as e:
                                return render_form(save_error=[str(e), e.traceback])
                        # Save the frontend because we maj the configuration attribute
                        frontend.save()
                    # Add node to nodes, it's a set (do it even if frontend configuration wasn't updated
                    # to reload haproxy with the new files)
                    nodes.update(frontend.get_nodes())

                """ And reload HAProxy """
                for node in nodes:
                    api_res = node.api_request("services.haproxy.haproxy.reload_service")
                    if not api_res.get('status'):
                        return render_form(save_error=["API request error on node {}".format(node.name),
                                                       api_res.get('message')])

        # If everything succeed, redirect to list view
        return HttpResponseRedirect('/system/template')

    return render_form()


def template_delete(request, object_id):

    try:
        template = ErrorTemplate.objects.get(pk=object_id)
    except ObjectDoesNotExist:
        return HttpResponseForbidden("Injection detected")

    """ Verify if the ErrorTemplate is used by a frontend """
    used_frontends = template.frontend_set.all()

    def render_form(**kwargs):
        return render(request, "generic_delete.html",
                      {
                          'used_by': used_frontends,
                          'obj_inst': template,
                          'redirect_url': '/system/template',
                          'menu_name': 'System -> HTTP Messages -> Delete',
                       **kwargs})

    if request.method == "POST" and request.POST.get('confirm') == "yes":
        """ If the template was used by a frontend """
        if used_frontends:
            nodes = set()
            """ For each of them """
            for frontend in used_frontends:
                frontend.configuration = {}
                # Set error_template to None, to generate correct Frontend conf
                frontend.error_template = None
                # Conf differs for nodes
                """ Refresh conf for each node the frontend uses """
                for node in frontend.get_nodes():
                    try:
                        # Generate frontend conf with no error_template
                        frontend.configuration[node.name] = frontend.generate_conf(node=node)
                        # And write conf on disk
                        frontend.save_conf(node)
                    except (ServiceError, VultureSystemError) as e:
                        """ The object has not been yet deleted """
                        logger.exception(e)
                        return render_form(error=[str(e), e.traceback])
                    # Add node to nodes, it's a set (unicity implicitly handled)
                    nodes.add(node)
                # Re-set the template because it will be deleted after,
                #  and we don't want to partialy modify object if error occurred
                frontend.error_template = template
                # Save the frontend because we maj the configuration attribute
                frontend.save()

            """ And reload HAProxy """
            for node in nodes:
                api_res = node.api_request("services.haproxy.haproxy.reload_service")
                if not api_res.get('status'):
                    logger.error("Template::delete: API error while trying to "
                                 "reload HAProxy service : {}".format(api_res.get('message')))
                    return render_form(error=["API request error on node {}".format(node.name),
                                              api_res.get('message')])

        """ Delete the conf before deleting the object """
        api_res = template.delete_conf()
        if not api_res.get('status'):
            # If error, do not delete the object !
            logger.error("Template::delete: API error while trying to "
                         "delete the conf file(s): {}".format(api_res.get('message')))
            return render_form(error=["API request error on node {}".format(node.name),
                                      api_res.get('message')])

        """ Delete the object, at the end """
        template.delete()

        return HttpResponseRedirect('/system/template')

    return render_form()
