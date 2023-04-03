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
__author__ = "William DARKWA"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Error Templates API'

# Django system imports
from django.conf import settings
from django.views import View
from django.http import JsonResponse
from django.utils.translation import gettext_lazy as _
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

# Django project imports
from gui.decorators.apicall import api_need_key
from system.error_templates.models import ErrorTemplate
from system.error_templates.form import ErrorTemplateForm
from toolkit.api.responses import build_response

#Required exceptions imports
from services.exceptions import ServiceError
from system.exceptions import VultureSystemError

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')

@method_decorator(csrf_exempt, name="dispatch")
class ErrorTemplateAPIv1(View):
    @api_need_key('cluster_api_key')
    def get(self, request, object_id=None):
        try:
            fields = request.GET.getlist('fields') or None
            name = request.GET.get('name', None)
            if object_id:
                error_template = ErrorTemplate.objects.get(pk=object_id).to_dict(fields=fields)
            elif name:
                error_template = ErrorTemplate.objects.get(name=name).to_dict(fields=fields)
            else:
                error_template = [e.to_dict(fields=fields) for e in ErrorTemplate.objects.all()]

            return JsonResponse({
                'data': error_template
            })

        except ErrorTemplate.DoesNotExist:
            return JsonResponse({
                'error': _('Object does not exist')
            }, status=404)

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'error': error
            }, status=500)

    @api_need_key('cluster_api_key')
    def post(self, request, object_id=None):
        try:
            error_template = None
            if object_id:
                try:
                    error_template = ErrorTemplate.objects.get(pk=object_id)
                except ErrorTemplate.DoesNotExist:
                    return JsonResponse({'error': _("Object does not exist.")}, status=404)

            if hasattr(request, "JSON"):
                form = ErrorTemplateForm(request.JSON or None, instance=error_template)
            else:
                form = ErrorTemplateForm(request.POST or None, instance=error_template)

            return template_edit(form)

        except Exception as e:
            if settings.DEV_MODE:
                raise

            logger.error(e, exc_info=1)
            return JsonResponse({
                'status': False,
                'error': _('An error has occurred')
            }, status=500)

    @api_need_key('cluster_api_key')
    def put(self, request, object_id=None):
        try:
            if object_id:
                try:
                    error_template = ErrorTemplate.objects.get(pk=object_id)
                except ErrorTemplate.DoesNotExist:
                    return JsonResponse({'error': _("Object does not exist.")}, status=404)

                if hasattr(request, "JSON"):
                    form = ErrorTemplateForm(request.JSON or None, instance=error_template)
                else:
                    form = ErrorTemplateForm(request.POST or None, instance=error_template)

                return template_edit(form)

            else:
                return JsonResponse({'error': _("You must specify an id.")})

        except Exception as e:
            if settings.DEV_MODE:
                raise

            logger.error(e, exc_info=1)
            return JsonResponse({
                'status': False,
                'error': _('An error has occurred')
            }, status=500)

    @api_need_key('cluster_api_key')
    def delete(self, request, object_id):
        try:
            if object_id:
                try:
                    error_template = ErrorTemplate.objects.get(pk=object_id)
                except ErrorTemplate.DoesNotExist:
                    return JsonResponse({'error': _("Object does not exist.")}, status=404)

            else:
                return JsonResponse({'error': _("You must specify an id.")})

            if not request.JSON.get('confirm', "").lower() == "yes" :
                return JsonResponse({'error': _("Please confirm with confirm=yes in JSON body.")}, status=400)

            """ Verify if the ErrorTemplate is used by a frontend """
            used_frontends = error_template.frontend_set.all()
            if used_frontends:
                nodes = set()
                """ For each of them """
                for frontend in used_frontends:
                    frontend.configuration = {}
                    # Set error_template to None, to generate correct Frontend conf
                    frontend.error_template = None
                    # Conf differs for nodes
                    """ Refresh conf for each node the frontend uses """
                    try:
                        for node in frontend.get_nodes():
                            # Generate frontend conf with no error_template
                            frontend.configuration[node.name] = frontend.generate_conf(node=node)
                            # And write conf on disk
                            frontend.save_conf(node)

                            # Add node to nodes, it's a set (unicity implicitly handled)
                            nodes.add(node)
                    except (ServiceError, VultureSystemError) as e:
                        """ The object has not been yet deleted """
                        logger.critical(e, exc_info=1)
                        error = _("An error has occurred")

                        if settings.DEV_MODE:
                            error = str(e)

                        return JsonResponse({
                            'error': error
                        }, status=500)
                    # Re-set the template because it will be deleted after,
                    #  and we don't want to partialy modify object if error occurred
                    frontend.error_template = error_template
                    # Save the frontend because we maj the configuration attribute
                    frontend.save()

                """ And reload HAProxy """
                for node in nodes:
                    api_res = node.api_request("services.haproxy.haproxy.reload_service")
                    if not api_res.get('status'):
                        error = _("An error has occurred")

                        if settings.DEV_MODE:
                            error = "Template::delete: API error while trying to "\
                                    "reload HAProxy service : {}".format(api_res.get('message'))

                        return JsonResponse({
                            'error': error
                        }, status=500)

            """ Delete the conf before deleting the object """
            api_res = error_template.delete_conf()
            if not api_res.get('status'):
                # If error, do not delete the object !
                error = _("An error has occurred")

                if settings.DEV_MODE:
                    error = "Template::delete: API error while trying to "\
                            "delete the conf file(s): {}".format(api_res.get('message'))

                return JsonResponse({
                    'error': error
                }, status=500)

            """ Delete the object, at the end """
            error_template.delete()

            return JsonResponse({
                    'status': True
                }, status=204)

        except Exception as e:
            if settings.DEV_MODE:
                raise

            logger.error(e, exc_info=1)
            return JsonResponse({
                'status': False,
                'error': _('An error has occurred')
            }, status=500)

def template_edit(form):
    try:
        if form.is_valid():
            # Save the form to get an id if there is not already one
            error_template = form.save(commit=False)
            error_template.save()

            """ Write template files """
            api_res = error_template.write_conf()

            """ And if it is used by a frontend """
            if error_template.frontend_set.count() > 0:
                # Retrieve nodes concerned with those frontend(s)
                frontends = error_template.frontend_set.all()
                nodes = set()

                """ Write Frontend conf if needed """
                if form.has_changed() and any(field.endswith("_mode") for field in form.changed_data):
                    for frontend in frontends:
                        frontend.configuration = {}
                        # Conf differs for nodes
                        for node in frontend.get_nodes():
                            try:
                                frontend.configuration[node.name] = frontend.generate_conf(node=node)
                                frontend.save_conf(node)
                            except (ServiceError, VultureSystemError) as e:
                                logger.exception(e)
                                if settings.DEV_MODE:
                                    raise
                                return JsonResponse({
                                    'error': str(e)
                                }, status=500)
                            # Add node to nodes, it's a set
                            nodes.add(node)
                        # Save the frontend because we maj the configuration attribute
                        frontend.save()

                    """ And reload HAProxy """
                    for node in nodes:
                        api_res = node.api_request("services.haproxy.haproxy.reload_service")
                        if not api_res.get('status'):
                            logger.exception(e)
                            if settings.DEV_MODE:
                                raise
                            return JsonResponse({
                                'error': str(e)
                            }, status=500)

            return build_response(error_template.id, "system.error_templates.api", COMMAND_LIST)
        else:
            logger.error("ErrorTemplate api form error : {}".format(form.errors.get_json_data()))
            return JsonResponse(form.errors.get_json_data(), status=400)

    except ValueError as e:
        logger.critical(e, exc_info=1)
        if settings.DEV_MODE:
            raise

        return JsonResponse({
            'status': False,
            'error': _('JSON failed to load')
        }, status=500)

COMMAND_LIST = {
}

