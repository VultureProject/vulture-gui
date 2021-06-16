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

__author__ = "Théo BERTIN"
__credits__ = ["Kevin GUILLEMOT"]
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Darwin Policy APIs'


# Django system imports
from django.conf import settings
from django.core.exceptions import ValidationError
from django.db.models.deletion import ProtectedError
from django.http import (JsonResponse, HttpResponseBadRequest, HttpResponseForbidden)
from django.utils.translation import ugettext_lazy as _
from django.views import View
from django.utils.decorators import method_decorator

# Django project imports
from gui.decorators.apicall import api_need_key
from django.views.decorators.csrf import csrf_exempt
from darwin.policy.models import DarwinPolicy, DarwinFilter, FilterPolicy, DarwinBuffering, VAST_MODELS_PATH, VAML_MODELS_PATH
from darwin.policy.views import policy_edit, COMMAND_LIST
from system.cluster.models import Cluster, Node
from services.frontend.models import Frontend
from toolkit.api.responses import build_response


# Extern modules imports
from glob import glob as file_glob
import json
from os import path as os_path
from pymongo.errors import DuplicateKeyError
from sys import exc_info

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api')


@method_decorator(csrf_exempt, name="dispatch")
class DarwinFilterTypesAPIv1(View):
    @api_need_key('cluster_api_key')
    def get(self, request):
        data = []
        try:
            for filter_type in DarwinFilter.objects.all():
                data.append(filter_type.to_dict())
        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'error': error
            }, status=500)

        return JsonResponse({
            'data': data
        }, status=200)


@method_decorator(csrf_exempt, name="dispatch")
class DarwinFilterAPIv1(View):
    @api_need_key('cluster_api_key')
    def get(self, request, filter_id=None):
        data = {}
        try:
            if not filter_id:
                data = []
                for policy_filter in FilterPolicy.objects.all():
                    data.append(policy_filter.to_dict())
            else:
                try:
                    policy_filter = FilterPolicy.objects.get(id=filter_id)
                    data = policy_filter.to_dict()
                except FilterPolicy.DoesNotExist:
                    return JsonResponse({
                        'error': _("filter with id {} does not exist".format(filter_id))
                    }, status=404)

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'error': error
            }, status=500)

        return JsonResponse({
            'data': data
        }, status=200)



@method_decorator(csrf_exempt, name="dispatch")
class DarwinPolicyAPIv1(View):
    @api_need_key('cluster_api_key')
    def get(self, request, object_id=None):
        try:
            if object_id:
                try:
                    obj = DarwinPolicy.objects.get(pk=object_id).to_dict()
                except DarwinPolicy.DoesNotExist:
                    return JsonResponse({
                        'error': _('Object does not exist')
                    }, status=404)

            else:
                obj = [s.to_dict() for s in DarwinPolicy.objects.all()]

            return JsonResponse({
                'data': obj
            })

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'error': error
            }, status=500)

    @staticmethod
    def _create_or_update_filters(policy, filters_list):
        new_filters = []
        bufferings =[]

        current_filters = FilterPolicy.objects.filter(policy_id=policy.pk)

        for filt in filters_list:
            try:
                filt['policy'] = policy
                filt['filter_type'] = DarwinFilter.objects.get(id=filt.get('filter_type', 0))
            except DarwinFilter.DoesNotExist:
                logger.error(f"Error while creating/updating filter for darwin policy : DarwinFilter id '{filt.get('filter_type', 0)}' does not exist")
                return f"unknown filter type {filt.get('filter_type', 0)}"

            buffering_opts = filt.pop('buffering', None)
            try:
                filt_id = filt.pop('id', 0)
                if filt_id != 0:
                    filter_instance, _ = FilterPolicy.objects.update_or_create(
                        id=filt_id,
                        defaults=filt)
                else:
                    filter_instance = FilterPolicy(**filt)

                filter_instance.status = {node.name: "STARTING" for node in Node.objects.all().only('name')}

                filter_instance.full_clean()
                new_filters.append(filter_instance)

                if buffering_opts:
                    bufferings.append((filter_instance, buffering_opts))

            except (ValidationError, ValueError, TypeError) as e:
                logger.error(str(e), exc_info=1)
                return str(e)

        for filter_instance in new_filters:
            filter_instance.save()

        filters_delete = set(current_filters) - set(new_filters)
        for filter_delete in filters_delete:
            Cluster.api_request("services.darwin.darwin.delete_filter_conf", filter_delete.conf_path)
            filter_delete.delete()

        try:
            for filter_instance, buffering_opts in bufferings:
                DarwinBuffering.objects.update_or_create(
                    destination_filter=filter_instance,
                    defaults={
                        'interval': buffering_opts.get('interval'),
                        'required_log_lines': buffering_opts.get('required_log_lines'),
                    }
                )
        except Exception as e:
            logger.error(e, exc_info=1)
            return 'error while creating darwin buffering: {}'.format(e)

        return ""


    @api_need_key('cluster_api_key')
    def post(self, request, object_id=None, action=None):
        policy = None

        try:
            if action:
                #Trigger action on existing policy
                if not object_id:
                    return JsonResponse({
                        'error': _('You must specify an ID')
                    }, status=401)

                if action not in list(COMMAND_LIST.keys()):
                    return JsonResponse({
                        'error': _('Action not allowed')
                    }, status=403)
                return COMMAND_LIST[action](request, object_id, api=True)
            else:
                #Create a new policy with filters
                # Content could be in POST when coming from GUI
                if hasattr(request, "JSON"):
                    filters_list = request.JSON.get('filters', [])
                    name = request.JSON.get('name', '')
                    description = request.JSON.get('description', '')
                    is_internal = request.JSON.get('is_internal', False)
                else:
                    filters_list = json.loads(request.POST.get('filters', '[]'))
                    name = request.POST.get('name', '')
                    description = request.POST.get('description', '')
                    is_internal = request.POST.get('is_internal', False)

                policy = DarwinPolicy(
                    name=name,
                    description=description,
                    is_internal=is_internal
                )

                try:
                    policy.full_clean()
                    policy.save()
                except ValidationError as e:
                    logger.error(e)
                    return JsonResponse({
                        'error': str(e),
                    }, status=400)

                error = DarwinPolicyAPIv1._create_or_update_filters(policy, filters_list)
                if error:
                    try:
                        policy.delete()
                    except:
                        pass
                    return JsonResponse({
                        "error": error
                    }, status=400)

        except Exception as e:
            try:
                policy.delete()
            except:
                pass

            logger.critical(e, exc_info=1)
            if settings.DEV_MODE:
                error = str(e)
            else:
                error = _("An error has occurred")
            return JsonResponse({
                'error': error
            }, status=500)

        if DarwinBuffering.objects.filter(destination_filter__policy=policy).exists():
            DarwinPolicy.update_buffering()

        for frontend in policy.frontend_set.all():
            for node in frontend.get_nodes():
                node.api_request("services.rsyslogd.rsyslog.build_conf", frontend.pk)

        Cluster.api_request("services.darwin.darwin.write_policy_conf", policy.pk)
        Cluster.api_request("services.darwin.darwin.reload_conf")

        return build_response(policy.pk, "darwin.policy.api", COMMAND_LIST)


    @api_need_key('cluster_api_key')
    def put(self, request, object_id=None):
        try:
            if object_id:
                # Content should always be JSON here
                filters = request.JSON.get('filters', [])
                name = request.JSON.get('name', '')
                description = request.JSON.get('description', '')
                # filters object might be a string when coming from GUI
                if isinstance(filters, str):
                    try:
                        filters = json.loads(filters)
                    except json.JsonDecodeError as e:
                        logger.error(e)
                        return JsonResponse({
                            'error': str(e)
                        }, status=400)

                policy, created = DarwinPolicy.objects.get_or_create(pk=object_id)

                policy.name = name
                policy.description = description

                try:
                    policy.full_clean()
                except ValidationError as e:
                    logger.error(e)
                    return JsonResponse({
                        'error': str(e),
                    }, status=400)

                error = DarwinPolicyAPIv1._create_or_update_filters(policy, filters)
                if error:
                    if created:
                        try:
                            policy.delete()
                        except:
                            pass
                    return JsonResponse({
                        "error": error
                    }, status=400)

                # Save once no errors were triggered during filters creation
                policy.save()
            else:
                return JsonResponse({
                    "error": _("You must provide an id")
                }, status=400)

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'error': error
            }, status=500)

        for frontend in policy.frontend_set.all():
            for node in frontend.get_nodes():
                node.api_request("services.rsyslogd.rsyslog.build_conf", frontend.pk)

        if DarwinBuffering.objects.filter(destination_filter__policy=policy).exists():
            DarwinPolicy.update_buffering()

        Cluster.api_request("services.darwin.darwin.write_policy_conf", policy.pk)
        Cluster.api_request("services.darwin.darwin.reload_conf")

        return build_response(policy.pk, "darwin.policy.api", COMMAND_LIST)



    @api_need_key('cluster_api_key')
    def delete(self, request, object_id=None):
        try:
            if object_id:
                try:
                    policy = DarwinPolicy.objects.get(pk=object_id)
                except DarwinPolicy.DoesNotExist:
                    return JsonResponse({
                        'error': _('Object does not exist')
                    }, status=404)

                filter_conf_paths = [obj.conf_path for obj in policy.filterpolicy_set.all()]

                try:
                    policy.delete()
                except ProtectedError as e:
                    logger.error("Error trying to delete Darwin policy '{}': policy is still being used".format(policy.name))
                    logger.exception(e)
                    return JsonResponse({
                        "error": _("Object is still used with the following objects: {}".format([str(obj) for obj in e.protected_objects]))
                    }, status=409)

                for filter_conf_path in filter_conf_paths:
                    Cluster.api_request("services.darwin.darwin.delete_filter_conf", filter_conf_path)

                for frontend in policy.frontend_set.all():
                    for node in frontend.get_nodes():
                        node.api_request("services.rsyslogd.rsyslog.build_conf", frontend.pk)

                Cluster.api_request("services.darwin.darwin.reload_conf")

            else:
                return JsonResponse({
                    "error": _("You must provide an id")
                }, status=400)

            return JsonResponse({
                'status': True
            }, status=200)

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'error': error
            }, status=500)


@method_decorator(csrf_exempt, name="dispatch")
class DarwinFilterRessourcesAPIv1(View):
    @api_need_key('cluster_api_key')
    def get(self, request, filter_type, ressource):
        glob = None
        data = []
        try:
            if filter_type == "vast":
                if ressource == "model":
                    glob = VAST_MODELS_PATH + "*.dat"
            elif filter_type == "vaml":
                if ressource == "model":
                    glob = VAML_MODELS_PATH + "*.dat"

            if glob is not None:
                data = [os_path.splitext(os_path.basename(file))[0] for file in file_glob(glob)]
            else:
                return JsonResponse({
                    'error': 'wrong ressource or filter type'
                }, status=404)
        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'error': error
            }, status=500)

        return JsonResponse({
            'data': data
        }, status=200)
