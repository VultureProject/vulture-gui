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
from darwin.policy.models import DarwinPolicy, FilterPolicy, DarwinFilter, DGA_MODELS_PATH, validate_connection_config, validate_content_inspection_config, validate_dga_config
from darwin.policy.views import policy_edit, COMMAND_LIST
from system.cluster.models import Cluster, Node
from services.frontend.models import Frontend
from toolkit.api.responses import build_response


# Extern modules imports
from sys import exc_info
from pymongo.errors import DuplicateKeyError
from glob import glob as file_glob

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api')


@method_decorator(csrf_exempt, name="dispatch")
class DarwinFilterAPIv1(View):

    @staticmethod
    def get_available_dga_models():
        """
            Gets the list of available models and token maps for the DGA filter.
            The files are returned without path, and should be given as-is during POST/PUT operations in policies
        """
        result = {}
        result['models'] = []
        result['tokens'] = []
        for file in file_glob(DGA_MODELS_PATH + "*.pb"):
            result['models'].append(file.split('/')[-1])
        for file in file_glob(DGA_MODELS_PATH + "*.csv"):
            result['tokens'].append(file.split('/')[-1])

        return result

    @api_need_key('cluster_api_key')
    def get(self, request, filter_name=None):
        data = {}
        try:
            if not filter_name:
                return JsonResponse({
                    'error': _('you must specify a filter name')
                }, status=401)
            else:
                try:
                    darwin_filter = DarwinFilter.objects.filter(name=filter_name).get()
                    data = darwin_filter.to_dict()
                except DarwinFilter.DoesNotExist:
                    return JsonResponse({
                        'error': _("filter name '{}' does not exist".format(filter_name))
                    }, status=404)

                # There could be calls to get lists of available files for other filters
                if filter_name == "dga":
                    data.update(DarwinFilterAPIv1.get_available_dga_models())

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
    def create_filters(policy, filters_list):
        new_filters = []

        for filt in filters_list:
            try:
                filter_name = filt.pop('name', '')
                darwin_filter = DarwinFilter.objects.get(name=filter_name)
            except DarwinFilter.DoesNotExist:
                logger.error("Error while creating filters for darwin policy : filter '{}' does not exist".format(filter_name))
                return "{} is not a valid filter".format(filter_name)

            try:
                filter_instance = FilterPolicy(
                    **filt,
                    policy=policy,
                    filter=darwin_filter,
                    status={node.name: "WAITING" for node in Node.objects.all().only('name')}
                )

                filter_instance.full_clean()
                new_filters.append(filter_instance)

            except (ValidationError, ValueError) as e:
                logger.error(e)
                return '"{}": {}'.format(filter_name, str(e))

        # At this point everything has been validated
        # So the old filters can be deleted safely
        filters_delete = FilterPolicy.objects.filter(policy_id=policy.pk)
        for filter_delete in filters_delete:
            Cluster.api_request("services.darwin.darwin.delete_filter_conf", filter_delete.conf_path)
            filter_delete.delete()
        # And the new ones can be inserted in their place
        for filter_instance in new_filters:
            filter_instance.save()

        return ""


    @api_need_key('cluster_api_key')
    def post(self, request, object_id=None, action=None):
        new_filters = []
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
                filters_list = request.JSON.pop('filters', [])
                policy = DarwinPolicy(
                    name=request.JSON.get("name", ""),
                    description=request.JSON.get("description", ""))

                try:
                    policy.full_clean()
                    policy.save()
                except ValidationError as e:
                    logger.error(e)
                    return JsonResponse({
                        'error': str(e),
                    }, status=400)

                error = DarwinPolicyAPIv1.create_filters(policy, filters_list)
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

        for frontend in policy.frontend_set.all():
            for node in frontend.get_nodes():
                node.api_request("services.rsyslogd.rsyslog.build_conf", frontend.pk)
        Cluster.api_request("services.darwin.darwin.write_policy_conf", policy.pk)
        Cluster.api_request("services.darwin.darwin.build_conf")

        return build_response(policy.pk, "darwin.policy.api", COMMAND_LIST)


    @api_need_key('cluster_api_key')
    def put(self, request, object_id=None):
        try:
            if object_id:
                filters = request.JSON.pop('filters', [])
                policy, created = DarwinPolicy.objects.get_or_create(pk=object_id)

                policy.name = request.JSON.get('name', "")
                policy.description = request.JSON.get('description', "")

                try:
                    policy.full_clean()
                except ValidationError as e:
                    logger.error(e)
                    return JsonResponse({
                        'error': str(e),
                    }, status=400)

                error = DarwinPolicyAPIv1.create_filters(policy, filters)
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
        Cluster.api_request("services.darwin.darwin.write_policy_conf", policy.pk)
        Cluster.api_request("services.darwin.darwin.build_conf")

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
                Cluster.api_request("services.darwin.darwin.build_conf")

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