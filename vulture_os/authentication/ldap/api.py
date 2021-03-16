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
__author__ = "Olivier de Régis"
__credits__ = []
__license__ = "GPLv3"
__version__ = "3.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'LDAP API'

import logging
from django.views import View
from django.conf import settings
from django.http import JsonResponse
from authentication import ldap
from gui.decorators.apicall import api_need_key
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from authentication.ldap.models import LDAPRepository
from django.utils.translation import ugettext_lazy as _
from authentication.ldap.views import ldap_edit
from authentication.generic_delete import DeleteLDAPRepository
from authentication.ldap import tools

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api')

@method_decorator(csrf_exempt, name="dispatch")
class LDAPApi(View):
    @api_need_key('cluster_api_key')
    def get(self, request, object_id=None):
        try:
            if object_id:
                ldap_repository = LDAPRepository.objects.get(pk=object_id)
            elif request.GET.get('name'):
                ldap_repository = LDAPRepository.objects.get(name=request.GET['name'])
            else:
                ldap_repos = [ld.to_dict() for ld in LDAPRepository.objects.all()]
                return JsonResponse({
                    "data": ldap_repos
                })

            user_keys = []
            for key in tools.AVAILABLE_USER_KEYS:
                if getattr(ldap_repository, key):
                    user_keys.append(getattr(ldap_repository, key))

            group_keys = []
            for key in tools.AVAILABLE_GROUP_KEYS:
                if getattr(ldap_repository, key):
                    group_keys.append(getattr(ldap_repository, key))

            return JsonResponse({
                "available_group_keys": group_keys,
                "available_user_keys": user_keys,
                "data": ldap_repository.to_dict()
            })

        except LDAPRepository.DoesNotExist:
            return JsonResponse({
                "error": _("Object does not exist")
            }, status=404)

    @api_need_key('cluster_api_key')
    def post(self, request):
        try:
            return ldap_edit(request, None, api=True)
        
        except Exception as e:
            logger.critical(e, exc_info=1)
            if settings.DEV_MODE:
                error = str(e)
            else:
                error = _("An error has occurred")

        return JsonResponse({
            'error': error
        }, status=500) 
        
    @api_need_key('cluster_api_key')
    def put(self, request, object_id):
        try:
            return ldap_edit(request, object_id, api=True)

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'error': error
            }, status=500)

    @api_need_key('cluster_api_key')
    def delete(self, request, object_id):
        try:
            return DeleteLDAPRepository().post(request, object_id=object_id, confirm=True, api=True)

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'error': error
            }, status=500)


@method_decorator(csrf_exempt, name="dispatch")
class LDAPViewApi(View):
    @api_need_key('cluster_api_key')
    def get(self, request, object_id):
        try:
            object_type = request.GET['object_type'].lower()
            ldap_repository = LDAPRepository.objects.get(pk=object_id)

            if object_type not in ('users', 'groups'):
                raise KeyError()

            if object_type == "users":
                if request.GET.get('group_dn'):
                    group_dn = request.GET['group_dn']
                    data = tools.get_users(ldap_repository, group_dn)
                elif request.GET.get('search'):
                    search = request.GET['search']
                    data = tools.search_users(ldap_repository, search)

            elif object_type == "groups":
                data = tools.get_groups(ldap_repository)

            return JsonResponse({object_type: data})

        except LDAPRepository.DoesNotExist:
            return JsonResponse({
                "status": False,
                "error": _("Repository does not exist")
            }, status=404)

        except KeyError as err:
            logger.debug(err)
            return JsonResponse({
                "status": False,
                "error": _("Invalid call")
            }, status=400)

        except Exception as error:
            logger.critical(error, exc_info=1)
            if settings.DEV_MODE:
                raise

            return JsonResponse({
                "status": False,
                "errror": str(error)
            }, status=500)

    @api_need_key('cluster_api_key')
    def put(self, request, object_id):
        try:
            ldap_repository = LDAPRepository.objects.get(pk=object_id)
            client = ldap_repository.get_client()

            dn = request.JSON['dn']
            userPassword = request.JSON.get('userPassword')

            attributes = {}
            for key in tools.AVAILABLE_USER_KEYS:
                ldap_key = getattr(ldap_repository, key)
                if ldap_key:
                    data = request.JSON.get(ldap_key)
                    if data:
                        if isinstance(data, str):
                            data = [data]

                    attributes[ldap_key] = data

            old_objects = tools.find_user(ldap_repository, dn, ['*'])
            del(old_objects['dn'])
            ldap_response = client.update_user(dn, old_objects, attributes, userPassword)
            return JsonResponse({
                "message": _("Data saved")
            }, status=200)

        except LDAPRepository.DoesNotExist:
            return JsonResponse({
                "error": _("LDAP Repository does not exist")
            }, status=404)

        except KeyError as err:
            logger.debug(err)
            return JsonResponse({
                "status": False,
                "error": _("Invalid call")
            }, status=400)

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occured")

            if settings.DEV_MODE:
                raise

            return JsonResponse({
                "error": error
            }, status=500)

    @api_need_key('cluster_api_key')
    def post(self, request, object_id):
        try:
            ldap_repository = LDAPRepository.objects.get(pk=object_id)

            if request.JSON['object_type'].lower() == "user":
                group_dn = request.JSON['group_dn']
                tmp_user = request.JSON['user']
                userPassword = request.JSON.get('userPassword')

                # Calculate DN
                user_attr = tmp_user[ldap_repository.user_attr]

                attrs = {}
                for attribute in ('user_account_locked_attr', 'user_change_password_attr', 'user_mobile_attr', 'user_email_attr'):
                    ldap_attr = getattr(ldap_repository, attribute)
                    if ldap_attr and tmp_user.get(ldap_attr):
                        attrs[ldap_attr] = [tmp_user[ldap_attr]]

                ldap_response = tools.create_user(ldap_repository, group_dn, user_attr, userPassword, attrs)

            elif request.JSON['object_type'].lower() == "group":
                group_name = request.JSON['group_name']
                members = request.JSON['member']
                status, ldap_response = tools.create_group(ldap_repository, group_name, members)
                if not status:
                    return JsonResponse({
                        "status": False,
                        "error": ldap_response
                    }, status=400)

            return JsonResponse({
                "status": True
            }, status=201)

        except KeyError as err:
            logger.debug(err)
            return JsonResponse({
                "status": False,
                "error": _("Invalid call")
            }, status=400)

        except LDAPRepository.DoesNotExist:
            return JsonResponse({
                "error": _("LDAP Repository does not exist")
            }, status=404)

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occured")
            if settings.DEV_MODE:
                raise

            return JsonResponse({
                "error": error
            }, status=500)

    @api_need_key('cluster_api_key')
    def delete(self, request, object_id):
        try:
            ldap_repository = LDAPRepository.objects.get(pk=object_id)
            dn = request.JSON['dn']
            client = ldap_repository.get_client()
            groups = [tools.find_group(ldap_repository, group_dn, ["*"]) for group_dn in client.search_user_groups_by_dn(dn)]
            client.delete_user(dn, groups)
            return JsonResponse({
                "status": True
            })

        except KeyError as err:
            logger.debug(err)
            return JsonResponse({
                "status": False,
                "error": _("Invalid call")
            }, status=400)

        except LDAPRepository.DoesNotExist:
            return JsonResponse({
                "error": _("LDAP Repository does not exist")
            }, status=404)

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occured")

            if settings.DEV_MODE:
                raise

            return JsonResponse({
                "error": error
            }, status=500)
