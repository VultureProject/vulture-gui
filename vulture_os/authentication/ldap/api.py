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
from gui.decorators.apicall import api_need_key
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from authentication.ldap.models import LDAPRepository
from django.utils.translation import ugettext_lazy as _

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api')


AVAILABLE_GROUP_KEYS = ("group_attr",)
AVAILABLE_USER_KEYS = ("user_attr", "user_account_locked_attr", "user_change_password_attr", "user_mobile_attr", "user_email_attr")

def find_user(ldap_repo, user_dn, attr_list):
    client = ldap_repo.get_client()
    user = client.search_by_dn(user_dn, attr_list=attr_list)

    dn, attrs = user[0]
    user = {"dn": dn}

    for key in AVAILABLE_USER_KEYS:
        ldap_key = getattr(ldap_repo, key)
        if ldap_key:
            user[ldap_key] = attrs.get(ldap_key, "")

    return user

def find_group(ldap_repo, group_dn, attr_list):
    client = ldap_repo.get_client()
    group = client.search_by_dn(group_dn, attr_list=attr_list)

    dn, attrs = group[0]
    group = {"dn": dn}

    for key in AVAILABLE_GROUP_KEYS:
        ldap_key = getattr(ldap_repo, key)
        if ldap_key:
            group[ldap_key] = attrs[ldap_key]

    group[ldap_repo.group_member_attr] = attrs[ldap_repo.group_member_attr]
    return group

@method_decorator(csrf_exempt, name="dispatch")
class LDAPApi(View):
    @api_need_key('cluster_api_key')
    def get(self, request, object_id):
        try:
            ldap_repository = LDAPRepository.objects.get(pk=object_id)
            client = ldap_repository.get_client()

            user_keys = []
            for key in AVAILABLE_USER_KEYS:
                if getattr(ldap_repository, key):
                    user_keys.append(getattr(ldap_repository, key))

            group_keys = []
            for key in AVAILABLE_GROUP_KEYS:
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
            }, status=400)


@method_decorator(csrf_exempt, name="dispatch")
class LDAPViewApi(View):
    @api_need_key('cluster_api_key')
    def get(self, request, object_id):
        try:
            object_type = request.GET.get('object_type', 'all')
            ldap_repository = LDAPRepository.objects.get(pk=object_id)
            client = ldap_repository.get_client()


            if object_type.lower() == "users":
                group_dn = request.GET.get('group_dn')
                if group_dn:
                    group = find_group(ldap_repository, group_dn, ['*'])
                    members  = []
                    for member_dn in group['member']:
                        members.append(find_user(ldap_repository, member_dn, ["*"]))

                    data = members

            elif object_type.lower() == "groups":
                group_base_dn = f"{ldap_repository.group_dn},{ldap_repository.base_dn}"
                
                data = []
                for group_dn in client.enumerate_groups():
                    if group_base_dn not in group_dn:
                        continue

                    group = find_group(ldap_repository, group_dn, ['*'])
                    data.append(group)

            return JsonResponse({object_type: data})

        except LDAPRepository.DoesNotExist:
            return JsonResponse({
                "status": False,
                "error": _("Repository does not exist")
            }, status=404)
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

            if userPassword:
                attributes['userPassword'] = [userPassword]

            for key in AVAILABLE_USER_KEYS:
                ldap_key = getattr(ldap_repository, key)
                if ldap_key:
                    data = request.JSON.get(ldap_key)
                    if data:
                        if isinstance(data, str):
                            data = [data]

                    attributes[ldap_key] = data

            old_objects = find_user(ldap_repository, dn, ['*'])
            del(old_objects['dn'])
            ldap_response = client.update_user(dn, old_objects, attributes)
            return JsonResponse({
                "message": _("Data saved")
            }, status=200)

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
    def post(self, request, object_id):
        try:
            ldap_repository = LDAPRepository.objects.get(pk=object_id)
            client = ldap_repository.get_client()

            group_dn = request.JSON['group_dn']
            tmp_user = request.JSON['user']
            userPassword = request.JSON.get('userPassword', '')
 
            # Calculate DN
            user_attr = tmp_user[ldap_repository.user_attr]
            dn = f"{ldap_repository.user_attr}={user_attr},{group_dn}"
            user = {
                "sn": [user_attr],
                "cn": [user_attr],
                "userPassword": [userPassword],
                ldap_repository.user_attr: [user_attr],
                "objectClass": ["inetOrgPerson", "top"],
                "description": ["User created by Vulture"],
            }

            for k, v in tmp_user.items():
                user[k] = [v]

            ldap_response = client.add_user(dn, user, group_dn)
            return JsonResponse({
                "status": True
            }, status=201)
        
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
            dn = request.JSON.get('dn')
            client = ldap_repository.get_client()
            groups = [find_group(ldap_repository, group_dn, ["*"]) for group_dn in client.search_user_groups_by_dn(dn)]
            client.delete_user(dn, groups)
            return JsonResponse({
                "status": True
            })
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