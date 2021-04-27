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
__doc__ = 'IDP API'

import logging
from django.views import View
from django.conf import settings
from authentication.ldap import tools
from django.http import JsonResponse
from gui.decorators.apicall import api_need_key
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.utils.translation import ugettext_lazy as _
from authentication.user_portal.models import UserAuthentication
from authentication.ldap.tools import NotUniqueError, UserNotExistError
from toolkit.portal.registration import perform_email_registration, perform_email_reset


logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api')


def get_repo(portal):
    ldap_repo = None
    for repo in portal.repositories.all():
        if repo.subtype == "LDAP":
            ldap_repo = repo.get_daughter()
            break

    if not ldap_repo:
        # The portal does not have a LDAP repository
        raise UserAuthentication.DoesNotExist()

    return ldap_repo


@method_decorator(csrf_exempt, name="dispatch")
class IDPApiView(View):
    @api_need_key("cluster_api_key")
    def get(self, request, object_id):
        try:
            portal = UserAuthentication.objects.get(pk=object_id)
            ldap_repo = get_repo(portal)

            object_type = request.GET["object_type"].lower()
            if object_type not in ("users", "search"):
                raise KeyError()

            if object_type == "users":
                data = []
                group_name = f"{ldap_repo.group_attr}={portal.group_registration}"
                tmp_data = tools.get_users(ldap_repo, group_name)

                for tmp in tmp_data:
                    tmp_user = {
                        "username": tmp[ldap_repo.user_attr][0]
                    }

                    try:
                        tmp_user["is_locked"] = ""
                        if ldap_repo.user_account_locked_attr and tmp.get(ldap_repo.get_user_account_locked_attr):
                            tmp_user["is_locked"] = tmp[ldap_repo.get_user_account_locked_attr][0]
                    except IndexError:
                        pass
 
                    try:
                        tmp_user["need_change_password"] = ""
                        if ldap_repo.user_change_password_attr and tmp.get(ldap_repo.get_user_change_password_attr):
                            tmp_user["need_change_password"] = tmp[ldap_repo.get_user_change_password_attr][0]
                    except IndexError:
                        pass

                    try:
                        tmp_user["mobile"] = ""
                        if ldap_repo.user_mobile_attr:
                            tmp_user["mobile"] = tmp[ldap_repo.user_mobile_attr][0]
                    except IndexError:
                        pass

                    try:
                        tmp_user["smartcardid"] = ""
                        if ldap_repo.user_smartcardid_attr:
                            tmp_user["smartcardid"] = tmp[ldap_repo.user_smartcardid_attr][0]
                    except IndexError:
                        pass
                    
                    try:
                        tmp_user["email"] = ""
                        if ldap_repo.user_email_attr:
                            tmp_user["email"] = tmp[ldap_repo.user_email_attr][0]
                    except IndexError:
                        pass

                    data.append(tmp_user)

                return JsonResponse({
                    "data": data
                })

            elif object_type == "search":
                search_str = request.GET['search']
                data = tools.search_users(ldap_repo, search_str)
                return JsonResponse({
                    "data": data
                })

        except KeyError as err:
            logger.debug(err)
            return JsonResponse({
                "status": False,
                "error": _("Invalid call")
            }, status=400)

        except UserAuthentication.DoesNotExist:
            return JsonResponse({
                "status": False,
                "error": _("Portal does not exist")
            }, status=404)
        except Exception as err:
            logger.critical(err, exc_info=1)
            if settings.DEV_MODE:
                raise

            return JsonResponse({
                "status": False,
                "error": str(err)
            }, status=500)

@method_decorator(csrf_exempt, name="dispatch")
class IDPApiUserView(View):
    @api_need_key('cluster_api_key')
    def post(self, request, object_id, action=None):
        try:
            portal = UserAuthentication.objects.get(pk=object_id)
            ldap_repo = get_repo(portal)

            if action and action not in ("resend_registration", "reset_password", "lock", "unlock"):
                return JsonResponse({
                    "status": False,
                    "error": _("Invalid action")
                }, status=400)

            elif not action:
                user = {
                    ldap_repo.user_attr: request.JSON['username']
                }

                attrs = {}
                if ldap_repo.user_account_locked_attr:
                    attr = ldap_repo.get_user_account_locked_attr
                    attrs[attr] = request.JSON.get('is_locked')

                if ldap_repo.user_change_password_attr:
                    attr = ldap_repo.get_user_change_password_attr
                    attrs[attr] = request.JSON.get('need_change_password')

                if ldap_repo.user_mobile_attr:
                    attrs[ldap_repo.user_mobile_attr] = request.JSON.get('mobile')

                if ldap_repo.user_smartcardid_attr:
                    attrs[ldap_repo.user_smartcardid_attr] = request.JSON.get('smartcardid')

                if ldap_repo.user_email_attr:
                    attrs[ldap_repo.user_email_attr] = request.JSON.get('email')

                group_name = None
                if portal.update_group_registration:
                    group_name = f"{ldap_repo.group_attr}={portal.group_registration}"

                ldap_response, user_id = tools.create_user(ldap_repo, user[ldap_repo.user_attr],
                                                           request.JSON.get('userPassword'), attrs, group_name)

            if not action or action == "resend_registration":
                if not perform_email_registration(logger,
                                        f"https://{portal.external_fqdn}",
                                        portal.name,
                                        portal.portal_template,
                                        request.JSON['email'],
                                        expire=72 * 3600):
                    return JsonResponse({'status': False,
                                         'error': _("Fail to send user's registration email")}, status=500)

            elif action == "reset_password":
                perform_email_reset(logger,
                                 f"https://{portal.external_fqdn}",
                                 portal.name,
                                 portal.portal_template,
                                 request.JSON['email'],
                                 expire=3600)
                return JsonResponse({'status': False,
                                     'error': _("Fail to send user's reset password email")}, status=500)

            elif action in ("lock", "unlock"):
                username = request.JSON["username"]
                to_lock = action == "lock"
                ldap_response, user_id = tools.lock_unlock_user(ldap_repo, username, lock=to_lock)
                return JsonResponse({
                    "status": True,
                    "user_id": user_id
                })

            return JsonResponse({
                "status": True,
                "user_id": user_id
            }, status=201)
        except KeyError as err:
            logger.debug(err)
            return JsonResponse({
                "status": False,
                "error": _("Invalid call")
            }, status=400)

        except NotUniqueError:
            return JsonResponse({
                "status": False,
                "error": _("User already exist")
            }, status=409)
        except UserAuthentication.DoesNotExist:
            return JsonResponse({
                "status": False,
                "error": _("Portal does not exist")
            }, status=404)
        except Exception as err:
            logger.critical(err, exc_info=1)
            if settings.DEV_MODE:
                raise

            return JsonResponse({
                "status": False,
                "error": str(err)
            }, status=500)

    @api_need_key('cluster_api_key')
    def put(self, request, object_id):
        try:
            portal = UserAuthentication.objects.get(pk=object_id)
            ldap_repo = get_repo(portal)

            username = request.JSON['username']

            attrs = {
                ldap_repo.user_attr: [username]
            }

            if ldap_repo.user_email_attr:
                attrs[ldap_repo.user_email_attr] = request.JSON.get('email')
            
            if ldap_repo.user_account_locked_attr:
                attr = ldap_repo.get_user_account_locked_attr
                attrs[attr] = request.JSON.get('is_locked')
            
            if ldap_repo.user_change_password_attr:
                attr = ldap_repo.get_user_change_password_attr
                attrs[attr] = request.JSON.get('need_change_password')
            
            if ldap_repo.user_mobile_attr:
                attrs[ldap_repo.user_mobile_attr] = request.JSON.get('mobile')

            if ldap_repo.user_smartcardid_attr:
                attrs[ldap_repo.user_smartcardid_attr] = request.JSON.get('smartcardid')

            status, user_dn = tools.update_user(ldap_repo, username, attrs, request.JSON.get('userPassword'))
            if status is False:
                return JsonResponse({
                    "status": False,
                    "error": _("User not found")
                }, status=404)

            return JsonResponse({
                "status": True,
                "user_id": user_dn
            })
        except KeyError as err:
            logger.debug(err)
            return JsonResponse({
                "status": False,
                "error": _("Invalid call")
            }, status=400)

        except UserAuthentication.DoesNotExist:
            return JsonResponse({
                "status": False,
                "error": _("Portal does not exist")
            }, status=404)
        except Exception as err:
            logger.critical(err, exc_info=1)
            if settings.DEV_MODE:
                raise

            return JsonResponse({
                "status": False,
                "error": str(err)
            }, status=500)

    @api_need_key('cluster_api_key')
    def delete(self, request, object_id):
        try:
            portal = UserAuthentication.objects.get(pk=object_id)
            ldap_repo = get_repo(portal)

            username = request.JSON['username']

            status = tools.delete_user(ldap_repo, username)
            if status is False:
                return JsonResponse({
                    "status": False,
                    "error": _("User not found")
                }, status=404)

            return JsonResponse({
                "status": True
            })

        except UserNotExistError:
            return JsonResponse({
                "status": False,
                "error": _("User not found")
            }, status=404)

        except KeyError as err:
            logger.debug(err)
            return JsonResponse({
                "status": False,
                "error": _("Invalid call")
            }, status=400)

        except UserAuthentication.DoesNotExist:
            return JsonResponse({
                "status": False,
                "error": _("Portal does not exist")
            }, status=404)
        except Exception as err:
            logger.critical(err, exc_info=1)
            if settings.DEV_MODE:
                raise

            return JsonResponse({
                "status": False,
                "error": str(err)
            }, status=500)
