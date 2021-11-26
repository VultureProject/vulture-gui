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
from authentication.totp_profiles.models import TOTPProfile
from authentication.ldap.tools import NotUniqueError, UserNotExistError
from authentication.idp.attr_tools import MAPPING_ATTRIBUTES
from toolkit.portal.registration import perform_email_registration, perform_email_reset
from toolkit.network.smtp import test_smtp_server

from system.cluster.models import Cluster


logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api')


def get_repo(portal, repo_id):
    return portal.repositories.get(subtype="LDAP", pk=repo_id).get_daughter()


@method_decorator(csrf_exempt, name="dispatch")
class IDPApiView(View):
    @api_need_key("cluster_api_key")
    def get(self, request, portal_id, repo_id):
        try:
            portal = UserAuthentication.objects.get(pk=portal_id)
            ldap_repo = get_repo(portal, repo_id)

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
                        tmp_user["email"] = ""
                        if ldap_repo.user_email_attr:
                            tmp_user["email"] = tmp[ldap_repo.user_email_attr][0]
                    except IndexError:
                        pass

                    for key, value in MAPPING_ATTRIBUTES.items():
                        if value["type"] == str:
                            try:
                                tmp_user[key] = tmp.get(value["internal_key"], [])[0]
                            except (IndexError, TypeError):
                                tmp_user[key] = ""
                        
                        elif value["type"] == list:
                            tmp_user[key] = tmp.get(value["internal_key"], [])

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
            logger.error(err)
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
    def post(self, request, portal_id, repo_id, action=None):
        try:
            portal = UserAuthentication.objects.get(pk=portal_id)
            ldap_repo = get_repo(portal, repo_id)

            if action and action not in ("resend_registration", "reset_password", "lock", "unlock", "reset_otp"):
                return JsonResponse({
                    "status": False,
                    "error": _("Invalid action")
                }, status=400)

            elif not action:
                config = Cluster.get_global_config()
                assert config.smtp_server, "SMTP server is not properly configured."
                try:
                    # This method simply raises if an error occur
                    test_smtp_server(config.smtp_server), "SMTP server seems to be unavailable."
                except Exception as e:
                    raise Exception("SMTP server is not properly configured: {}".format(str(e)))

                user = request.JSON['username']

                attrs = {}
                if ldap_repo.user_account_locked_attr:
                    attr = ldap_repo.get_user_account_locked_attr
                    attrs[attr] = request.JSON.get('is_locked')

                if ldap_repo.user_change_password_attr:
                    attr = ldap_repo.get_user_change_password_attr
                    attrs[attr] = request.JSON.get('need_change_password')

                if ldap_repo.user_mobile_attr:
                    attrs[ldap_repo.user_mobile_attr] = request.JSON.get('mobile')

                if ldap_repo.user_email_attr:
                    attrs[ldap_repo.user_email_attr] = request.JSON.get('email')

                # Variable needed to send user's registration
                user_mail = request.JSON.get('email')

                for key, value in MAPPING_ATTRIBUTES.items():
                    attrs[value["internal_key"]] = request.JSON.get(key)

                group_name = None
                if portal.update_group_registration:
                    group_name = f"{ldap_repo.group_attr}={portal.group_registration}"

                ldap_response, user_id = tools.create_user(
                    ldap_repo, user, request.JSON.get('userPassword'),
                    attrs, group_name
                )
            else:
                # We get an action
                # !! If we get a DN, extract username to search in LDAP configured scope (for segregation regards) !!
                user = request.JSON['id']
                if "," in user:
                    user = user.split(",")[0]
                if "=" in user:
                    user = user.split('=')[1]
                # We will need user' email for registration and reset
                user_id, user_mail = tools.find_user_email(ldap_repo, user)
                logger.info(f"User's email found : {user_mail}")


            if not action or action == "resend_registration":
                if not perform_email_registration(logger,
                                        f"https://{portal.external_fqdn}/",
                                        portal.name,
                                        portal.portal_template,
                                        user_mail,
                                        user,
                                        repo_id=repo_id,
                                        expire=72 * 3600):
                    logger.error(f"Failed to send registration email to '{user_mail}'")
                    return JsonResponse({'status': False,
                                         'error': _("Fail to send user's registration email")}, status=500)
                else:
                    logger.info(f"Registration email re-sent to '{user_mail}'")

            elif action == "reset_password":
                if not perform_email_reset(logger,
                                 f"https://{portal.external_fqdn}/",
                                 portal.name,
                                 portal.portal_template,
                                 user_mail,
                                 user,
                                 repo_id=repo_id,
                                 expire=3600):
                    logger.error(f"Failed to send reset password email to '{user_mail}'")
                    return JsonResponse({'status': False,
                                         'error': _("Fail to send user's reset password email")}, status=500)
                else:
                    logger.info(f"Reset password email sent to '{user_mail}'")

            elif action == "reset_otp":
                try:
                    if not portal.otp_repository:
                        logger.error(f"IDP::Reset_otp: TOTP not configured for portal {portal}")
                        return JsonResponse({'status': False, 'error': _("TOTP not configured on portal")})
                    otp_profile = TOTPProfile.objects.get(auth_repository=ldap_repo,
                                                          totp_repository=portal.otp_repository,
                                                          login=user)
                    otp_profile.delete()
                except TOTPProfile.DoesNotExist:
                    logger.error(f"TOTP Profile not found for repo='{ldap_repo}', "
                                 f"otp_repo='{portal.otp_repository}', user='{user}'")
                    return JsonResponse({'status': False,'error': _("TOTP Profile not found")}, status=404)
                except Exception as e:
                    logger.exception(e)
                    logger.error(f"Failed to reset otp for user '{user}'")
                    return JsonResponse({'status': False,
                                         'error': _("Fail to reset otp")}, status=500)
                else:
                    logger.info(f"Reset otp done for '{user}'")

            elif action in ("lock", "unlock"):
                user_dn = request.JSON["id"]
                # Check if a proper filter was configured in GUI before trying to lock
                if ldap_repo.user_account_locked_attr and ldap_repo.get_user_account_locked_attr:
                    to_lock = action == "lock"
                    ldap_response, user_id = tools.lock_unlock_user(ldap_repo, user_dn, lock=to_lock)
                else:
                    logger.error(f"Cannot lock user '{user_dn}' on repository '{ldap_repo}': no locking filter configured")
                    return JsonResponse({
                        "status": False,
                        "error": _("Lock unavailable for Repository")
                    }, status=409)


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

        except NotUniqueError as e:
            return JsonResponse({
                "status": False,
                "error": _("User already exist"),
                "user_id": str(e)
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
    def put(self, request, portal_id, repo_id):
        try:
            portal = UserAuthentication.objects.get(pk=portal_id)
            ldap_repo = get_repo(portal, repo_id)

            user_dn = request.JSON['id']

            attrs = {
                ldap_repo.user_attr: request.JSON["username"]
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
            
            for key, value in MAPPING_ATTRIBUTES.items():
                attrs[value["internal_key"]] = request.JSON.get(key)

            status, user_dn = tools.update_user(ldap_repo, user_dn, attrs, request.JSON.get('userPassword'))
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
    def delete(self, request, portal_id, repo_id):
        try:
            portal = UserAuthentication.objects.get(pk=portal_id)
            ldap_repo = get_repo(portal, repo_id)

            user_dn = request.JSON['id']

            status = tools.delete_user(ldap_repo, user_dn)
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
