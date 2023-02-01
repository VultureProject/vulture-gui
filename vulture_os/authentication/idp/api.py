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
from authentication.idp.authentication import api_check_authorization
from base64 import urlsafe_b64decode
from datetime import datetime, timedelta
from django.views import View
from django.conf import settings
from authentication.ldap import tools
from django.http import JsonResponse
from gui.decorators.apicall import api_need_key
from django.utils import timezone
from django.utils.decorators import method_decorator
from django.views.decorators.csrf import csrf_exempt
from django.utils.translation import ugettext_lazy as _
from authentication.base_repository import BaseRepository
from authentication.user_portal.models import UserAuthentication
from authentication.totp_profiles.models import TOTPProfile
from authentication.ldap.tools import NotUniqueError, UserDoesntExistError, GroupDoesntExistError
from authentication.idp.attr_tools import MAPPING_ATTRIBUTES
from oauth2.tokengenerator import Uuid4
from portal.system.redis_sessions import REDISOauth2Session, REDISBase
from toolkit.portal.registration import perform_email_registration, perform_email_reset
from toolkit.network.smtp import test_smtp_server
from uuid import UUID

from system.cluster.models import Cluster


logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api')


def get_repo_by_id(portal, repo_id):
    return portal.repositories.get(subtype="LDAP", pk=repo_id).get_daughter()

def get_repo_by_name(portal, repo_name):
    return portal.repositories.get(subtype="LDAP", name=repo_name).get_daughter()


class ActionForbiddenException(Exception):
    def __init__(self, message="Forbidden"):
        self.message = message
        super().__init__(self.message)


@method_decorator(csrf_exempt, name="dispatch")
class IDPApiView(View):
    @api_need_key("cluster_api_key")
    def get(self, request, portal_id=None, repo_id=None, portal_name=None, repo_name=None):
        try:
            if portal_id:
                portal = UserAuthentication.objects.get(pk=portal_id)
            elif portal_name:
                portal = UserAuthentication.objects.get(name=portal_name)
            else:
                raise ValueError("Need a portal id or name to scope token on")

            if repo_id:
                ldap_repo = get_repo_by_id(portal, repo_id)
            elif repo_name:
                ldap_repo = get_repo_by_name(portal, repo_name)
            else:
                raise ValueError("Need a repo id or name to scope token on")

            object_type = request.GET["object_type"].lower()
            if object_type not in ("users", "search"):
                raise KeyError()

            if object_type == "users":
                data = []
                group_name = f"{ldap_repo.group_attr}={portal.group_registration}"
                tmp_data = tools.get_users_in_group(ldap_repo, group_name)

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

        except ValueError as e:
            return JsonResponse({
                "status": False,
                "error": _(str(e))
            }, status=400)

        except UserAuthentication.DoesNotExist:
            return JsonResponse({
                "status": False,
                "error": _("Portal does not exist")
            }, status=404)

        except GroupDoesntExistError:
            return JsonResponse({
                "status": True,
                "data": {}
            }, status=204)

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
    def post(self, request, portal_id=None, repo_id=None, portal_name=None, repo_name=None, action=None):
        try:
            if portal_id:
                portal = UserAuthentication.objects.get(pk=portal_id)
            elif portal_name:
                portal = UserAuthentication.objects.get(name=portal_name)
            else:
                raise ValueError("Need a portal id or name to scope token on")

            if repo_id:
                ldap_repo = get_repo_by_id(portal, repo_id)
            elif repo_name:
                ldap_repo = get_repo_by_name(portal, repo_name)
            else:
                raise ValueError("Need a repo id or name to scope token on")

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

                logger.info(f"IDPApiUserView::POST:[{portal.name}/{ldap_repo}] Creating user {user} with attributes {attrs}")

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
                logger.info(f"IDPApiUserView::POST:[{portal.name}/{ldap_repo}] User's email found : {user_mail}")


            if not action or action == "resend_registration":
                if not perform_email_registration(logger,
                                        f"https://{portal.external_fqdn}/",
                                        portal.name,
                                        portal.portal_template,
                                        user_mail,
                                        user,
                                        repo_id=repo_id,
                                        expire=72 * 3600):
                    logger.error(f"IDPApiUserView::POST:[{portal.name}/{ldap_repo}] Failed to send registration email to '{user_mail}'")
                    return JsonResponse({'status': False,
                                         'error': _("Fail to send user's registration email")}, status=500)
                else:
                    logger.info(f"IDPApiUserView::POST:[{portal.name}/{ldap_repo}] Registration email sent to '{user_mail}' (user {user})")

            elif action == "reset_password":
                if not perform_email_reset(logger,
                                 f"https://{portal.external_fqdn}/",
                                 portal.name,
                                 portal.portal_template,
                                 user_mail,
                                 user,
                                 repo_id=repo_id,
                                 expire=72 * 3600):
                    logger.error(f"IDPApiUserView::POST:[{portal.name}/{ldap_repo}] Failed to send reset password email to '{user_mail}'")
                    return JsonResponse({'status': False,
                                         'error': _("Fail to send user's reset password email")}, status=500)
                else:
                    logger.info(f"IDPApiUserView::POST:[{portal.name}/{ldap_repo}] Reset password email sent to '{user_mail}' (user {user})")

            elif action == "reset_otp":
                try:
                    if not portal.otp_repository:
                        logger.error(f"IDPApiUserView::POST:[{portal.name}/{ldap_repo}] TOTP not configured for portal")
                        return JsonResponse({'status': False, 'error': _("TOTP not configured on portal")}, status=400)
                    otp_profile = TOTPProfile.objects.get(auth_repository=ldap_repo,
                                                          totp_repository=portal.otp_repository,
                                                          login=user)
                    otp_profile.delete()
                except TOTPProfile.DoesNotExist:
                    logger.error(f"IDPApiUserView::POST:[{portal.name}/{ldap_repo}] TOTP Profile not found for "
                                 f"otp_repo='{portal.otp_repository}', user='{user}'")
                    return JsonResponse({'status': False,'error': _("TOTP Profile not found")}, status=404)
                except Exception as e:
                    logger.exception(e)
                    logger.error(f"IDPApiUserView::POST:[{portal.name}/{ldap_repo}] Failed to reset otp for user '{user}'")
                    return JsonResponse({'status': False,
                                         'error': _("Fail to reset otp")}, status=500)
                else:
                    logger.info(f"IDPApiUserView::POST:[{portal.name}/{ldap_repo}] TOTP reset for '{user}'")

            elif action in ("lock", "unlock"):
                user_dn = request.JSON["id"]
                # Check if a proper filter was configured in GUI before trying to lock
                if ldap_repo.user_account_locked_attr and ldap_repo.get_user_account_locked_attr:
                    to_lock = action == "lock"
                    ldap_response, user_id = tools.lock_unlock_user(ldap_repo, user_dn, lock=to_lock)
                    logger.info(f"IDPApiUserView::POST:[{portal.name}/{ldap_repo}] user '{user}' {'locked' if to_lock else 'unlocked'}")
                else:
                    logger.error(f"IDPApiUserView::POST:[{portal.name}/{ldap_repo}] Cannot lock user '{user_dn}': no locking filter configured")
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

        except ValueError as e:
            return JsonResponse({
                "status": False,
                "error": _(str(e))
            }, status=400)

        except NotUniqueError as e:
            return JsonResponse({
                "status": False,
                "error": _("User already exists"),
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
    def put(self, request, portal_id=None, repo_id=None, portal_name=None, repo_name=None):
        try:
            if portal_id:
                portal = UserAuthentication.objects.get(pk=portal_id)
            elif portal_name:
                portal = UserAuthentication.objects.get(name=portal_name)
            else:
                raise ValueError("Need a portal id or name to scope token on")

            if repo_id:
                ldap_repo = get_repo_by_id(portal, repo_id)
            elif repo_name:
                ldap_repo = get_repo_by_name(portal, repo_name)
            else:
                raise ValueError("Need a repo id or name to scope token on")

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

            logger.info(f"IDPApiUserView::PUT::[{portal.name}/{ldap_repo}] Changing user {user_dn} with new attributes {attrs}")

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

        except AssertionError as err:
            logger.debug(err)
            return JsonResponse({
                "status": False,
                "error": _(str(err))
            }, status=409)

        except KeyError as err:
            logger.debug(err)
            return JsonResponse({
                "status": False,
                "error": _("Invalid call")
            }, status=400)

        except ValueError as e:
            return JsonResponse({
                "status": False,
                "error": _(str(e))
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
    def delete(self, request, portal_id=None, repo_id=None, portal_name=None, repo_name=None):
        try:
            if portal_id:
                portal = UserAuthentication.objects.get(pk=portal_id)
            elif portal_name:
                portal = UserAuthentication.objects.get(name=portal_name)
            else:
                raise ValueError("Need a portal id or name to scope token on")

            if repo_id:
                ldap_repo = get_repo_by_id(portal, repo_id)
            elif repo_name:
                ldap_repo = get_repo_by_name(portal, repo_name)
            else:
                raise ValueError("Need a repo id or name to scope token on")
            redis_handler = REDISBase()

            user_dn = request.JSON['id']
            logger.info(f"IDPApiUserView::DELETE::[{portal.name}/{ldap_repo}] Request to remove user {user_dn}")

            status = tools.delete_user(ldap_repo, user_dn)
            if status is False:
                return JsonResponse({
                    "status": False,
                    "error": _("User not found")
                }, status=404)
            logger.info(f"IDPApiUserView::DELETE::[{portal.name}/{ldap_repo}] Removed user {user_dn}")

            # Search and remove all related oauth2 tokens
            logger.info(f"IDPApiUserView::DELETE::[{portal.name}/{ldap_repo}] Removing user {user_dn} related oauth tokens")
            all_tokens = redis_handler.scan_all("oauth2_*", type="hash")
            for token in all_tokens:
                repo = redis_handler.hget(token, "repo")
                sub = redis_handler.hget(token, "sub")

                if repo == portal.oauth_client_id and sub == user_dn:
                    logger.info(f"IDPApiUserView::DELETE::[{portal.name}/{ldap_repo}] Removing oauth token {token} from deleted user {user_dn}")
                    redis_handler.delete(token)
                    redis_handler.delete(f"{token}_{repo}")

            return JsonResponse({
                "status": True
            })

        except UserDoesntExistError:
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

        except ValueError as e:
            return JsonResponse({
                "status": False,
                "error": _(str(e))
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


def _validate_request(request, user_b64, portal_id=None, repo_id=None, portal_name=None, repo_name=None, token_key=None):
    # parameters
    if portal_id:
        portal = UserAuthentication.objects.get(pk=portal_id)
    elif portal_name:
        portal = UserAuthentication.objects.get(name=portal_name)
    else:
        raise ValueError("Need a portal id or name to scope token on")

    if repo_id:
        repo = get_repo_by_id(portal, repo_id)
    elif repo_name:
        repo = get_repo_by_name(portal, repo_name)
    else:
        raise ValueError("Need a repo id or name to scope token on")

    user_dn = urlsafe_b64decode(user_b64).decode("utf-8")
    user = tools.get_user_by_dn(repo, user_dn)
    scopes = portal.get_user_scope({}, user)
    assert 'sub' in scopes, "Cannot create token: IDP's scoping doesn't define a valid 'sub'"

    if token_key:
        try:
            UUID(token_key, version=4)
        except ValueError:
            raise ValueError("token's format is invalid")

    # data
    expire_at = request.JSON.get("expire_at")
    if expire_at:
        try:
            expire_at = datetime.fromtimestamp(expire_at, tz=timezone.utc)
        except TypeError:
            raise ValueError("'expire_at' field should be a valid unix timestamp")
        assert expire_at > timezone.now(), "'expire_at' cannot be in the past"
    else:
        expire_at = timezone.now() + timedelta(seconds=portal.oauth_timeout)

    # Auth
    auth_token = request.auth_token
    sub = auth_token.keys.get("sub")
    assert sub != None, "No 'sub' in authentication token, cannot establish user's identity"

    if sub != user_dn:
        logger.warning(f"User '{sub}' cannot create a token for user {user_dn}")
        raise ActionForbiddenException("Cannot modify tokens for another user")

    return portal, repo, user_dn, expire_at, scopes


@method_decorator(csrf_exempt, name="dispatch")
class IDPApiUserTokenView(View):

    @api_need_key('cluster_api_key')
    @api_check_authorization()
    def post(self, request, user_b64, portal_id=None, repo_id=None, portal_name=None, repo_name=None):
        try:
            portal, repo, user_dn, expire_at, scopes = _validate_request( request,
                                                                        user_b64,
                                                                        portal_id=portal_id,
                                                                        repo_id=repo_id,
                                                                        portal_name=portal_name,
                                                                        repo_name=repo_name)
            # All validation is done, creating token
            token_key = Uuid4().generate()
            token = REDISOauth2Session(REDISBase(), f"oauth2_{token_key}")
            logger.info(f"IDPApiUserTokenView::POST::[{portal.name}/{repo}] Creating token "
                        f"with scopes {scopes}, for user {user_dn}, expiration: {expire_at}")
            logger.debug(f"IDPApiUserTokenView::POST::[{portal.name}/{repo}] New token is {token_key}")
            token.register_authentication(
                portal.oauth_client_id,
                scopes,
                expire_at
            )

        except UserAuthentication.DoesNotExist:
            logger.warning(f"IDPApiUserTokenView::POST:: Tried to access unknown resource: "
                            f"portal {portal_id or portal_name}")
            return JsonResponse({
                "status": False,
                "error": _("Portal does not exist")
            }, status=404)
        except BaseRepository.DoesNotExist:
            logger.warning(f"IDPApiUserTokenView::POST:: "
                            f"Tried to access unknown resource: repo {repo_id or repo_name}")
            return JsonResponse({
                "status": False,
                "error": _("Repository does not exist")
            }, status=404)
        except UserDoesntExistError as e:
            logger.warning(f"IDPApiUserTokenView::POST:: "
                            f"Tried to access unknown resource: user {e.user_dn}")
            return JsonResponse({
                "status": False,
                "error": _("User does not exist")
            }, status=404)
        except ActionForbiddenException as e:
            logger.warning(f"IDPApiUserTokenView::POST:: {str(e)}")
            return JsonResponse({
                "status": False,
                "error": _(str(e))
            }, status=403)
        except (AssertionError, ValueError) as e:
            logger.warning(f"IDPApiUserTokenView::POST:: {str(e)}")
            return JsonResponse({
                "status": False,
                "error": _(str(e))
            }, status=400)
        except Exception as e:
            logger.exception(e)
            return JsonResponse({
                "status": False,
                "error": _("An unknown error occured")
            }, status=500)

        return JsonResponse({
            "status": True,
            "expire_at": int(expire_at.timestamp()),
            "token": token_key
        }, status=201)


@method_decorator(csrf_exempt, name="dispatch")
class IDPApiUserTokenModificationView(View):
    @api_need_key('cluster_api_key')
    @api_check_authorization()
    def patch(self, request, user_b64, token_key, portal_id=None, repo_id=None, portal_name=None, repo_name=None):
        try:
            token_key = str(token_key)
            portal, repo, user_dn, expire_at, scopes = _validate_request( request,
                                                                        user_b64,
                                                                        portal_id=portal_id,
                                                                        repo_id=repo_id,
                                                                        portal_name=portal_name,
                                                                        repo_name=repo_name,
                                                                        token_key=token_key)
            # All validation is done, creating token
            token = REDISOauth2Session(REDISBase(), f"oauth2_{token_key}")
            if not token.exists():
                logger.warning(f"IDPApiUserTokenModificationView::PATCH::[{portal.name}/{repo}] User '{user_dn}' "
                                f"Trying to refresh a token that doesn't exist")
                logger.debug(f"IDPApiUserTokenModificationView::PATCH::[{portal.name}/{repo}] token is {token_key}")
                return JsonResponse({
                    "status": False
                }, status=404)
            elif token.keys.get("sub") != user_dn:
                logger.error(f"IDPApiUserTokenModificationView::PATCH::[{portal.name}/{repo}] User '{user_dn}' "
                                f"is trying to override a token owned by '{token.keys.get('sub')}'!")
                logger.debug(f"IDPApiUserTokenModificationView::PATCH::[{portal.name}/{repo}] token is {token_key}")
                return JsonResponse({
                    "status": False
                }, status=404)
            logger.info(f"IDPApiUserTokenModificationView::PATCH::[{portal.name}/{repo}] Updating token "
                        f"with scopes {scopes}, for user {user_dn}, expiration: {expire_at}")
            logger.debug(f"IDPApiUserTokenModificationView::PATCH::[{portal.name}/{repo}] token is {token_key}")
            token.register_authentication(
                portal.oauth_client_id,
                scopes,
                expire_at
            )

        except UserAuthentication.DoesNotExist:
            logger.warning(f"IDPApiUserTokenModificationView::PATCH:: Tried to access unknown resource: "
                            f"portal {portal_id or portal_name}")
            return JsonResponse({
                "status": False,
                "error": _("Portal does not exist")
            }, status=404)
        except BaseRepository.DoesNotExist:
            logger.warning(f"IDPApiUserTokenModificationView::PATCH:: Tried to access unknown resource: "
                            f"repo {repo_id or repo_name}")
            return JsonResponse({
                "status": False,
                "error": _("Repository does not exist")
            }, status=404)
        except UserDoesntExistError as e:
            logger.warning(f"IDPApiUserTokenModificationView::PATCH:: "
                            f"Tried to access unknown resource: user {e.user_dn}")
            return JsonResponse({
                "status": False,
                "error": _("User does not exist")
            }, status=404)
        except ActionForbiddenException as e:
            logger.warning(f"IDPApiUserTokenModificationView::PATCH:: {str(e)}")
            return JsonResponse({
                "status": False,
                "error": _(str(e))
            }, status=403)
        except (AssertionError, ValueError) as e:
            logger.warning(f"IDPApiUserTokenModificationView::PATCH:: {str(e)}")
            return JsonResponse({
                "status": False,
                "error": _(str(e))
            }, status=400)
        except Exception as e:
            logger.exception(e)
            return JsonResponse({
                "status": False,
                "error": _("An unknown error occured")
            }, status=500)

        return JsonResponse({
            "status": True,
            "expire_at": int(expire_at.timestamp()),
            "token": token_key
        }, status=201)


    @api_need_key('cluster_api_key')
    @api_check_authorization()
    def delete(self, request, user_b64, token_key, portal_id=None, repo_id=None, portal_name=None, repo_name=None):
        try:
            token_key = str(token_key)
            portal, repo, user_dn, _, _ = _validate_request( request,
                                                                        user_b64,
                                                                        portal_id=portal_id,
                                                                        repo_id=repo_id,
                                                                        portal_name=portal_name,
                                                                        repo_name=repo_name,
                                                                        token_key=token_key)
            # All validation is done, creating token
            token = REDISOauth2Session(REDISBase(), f"oauth2_{token_key}")
            if not token.exists():
                logger.warning(f"IDPApiUserTokenModificationView::DELETE::[{portal.name}/{repo}] "
                                f"User {user_dn} trying to delete token that doesn't exist")
                logger.debug(f"IDPApiUserTokenModificationView::DELETE::[{portal.name}/{repo}] token is {token_key}")
                return JsonResponse({
                    "status": False
                }, status=404)
            elif token.keys.get("sub") != user_dn:
                logger.error(f"IDPApiUserTokenModificationView::DELETE::[{portal.name}/{repo}] User '{user_dn}' "
                                f"is trying to delete a token owned by '{token.keys.get('sub')}'!")
                logger.debug(f"IDPApiUserTokenModificationView::DELETE::[{portal.name}/{repo}] token is {token_key}")
                return JsonResponse({
                    "status": False
                }, status=404)
            logger.info(f"IDPApiUserTokenModificationView::DELETE::[{portal.name}/{repo}] "
                            f"Deleting a token for user {user_dn}")
            logger.debug(f"IDPApiUserTokenModificationView::DELETE::[{portal.name}/{repo}] token is {token_key}")
            token.delete()

        except UserAuthentication.DoesNotExist:
            logger.warning(f"IDPApiUserTokenModificationView::DELETE:: "
                            f"Tried to access unknown resource: portal {portal_id or portal_name}")
            return JsonResponse({
                "status": False,
                "error": _("Portal does not exist")
            }, status=404)
        except BaseRepository.DoesNotExist:
            logger.warning(f"IDPApiUserTokenModificationView::DELETE:: "
                            f"Tried to access unknown resource: repo {repo_id or repo_name}")
            return JsonResponse({
                "status": False,
                "error": _("Repository does not exist")
            }, status=404)
        except UserDoesntExistError as e:
            logger.warning(f"IDPApiUserTokenModificationView::DELETE:: "
                            f"Tried to access unknown resource: user {e.user_dn}")
            return JsonResponse({
                "status": False,
                "error": _("User does not exist")
            }, status=404)
        except ActionForbiddenException as e:
            logger.warning(f"IDPApiUserTokenModificationView::DELETE:: {str(e)}")
            return JsonResponse({
                "status": False,
                "error": _(str(e))
            }, status=403)
        except (AssertionError, ValueError) as e:
            logger.warning(f"IDPApiUserTokenModificationView::DELETE:: {str(e)}")
            return JsonResponse({
                "status": False,
                "error": _(str(e))
            }, status=400)
        except Exception as e:
            logger.exception(e)
            return JsonResponse({
                "status": False,
                "error": _("An unknown error occured")
            }, status=500)

        return JsonResponse({
            "status": True,
        }, status=204)
