#!/usr/bin/python
# -*- coding: utf-8 -*-
"""This file is part of Vulture 3.

Vulture 3 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Vulture 3 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Vulture 3.  If not, see http://www.gnu.org/licenses/.
"""
__author__ = "Kevin Guillemot"
__credits__ = []
__license__ = "GPLv3"
__version__ = "3.0.0"
__maintainer__ = \
    "Vulture Project"
__email__ = "contact@vultureproject.org"
__doc__ = 'System utils classes for SELF Service'

# import sys
# sys.path.append("/home/vlt-gui/vulture/portal")


# Django system imports
from django.conf import settings
from django.contrib.auth.hashers import make_password
from django.core.validators import validate_email

# Django project imports
from system.cluster.models import Cluster
from system.users.models import User
from portal.system.redis_sessions import REDISBase, REDISAppSession, REDISPortalSession
from portal.views.logon import authenticate, validate_portal_cookie
from portal.views.responses import self_message_response, self_ask_passwords, self_message_main, set_portal_cookie
from authentication.base_repository import BaseRepository
from toolkit.portal.registration import perform_email_registration, perform_email_reset
from toolkit.system.hashes import random_sha256
from authentication.portal_template.models import (RESET_PASSWORD_NAME, INPUT_PASSWORD_OLD, INPUT_PASSWORD_1,
                                               INPUT_PASSWORD_2, INPUT_EMAIL)
from workflow.models import Workflow
from authentication.openid.models import OpenIDRepository

# Required exceptions imports
from portal.system.exceptions import RedirectionNeededError, PasswordMatchError, PasswordEmptyError, TokenNotFoundError
from toolkit.auth.exceptions import AuthenticationError, AuthenticationFailed, UserNotFound

# Extern modules imports
from ast import literal_eval
from bson import ObjectId
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from jinja2 import Environment, FileSystemLoader
from re import match as re_match
from smtplib import SMTP, SMTPException

# Logger configuration imports
import logging

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('portal_authentication')


class SELFService(object):
    def __init__(self, workflow, token_name, global_config, main_url):
        # DoesNotExists
        self.workflow = workflow
        self.redis_base = REDISBase()
        self.token_name = token_name
        self.config = global_config
        self.main_url = main_url

        if not self.workflow.authentication:
            raise RedirectionNeededError("Application '{}' does not need authentication".format(self.workflow.name),
                                         self.workflow.get_redirect_uri())

    def get_username_by_email(self, repositories, email):
        for repo in repositories:
            try:
                if repo.subtype == "internal":
                    user = User.objects.get(email=email)
                    result = {
                        'name': user,
                        'backend': repo
                    }
                else:
                    result = repo.get_client().search_user_by_email(email)
                    result['backend'] = repo
                logger.info("SELF::get_user_by_email: User '{}' successfully found on backend '{}'".format(
                            result['name'],
                            result['backend']))
                return result

            except (UserNotFound, User.DoesNotExist) as e:
                raise UserNotFound(f"SELF::get_user_by_email: Could not find email '{email}' on backend '{repo}': {e}")
            except Exception as e:
                raise Exception(
                    f"SELF::get_user_by_email: Unknown error while searching for email '{email}' on backend '{repo}': {e}")

        raise UserNotFound(f"Could not find user from email '{email}'")


    def get_user_by_username(self, repositories, username):
        e = None
        for repo in repositories:
            try:
                if repo.subtype == "internal":
                    user = User.objects.get(username=username)
                    result = {
                        'name': user,
                        'backend': repo
                    }
                else:
                    result = repo.get_client().search_user_by_username(username)
                    result['backend'] = repo
                logger.info("SELF::get_user_by_username: User '{}' successfully found on backend '{}'".format(
                            result['name'],
                            result['backend']))
                return result
            except (UserNotFound, User.DoesNotExist) as e:
                raise UserNotFound(f"SELF::get_user_by_username: Could not find username '{username}' on backend '{repo}': {e}")
            except Exception as e:
                raise Exception(
                    f"SELF::get_user_by_username: Unknown error while searching for username '{username}' on backend '{repo}': {e}")

        raise UserNotFound(f"Could not find user from username '{username}'")


    def set_authentication_params(self, repo, authentication_results, username):
        if authentication_results:
            self.backend_id = str(repo.id)

            if isinstance(authentication_results, User):
                result = {
                    'data': {
                        'password_expired': False,
                        'account_locked': (not authentication_results.is_active),
                        'user_email': authentication_results.email
                    }
                }
            else:
                result = authentication_results

            result['backend'] = repo

            logger.debug("AUTH::set_authentication_params: Authentication results : {}".format(authentication_results))
            return result
        else:
            raise AuthenticationError(
                "SELF::authenticate: Authentication result is empty for username '{}'".format(username))

    def authenticate_on_backend(self, backend, username, password):

        authentication_results = self.set_authentication_params(backend,
                                                                backend.authenticate(username, password,
                                                                   #acls=self.application.access_mode, # TODO
                                                                ),
                                                                username)

        logger.info(
            "AUTH::authenticate: User '{}' successfully authenticated on backend '{}'".format(username, backend))
        self.backend_id = str(backend.id)

        return authentication_results

    def retrieve_credentials(self, request):
        """ Get portal_cookie name and application_cookie name from cluster """
        portal_cookie_name = self.workflow.authentication.auth_cookie_name or self.config.portal_cookie_name
        """ Get portal cookie value (if exists) """
        portal_cookie = request.COOKIES.get(portal_cookie_name, None)
        if portal_cookie == None:
            raise TokenNotFoundError("User has no session")

        self.redis_portal_session = REDISPortalSession(self.redis_base, portal_cookie)
        if self.redis_portal_session == None:
            raise TokenNotFoundError("Invalid portal session")

        if not self.redis_portal_session.authenticated_app(self.workflow.id):
            raise AuthenticationFailed("User Authentication is not complete yet")

        # And get username from redis_portal_session
        self.backend_id = self.redis_portal_session.get_auth_backend(self.workflow.id)
        self.username = self.redis_portal_session.get_login(str(self.backend_id))

        assert self.username, "Unable to find username in portal session !"
        return self.username

    def perform_action(self):
        openid_connector = OpenIDRepository.objects.get(client_id=self.workflow.authentication.oauth_client_id)
        workflows = Workflow.objects.filter(authentication__repositories_id__exact=openid_connector.id)

        final_apps = list()
        for w in workflows:
            final_apps.append({
                "name": w.name,
                "url": w.authentication.get_openid_start_url(
                    req_scheme="https" if w.frontend.listener_set.filter(tls_profiles__gt=0).exists() else "http",
                    workflow_host=w.fqdn,
                    workflow_path=w.public_dir,
                    repo_id=openid_connector.id
                )
            })

        return final_apps

    def main_response(self, request, app_list, error=None):
        return self_message_main(request, self.workflow.authentication, f"https://{self.workflow.fqdn}/", self.token_name, app_list, self.username, error)

    def message_response(self, request, message):
        # If IDP => user can come from /authorize, so get redirect_url
        redirect_url = request.GET.get('redirect_url')
        if not self.workflow.authentication.enable_external and not redirect_url:
            redirect_url = self.main_url
        # No go-back for IDP portal
        return self_message_response(self.workflow.authentication, message,
                                     redirect_url)

    def ask_credentials_response(self, request, action, error_msg, **kwargs):
        portal_cookie_name = self.workflow.authentication.auth_cookie_name or self.config.portal_cookie_name
        portal_cookie = validate_portal_cookie(request.COOKIES.get(portal_cookie_name)) or random_sha256()

        response = authenticate(request, self.workflow, portal_cookie, self.token_name, sso_forward=False, openid=False)
        self.redis_portal_session = REDISPortalSession(self.redis_base, portal_cookie)
        if self.redis_portal_session:
            return_url = f"https://{self.workflow.fqdn}/{self.token_name}/self"
            if action:
                return_url += f"/{action}"
            self.redis_portal_session.set_redirect_url(self.workflow.id, return_url)

        return set_portal_cookie(response, portal_cookie_name, portal_cookie, f"https://{self.workflow.fqdn}")


class SELFServiceChange(SELFService):
    def __init__(self, workflow, token_name, global_config, main_url):
        super().__init__(workflow, token_name, global_config, main_url)
        self.backend = None

    def retrieve_credentials(self, request):

        """ We may have a password reset token in URI """
        rdm = request.GET.get(RESET_PASSWORD_NAME, None) or request.POST.get(RESET_PASSWORD_NAME, None)

        # If not reset key, old password is required
        if not rdm:
            super().retrieve_credentials(request)
        else:
            # Chec rdm key format
            assert re_match("^[0-9a-f-]+$", rdm), "SELFServiceChange::retrieve_credentials: Injection attempt on 'rdm'"
            assert self.redis_base.exists(f"password_reset_{rdm}"), f"SELFServiceChange::retrieve_credentials: rdm key {rdm} does not exist"

        # Check if passwords are correct
        old_password = None  # None if rdm
        new_passwd = request.POST[INPUT_PASSWORD_1]
        new_passwd_cfrm = request.POST[INPUT_PASSWORD_2]
        if new_passwd != new_passwd_cfrm:
            raise PasswordMatchError("Password and confirmation mismatches")
        if new_passwd == "":
            raise PasswordEmptyError("Password cannot be empty")

        # If reset key, search username by email in repositories
        if rdm:
            # TODO might remove email in the future
            email = self.redis_base.hget('password_reset_' + rdm, 'email')
            username = self.redis_base.hget('password_reset_' + rdm, 'username')
            # Need at least one (keeping email for compatibility)
            assert email or username, "SELF::Change: Invalid Random Key provided: '{}'".format(rdm)
            # assert username, "SELF::Change: Invalid Random Key provided: '{}'".format(rdm)
            repo_id = self.redis_base.hget('password_reset_' + rdm, 'repo')
            if repo_id:
                # Only one backend if given in Redis session
                backends = [BaseRepository.objects.get(pk=repo_id).get_daughter()]
            else:
                backends = [repo.get_daughter() for repo in self.workflow.authentication.repositories.filter(subtype="LDAP")]

            if username:
                user_infos = self.get_user_by_username(backends, username)
            else:
                user_infos = self.get_username_by_email(backends, email)
            self.username = user_infos['name']
            self.backend = user_infos['backend']

        else:
            # Get old_password
            old_password = request.POST[INPUT_PASSWORD_OLD]  # If raise -> ask credentials

            # Use repository on which user authenticated to access this app (in redis session)
            repo = BaseRepository.objects.get(pk=self.backend_id).get_daughter()

            # Try to authenticate user with given old password
            user_infos = dict()
            try:
                user_infos = self.authenticate_on_backend(repo, self.username, old_password)
                self.backend = user_infos['backend']
                self.username = user_infos['name']
            except Exception as e:
                logger.error(f"Seems to have wrong old password on backend : '{repo.name}', exception details : {e}")
                logger.exception(e)
                raise AuthenticationError("Wrong old password")

            logger.debug("PORTAL::self: Found username from portal session: {}".format(self.username))

        return old_password


    def action_ok_message(self):
        return "Password successfully changed"


    # Change password
    def perform_action(self, request, old_password):

        # If we are here, password1 == password2 and old_password is correct if not reset
        # If reset, reset_key has been verified + repo has been found
        new_passwd = request.POST[INPUT_PASSWORD_1]

        rdm = (request.GET.get(RESET_PASSWORD_NAME, None) or request.POST.get(RESET_PASSWORD_NAME, None))

        # Check if password meets required complexity
        upper_case = 0
        lower_case = 0
        number = 0
        symbol = 0

        # min_len = int(self.workflow.pw_min_len)
        # min_upper = int(self.workflow.pw_min_upper)
        # min_lower = int(self.workflow.pw_min_lower)
        # min_number = int(self.workflow.pw_min_number)
        # min_symbol = int(self.workflow.pw_min_symbol)
        #
        # for i in new_passwd:
        #     if i.isupper():
        #         upper_case += 1
        #     elif i.islower():
        #         lower_case += 1
        #     elif i.isdigit():
        #         number += 1
        #     else:
        #         symbol += 1
        #
        # if not (len(
        #         new_passwd) >= min_len and upper_case >= min_upper and lower_case >= min_lower and number >= min_number and symbol >= min_symbol):
        #     logger.info("SELF::change_password: Password is too weak")
        #     raise AuthenticationError("Password do not meet complexity requirements")

        if self.backend.subtype == "internal":
            user = User.objects.get(username=str(self.username))
            new_password_hash = make_password(new_passwd)
            user.password = new_password_hash
            user.save()
        else:
            self.backend.get_client().update_password(self.username, old_password, new_passwd)
                                                      #krb5_service=self.application.app_krb_service)
        logger.info("SELF::change_password: Password successfully changed in backend")

        # If not rdm : set new password in Redis portal session
        if not rdm:
            self.redis_portal_session.setAutologonPassword(self.workflow.id, self.workflow.name,
                                                           self.backend_id, self.username, new_passwd)
        else:
            # Delete key in Redis
            self.redis_base.delete('password_reset_' + rdm)

        return self.action_ok_message()


    def ask_credentials_response(self, request, action, error_msg, **kwargs):
        rdm = request.GET.get(RESET_PASSWORD_NAME, None) or request.POST.get(RESET_PASSWORD_NAME, None)
        username = ""

        # If not reset key, try to retrieve username from current session
        if not rdm:
            try:
                super().retrieve_credentials(request)
                username = self.username if self.username else ""
            except Exception as e:
                logger.warning(f"SELFServiceChange::ask_credentials_response: could not retrieve credentials from session : {e}")
                return super().ask_credentials_response(request, action, error_msg)
        else:
            # Check rdm key format
            if re_match("^[0-9a-f-]+$", rdm):
                # And then get username from reset information
                result = self.redis_base.hget('password_reset_' + rdm, 'username')
                username = result if result else ""

        kwargs.update({"username": username})
        return self_ask_passwords(request,
                            self.workflow.authentication,
                            action,
                            request.GET.get(RESET_PASSWORD_NAME) or request.POST.get(RESET_PASSWORD_NAME),
                            error_msg,
                            **kwargs)


class SELFServiceLost(SELFService):
    def __init__(self, workflow, token_name, global_config, main_url, mail_expiration=259200):
        # Default expiration value is 3 days
        # TODO allow User to configure the timeout on GUI
        self.mail_expiration = mail_expiration
        super().__init__(workflow, token_name, global_config, main_url)

    def retrieve_credentials(self, request):
        """ We may have a password reset token in URI """
        email = request.POST[INPUT_EMAIL]  # -> ask email if raise KeyError

        # raise django.core.exceptions.ValidationError: ['Enter a valid email address.']
        validate_email(email)

        user_infos = self.get_username_by_email([r.get_daughter() for r in self.workflow.authentication.repositories.all()], email)
        self.username = user_infos['name']
        self.backend = user_infos['backend']

        return email


    def ask_credentials_response(self, request, action, error_msg, **kwargs):

        return self_ask_passwords(request,
                                  self.workflow.authentication,
                                  action,
                                  request.GET.get(RESET_PASSWORD_NAME) or request.POST.get(RESET_PASSWORD_NAME),
                                  error_msg,
                                  **kwargs)


    def action_ok_message(self):
        return ("<b>Mail successfully sent</b>"
        "<br>If your email address is valid, you should receive a message shortly with information on how to reset your password")


    def perform_action(self, request, email):
        if not perform_email_reset(logger, self.main_url, self.workflow.name, self.workflow.authentication.portal_template,
                            email, self.username, expire=self.mail_expiration, repo_id=self.backend.id):
            raise SMTPException("Could not send the reset email")
        return self.action_ok_message()

    # def ask_credentials_response(self):
    #	return self_response()


class SELFServiceLogout(SELFService):
    def __init__(self, workflow, token_name, global_config, main_url):
        super().__init__(workflow, token_name, global_config, main_url)

    def perform_action(self, _, username):

        logger.info(f"User {username} disconnecting from {self.workflow.authentication.name}")
        self.redis_portal_session.destroy()

        return "{} successfully disconnected".format(self.username)
