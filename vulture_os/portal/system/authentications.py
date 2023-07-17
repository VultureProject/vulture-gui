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
__doc__ = 'System utils authentication'

# Django system imports
from django.conf import settings
from django.http import HttpResponse, JsonResponse, HttpResponseRedirect

# Django project imports
# FIXME from gui.models.repository_settings  import KerberosRepository, LDAPRepository
from portal.system.redis_sessions import (REDISBase, REDISAppSession, REDISPortalSession, REDISOauth2Session,
                                          REDISRefreshSession, RedisOpenIDSession)
from portal.views.responses import (split_domain, basic_authentication_response, kerberos_authentication_response,
                                    post_authentication_response, otp_authentication_response,
                                    learning_authentication_response, error_response)
from system.users.models import User
from workflow.models import Workflow
from authentication.base_repository import BaseRepository
from authentication.portal_template.models import INPUT_OTP_KEY, INPUT_OTP_RESEND

# Required exceptions imports
from portal.system.exceptions import RedirectionNeededError, CredentialsError, ACLError, TwoManyOTPAuthFailure
from ldap import LDAPError
from pymongo.errors import PyMongoError
from toolkit.auth.exceptions import AuthenticationError, RegisterAuthenticationError, OTPError

# Extern modules imports
from base64 import b64encode, urlsafe_b64decode
from bson import ObjectId
from captcha.image import ImageCaptcha
from smtplib import SMTPException
from uuid import uuid4

# Logger configuration imports
import logging

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('portal_authentication')


class Authentication(object):
    def __init__(self, portal_cookie, workflow, proto, redirect_url=None):
        self.redis_base = REDISBase()
        self.redis_portal_session = REDISPortalSession(self.redis_base, portal_cookie, **{f"url_{workflow.id}":redirect_url})
        self.workflow = workflow
        self.proto = proto
        self.oauth2_token = None
        self.refresh_token = None

        self.backend_id = self.authenticated_on_backend()

        if not self.workflow.authentication:
            raise RedirectionNeededError("Workflow '{}' does not need authentication".format(self.workflow.name),
                                         self.get_redirect_url())
        self.credentials = ["", ""]

    def is_authenticated(self):
        if self.redis_portal_session.exists() and self.redis_portal_session.authenticated_app(self.workflow.id):
            # If user authenticated, retrieve its login
            self.backend_id = self.redis_portal_session.get_auth_backend(self.workflow.id)
            self.credentials[0] = self.redis_portal_session.get_login(str(self.backend_id))
            self.oauth2_token = self.redis_portal_session.get_oauth2_token(self.backend_id)
            self.refresh_token = self.redis_portal_session.get_refresh_token(self.backend_id)
            return True
        return False

    def get_user_infos(self, workflow_id):
        return self.redis_portal_session.get_user_infos(self.redis_portal_session.get_auth_backend(workflow_id))

    def double_authentication_required(self):
        return self.workflow.authentication.otp_repository is not None and \
            not self.redis_portal_session.is_double_authenticated(self.workflow.authentication.otp_repository.id)

    def authenticated_on_backend(self):
        backend_list = self.workflow.authentication.repositories.all()
        for backend in backend_list:
            if self.redis_portal_session.authenticated_backend(backend.id):
                return str(backend.id)
        return ""

    def set_authentication_params(self, repo, authentication_results):
        if authentication_results:
            result = {}
            self.backend_id = str(repo.id)

            if isinstance(authentication_results, User):
                result = {
                    'data': {
                        'password_expired': False,
                        'account_locked': (not authentication_results.is_active),
                        'user_email': authentication_results.email
                    },
                    'backend': repo
                }
                """ OAuth2 enabled in any case """
                result['data']['oauth2'] = {
                    'scope': '{}',
                    'token_return_type': 'both',
                    'token_ttl': self.workflow.authentication.auth_timeout
                }
            logger.debug("AUTH::set_authentication_params: Authentication results : {}".format(authentication_results))
            return result
        else:
            raise AuthenticationError("AUTH::set_authentication_params: Authentication results is empty : '{}' "
                                      "for username '{}'".format(authentication_results, self.credentials[0]))

    def authenticate_on_backend(self, backend):
        if backend.subtype == "internal":
            return self.set_authentication_params(backend, backend.authenticate(self.credentials[0],
                                                                                self.credentials[1]))
        else:
            return backend.authenticate(self.credentials[0], self.credentials[1],
                                        # FIXME : ACLs
                                        # acls=self.workflow.access_control_list,
                                        logger=logger)

    def authenticate(self, request):
        error = None
        for backend in self.workflow.authentication.repositories.exclude(subtype="openid"):
            try:
                authentication_results = self.authenticate_on_backend(backend)
                self.backend_id = str(backend.id)
                logger.info("AUTH::authenticate: User '{}' successfully authenticated on backend '{}'"
                            .format(self.credentials[0], backend))
                return authentication_results

            except (AuthenticationError, ACLError, PyMongoError, LDAPError) as e:
                logger.error("AUTH::authenticate: Authentication failure for username '{}' on backend '{}'"
                             " : '{}'".format(self.credentials[0], str(backend), str(e)))
                logger.exception(e)
                error = e
                continue
        raise error or AuthenticationError("No valid repository to authenticate user")

    def write_oauth2_session(self, scopes):
        logger.debug(f"AUTH::write_oauth2_session: Redis oauth2 session scopes are {scopes}")
        if not self.oauth2_token:
            self.oauth2_token = str(uuid4())

        self.redis_oauth2_session = REDISOauth2Session(self.redis_base, "oauth2_" + self.oauth2_token)
        # Use client_id as repo_id to allow linking token to both it's IDP and connector in Vulture
        self.redis_oauth2_session.register_authentication(
            str(self.workflow.authentication.oauth_client_id),
            scopes,
            self.workflow.authentication.oauth_timeout)

        logger.debug(f"AUTH::write_oauth2_session: access token successfuly created : {self.oauth2_token}")

    def write_refresh_session(self, scopes):
        logger.debug(f"AUTH::write_refresh_session: Redis oauth2 session scopes are {scopes}")
        if not self.refresh_token:
            self.refresh_token = str(uuid4())

        self.redis_refresh_session = REDISRefreshSession(self.redis_base, "refresh_" + self.refresh_token)
        # Time-To-Live is calculated to be equivalent to the time of the corresponding oauth token + 1 minute
        # Refresh historisation requires that refresh tokens are then available for max_nb_refresh 
        #   times the duration of an oauth token
        # (meaning if 3 refresh tokens are required for history, expiration of one refresh token
        #   will be 3 times the expiration of the oauth token + 1 minute)
        timeout = self.workflow.authentication.oauth_timeout * (self.workflow.authentication.max_nb_refresh + 1) + 60
        # Use client_id as repo_id to allow linking token to both it's IDP and connector in Vulture
        self.redis_refresh_session.store_refresh_token(
            scopes,
            timeout,
            self.oauth2_token)

        logger.debug(f"AUTH::write_refresh_session: refresh token successfuly created : {self.refresh_token}")

    def register_user(self, authentication_results, oauth2_scope):
        if self.workflow.authentication.enable_oauth:
        # Mandatory claims for SSO-F, OTP, change password, etc
            if not oauth2_scope.get('sub'):
                oauth2_scope['sub'] = authentication_results.get('sub', authentication_results.get("dn", ""))
            if not oauth2_scope.get('user_email'):
                oauth2_scope['user_email'] = authentication_results.get('user_email', "")
            if not oauth2_scope.get('user_phone'):
                oauth2_scope['user_phone'] = authentication_results.get('user_phone', "")
            logger.info(f"AUTH::register_user: Oauth enabled for {self.workflow.authentication.name}, creating oauth2 token")
            self.write_oauth2_session(oauth2_scope)
            if self.workflow.authentication.enable_refresh:
                self.write_refresh_session(oauth2_scope)

        portal_cookie = self.redis_portal_session.register_authentication(str(self.workflow.id),
                                                                          str(self.workflow.name),
                                                                          str(self.backend_id),
                                                                          self.workflow.authentication.otp_repository,
                                                                          self.credentials[0], self.credentials[1],
                                                                          self.oauth2_token,
                                                                          self.refresh_token,
                                                                          authentication_results,
                                                                          self.workflow.authentication.auth_timeout)

        logger.debug("AUTH::register_user: Authentication results successfully written in Redis portal session")
        return portal_cookie, self.oauth2_token, self.refresh_token

    def allow_user(self):
        if self.workflow.authentication.enable_oauth:
            # Take smallest timeout for authorisation key: will allow to refresh the oauth_token in case of expiration before the session expires
            timeout = min(self.workflow.authentication.auth_timeout, self.workflow.authentication.oauth_timeout)
        else:
            timeout = self.workflow.authentication.auth_timeout
        logger.debug(f"Authentication::allow_user: allowing session to {self.workflow.name} with authentication backend {self.backend_id} for {timeout} seconds")
        self.redis_portal_session.allow_access_to_app(
            self.workflow.id,
            timeout
        )

    def register_sso(self, backend_id):
        username = self.redis_portal_session.keys['login_' + backend_id]
        self.oauth2_token = self.redis_portal_session.keys.get('oauth2_' + backend_id)
        if self.workflow.authentication.enable_refresh:
            self.refresh_token = self.redis_portal_session.keys.get('refresh_' + backend_id)
        # Get current user_infos for this backend
        oauth2_scope = self.redis_portal_session.get_user_infos(backend_id)

        if self.workflow.authentication.enable_oauth:
            logger.info(f"AUTH::register_sso: Oauth enabled for {self.workflow.authentication.name}, creating oauth2 token")
            self.write_oauth2_session(oauth2_scope)
            if self.workflow.authentication.enable_refresh:
                logger.info(f"AUTH::register_user: Refresh tokens enabled for {self.workflow.authentication.name}, creating refresh token")
                self.write_refresh_session(oauth2_scope)

        password = self.redis_portal_session.getAutologonPassword(self.workflow.id, backend_id, username)
        logger.debug("AUTH::register_sso: Password successfully retrieved from Redis portal session")

        timeout = self.workflow.authentication.auth_timeout if self.workflow.authentication.enable_timeout_restart else None

        portal_cookie = self.redis_portal_session.register_sso(timeout,
                                                                backend_id, str(self.workflow.id),
                                                                self.workflow.authentication.otp_repository.id if self.workflow.authentication.otp_repository else None,
                                                                username,
                                                                self.oauth2_token,
                                                                self.refresh_token)

        logger.debug("AUTH::register_sso: SSO informations successfully written in Redis for user {}".format(username))
        self.credentials = [username, password]
        return portal_cookie, self.oauth2_token, self.refresh_token

    def register_openid(self, openid_token, **kwargs):
        # Generate a new OAuth2 token
        if not self.oauth2_token:
            self.oauth2_token = str(uuid4())
        # Register it into session
        self.redis_portal_session.set_oauth2_token(self.backend_id, self.oauth2_token)
        if self.workflow.authentication.enable_refresh:
            # Generate a new Refresh token
            if not self.refresh_token:
                self.refresh_token = str(uuid4())
            self.redis_portal_session.set_refresh_token(self.backend_id, self.refresh_token)
        # Create a new temporary token containing oauth2_token + kwargs
        RedisOpenIDSession(self.redis_base, f"token_{openid_token}").register(self.oauth2_token, self.refresh_token, **kwargs)
        logger.debug(f"AUTH::register_openid: openid_token, self.oauth2_token, self.refresh_token {openid_token, self.oauth2_token, self.refresh_token}")

    def del_redirect_uri(self):
        self.redis_portal_session.del_redirect_uri(self.workflow.id)

    def get_redirect_url(self):
        # Get custom redirect_url if present, or default workflow redirect url
        return self.redis_portal_session.get_redirect_url(self.workflow.id) or self.workflow.get_redirect_uri()

    def set_redirect_url(self, redirect_url):
        self.redis_portal_session.set_redirect_url(self.workflow.id, redirect_url)
        # self.redis_portal_session['url_{}'.format(self.workflow.id)] = redirect_url

    def del_redirect_url(self):
        self.redis_portal_session.del_redirect_url(self.workflow.id)

    def get_url_portal(self):
        try:
            # FIXME : auth_portal attribute ?
            return self.workflow.auth_portal or self.workflow.get_redirect_uri()
        except:
            return self.workflow.get_redirect_uri()

    def get_redirect_url_domain(self):
        return split_domain(self.get_redirect_url())

    def get_credentials(self, request):
        if not self.credentials[0]:
            try:
                self.retrieve_credentials(request)
            except:
                self.credentials[0] = self.redis_portal_session.get_login(self.backend_id)
        logger.debug("AUTH::get_credentials: User's login successfully retrieved from Redis session : '{}'".format(
            self.credentials[0]))
        if not self.credentials[1]:
            try:
                self.retrieve_credentials(request)
            except:
                if not self.backend_id:
                    self.backend_id = self.authenticated_on_backend()
                self.credentials[1] = self.redis_portal_session.getAutologonPassword(str(self.workflow.id),
                                                                                     self.backend_id,
                                                                                     self.credentials[0])
        logger.debug("AUTH::get_credentials: User's password successfully retrieved/decrypted from Redis session")

    def ask_learning_credentials(self, **kwargs):
        try:
            return learning_authentication_response(kwargs.get('request'),
                                                        self.workflow.authentication,
                                                        kwargs.get('fields'),
                                                        error=kwargs.get('error'))
        except Exception as e:
            logger.error("Failed to render learning fields response : ")
            logger.exception(e)
            return error_response(self.workflow.authentication, "An error occured")

    def generate_response(self):
        return HttpResponseRedirect(self.get_redirect_url())


class POSTAuthentication(Authentication):
    def __init__(self, portal_cookie, workflow, proto, redirect_url=None):
        super().__init__(portal_cookie, workflow, proto, redirect_url=redirect_url)

    def retrieve_credentials(self, request):
        username = request.POST['vltprtlsrnm']
        password = request.POST['vltprtlpsswrd']
        self.credentials = [username, password]

    def authenticate(self, request):
        if self.workflow.authentication.enable_captcha:
            assert (request.POST.get('vltprtlcaptcha') == self.redis_portal_session.retrieve_captcha(self.workflow.id))
        return super().authenticate(request)

    def ask_credentials_response(self, **kwargs):
        if self.workflow.authentication.enable_captcha:
            captcha_key = self.redis_portal_session.register_captcha(self.workflow.id)
            captcha = "data:image/image/png;base64," + b64encode(ImageCaptcha().generate(captcha_key).read()).decode()
        else:
            captcha = False

        response = post_authentication_response(kwargs.get('request'),
                                                self.workflow.authentication,
                                                self.workflow.public_dir,
                                                kwargs.get('public_token', ""),
                                                captcha=captcha,
                                                error=kwargs.get('error', ""))

        portal_cookie_name = kwargs.get('portal_cookie_name', None)
        if portal_cookie_name:
            response.set_cookie(portal_cookie_name, self.redis_portal_session.key,
                                domain=self.get_redirect_url_domain(), httponly=True,
                                secure=self.get_redirect_url().startswith('https'))

        return response


class BASICAuthentication(Authentication):
    def __init__(self, portal_cookie, workflow, proto, redirect_url=None):
        super().__init__(portal_cookie, workflow, proto, redirect_url=redirect_url)

    def retrieve_credentials(self, request):
        authorization_header = request.META.get("HTTP_AUTHORIZATION").replace("Basic ", "")
        authorization_header += '=' * (4 - len(authorization_header) % 4)
        username, password = urlsafe_b64decode(authorization_header).decode('utf-8').split(':')
        self.credentials = [username, password]

    def ask_credentials_response(self, **kwargs):
        response = basic_authentication_response(self.workflow.name)

        portal_cookie_name = kwargs.get('portal_cookie_name', None)
        if portal_cookie_name:
            response.set_cookie(portal_cookie_name, self.redis_portal_session.key,
                                domain=self.get_redirect_url_domain(), httponly=True,
                                secure=self.get_redirect_url().startswith('https'))

        return response


class KERBEROSAuthentication(Authentication):
    def __init__(self, portal_cookie, workflow, proto, redirect_url=None):
        super().__init__(portal_cookie, workflow, proto, redirect_url=redirect_url)

    def retrieve_credentials(self, request):
        self.credentials = request.META["HTTP_AUTHORIZATION"].replace("Negotiate ", "")

    def authenticate(self, request):
        e = None
        try:
            backend = self.workflow.authentication.repository
            if backend.subtype == "KERBEROS":
                authentication_results = backend.authenticate_token(logger, self.credentials)
                self.backend_id = str(backend.id)
                self.credentials = [authentication_results['data']['dn'], ""]
                logger.info("AUTH:authenticate: User '{}' successfully authenticated on kerberos repository '{}'"
                            .format(self.credentials[0], backend))
                return authentication_results
            else:
                raise AuthenticationError("Repository '{}' is not a Kerberos Repository".format(backend))

        except (AuthenticationError, ACLError) as e:
            logger.error("AUTH::authenticate: Authentication failure for kerberos token on primary repository '{}' : "
                         "'{}'".format(str(backend), str(e)))

            for fallback_backend in self.workflow.authentication.repositories_fallback.all():
                try:
                    if backend.subtype == "KERBEROS":
                        authentication_results = fallback_backend.get_backend().authenticate_token(logger,
                                                                                                   self.credentials)
                        self.backend_id = str(backend.id)
                        self.credentials = [authentication_results['data']['dn'], ""]
                        logger.info("AUTH:authenticate: User '{}' successfully authenticated on kerberos fallback "
                                    "repository '{}'".format(self.credentials[0], fallback_backend))

                        return authentication_results
                    else:
                        raise AuthenticationError("Backend '{}' not a Kerberos Repository".format(fallback_backend))

                except (AuthenticationError, ACLError) as e:
                    logger.error(
                        "AUTH::authenticate: Authentication failure for kerberos token on fallback repository '{}' : "
                        "'{}'".format(str(fallback_backend), str(e)))
                    continue

        raise e or AuthenticationError

    def ask_credentials_response(self, **kwargs):
        response = kerberos_authentication_response()

        portal_cookie_name = kwargs.get('portal_cookie_name', None)
        if portal_cookie_name:
            response.set_cookie(portal_cookie_name, self.redis_portal_session.key,
                                domain=self.get_redirect_url_domain(), httponly=True,
                                secure=self.get_redirect_url().startswith('https'))

        return response


class DOUBLEAuthentication(Authentication):
    def __init__(self, portal_cookie, workflow, proto, redirect_url=None):
        super().__init__(portal_cookie, workflow, proto, redirect_url=redirect_url)
        assert (self.redis_portal_session.exists())
        assert self.backend_id
        self.backend = BaseRepository.objects.get(pk=self.backend_id)
        self.credentials[0] = self.redis_portal_session.get_login(self.backend_id)
        self.resend = False
        self.print_captcha = False

    def retrieve_credentials(self, request):
        try:
            self.resend = request.POST.get(INPUT_OTP_RESEND, False)

            if not self.resend:
                key = request.POST[INPUT_OTP_KEY]
            user = self.redis_portal_session.get_otp_key()
            assert (user)
            # If self.resend this line will raise, it's wanted
            self.credentials = [user, key]
        except Exception as e:
            raise CredentialsError("Cannot retrieve otp credentials : {}".format(str(e)))

    def authenticate(self, request):
        repository = self.workflow.authentication.otp_repository

        if repository.otp_type == 'email':
            if repository.otp_mail_service == 'vlt_mail_service':
                if self.credentials[0] != self.credentials[1] and self.credentials[0] not in ['', None, 'None', False]:
                    raise AuthenticationError("The OTP key entered does not match the one saved")

        else:
            # The function raise itself AuthenticationError, or return True
            repository.authenticate(self.credentials[0], self.credentials[1],
                                    app=self.workflow,
                                    backend=self.backend,
                                    login=self.redis_portal_session.get_login(self.backend_id))

        logger.info("DB-AUTH::authenticate: User successfully double-authenticated "
                    "on OTP backend '{}'".format(repository))
        self.redis_portal_session.register_doubleauthentication(self.workflow.id, repository.id)
        self.redis_portal_session.reset_otp_retries(repository.id)
        logger.debug("DB-AUTH::authenticate: Double-authentication results successfully written in Redis portal session")

    def create_authentication(self):
        if self.resend or not self.redis_portal_session.get_otp_key():
            """ If the user ask to resend otp key or if the otp key has not yet been sent """
            otp_repo = self.workflow.authentication.otp_repository
            user_infos = self.redis_portal_session.get_user_infos(self.backend_id)
            user_phone = user_infos.get('user_phone', None)
            user_mail = user_infos.get('user_email', None)

            if otp_repo.otp_type == 'phone' and user_phone in ('', 'None', None, False, 'N/A'):
                logger.error("DB-AUTH::create_authentication: User phone is not valid : '{}'".format(user_phone))
                raise OTPError("Cannot find phone in repository <br> <b> Contact your administrator <b/>")

            elif (otp_repo.otp_type in ['email', 'totp'] or otp_repo.otp_phone_service == 'authy') and user_mail in (
                    '', 'None', None, False, 'N/A'):
                raise OTPError("Cannot find mail in repository <br> <b> Contact your administrator </b>")

            try:
                otp_info = otp_repo.get_client().register_authentication(user_mail=user_mail, user_phone=user_phone,
                                                            sender=self.workflow.authentication.portal_template.email_from,
                                                            app=self.workflow,
                                                            backend=self.backend,
                                                            login=self.redis_portal_session.get_login(self.backend_id))

                # TOTPClient.register_authent returns 2 values instead of only one
                if otp_repo.otp_type == "totp":
                    # Need to print the captcha to the user ?
                    self.print_captcha = otp_info[0]
                    otp_info = otp_info[1]
                    self.credentials[0] = otp_info

                logger.info("DB-AUTHENTICATION::create_authentication: Key successfully created/sent to {},"
                            "{}".format(user_mail, user_phone))
            except (SMTPException, RegisterAuthenticationError, Exception) as e:
                logger.error("DB-AUTHENTICATION::create_authentication: Exception while sending OTP key to {} : "
                             "{}".format(user_mail if otp_repo.otp_type == 'email' else user_phone, str(e)))
                logger.exception(e)
                otp_info = None

            if not otp_info:
                logger.error("DB-AUTH::create_authentication: OTP key created/sent is Null")
                raise OTPError("Error while sending secret key <br> <b> Contact your administrator </b>")

            self.redis_portal_session.set_otp_info(otp_info)
            # Ensure session is valid for at least 5 minutes
            self.redis_portal_session.set_ttl(300)
            logger.debug("DB-AUTH::create_authentication: OTP key successfully written in Redis session")

        elif self.workflow.authentication.otp_repository.otp_type == "totp":
            # Retrieve TOTPProfile if exists, or generate a new key
            otp_info = self.workflow.authentication.otp_repository.get_client().register_authentication(
                backend=self.backend,
                login=self.redis_portal_session.get_login(self.backend_id))
            self.print_captcha = otp_info[0]
            self.credentials[0] = otp_info[1]
            # And save the generated/retrieved key in Redis
            self.redis_portal_session.set_otp_info(otp_info[1])


    def authentication_failure(self):
        otp_retries = self.redis_portal_session.increment_otp_retries(self.workflow.authentication.otp_repository.id)
        logger.debug("DB-AUTH::authentication_failure: Number of retries successfully incremented in Redis session")
        if otp_retries >= int(self.workflow.authentication.otp_max_retry):
            logger.error("DB-AUTH::authentication_failure: Maximum number of retries reached : '{}'>='{}'"
                         .format(otp_retries, self.workflow.authentication.otp_max_retry))
            raise TwoManyOTPAuthFailure("Max number of retry reached </br> <b> Please re-authenticate </b>")

    def deauthenticate_user(self):
        self.redis_portal_session.deauthenticate(self.workflow.id, self.backend_id,
                                                 self.workflow.authentication.auth_timeout)
        if self.workflow.authentication.otp_repository:
            self.redis_portal_session.reset_otp_retries(self.workflow.authentication.otp_repository.id)
        logger.debug("DB-AUTH::deauthenticate_user: Redis portal session successfully updated (deauthentication)")

    def ask_credentials_response(self, **kwargs):
        captcha_url = ""
        if self.workflow.authentication.otp_repository.otp_type == "totp" and self.print_captcha:
            user_mail = self.redis_portal_session.keys.get('user_email', "")
            captcha_url = self.workflow.authentication.otp_repository.get_client().generate_captcha(self.credentials[0], user_mail)
            logger.debug(f"DB-AUTH::ask_credentials_response: Captcha generated for user {user_mail} : {self.credentials[0]}")

        response = otp_authentication_response(kwargs.get('request'),
                                               self.workflow.authentication,
                                               self.workflow.authentication.otp_repository.otp_type,
                                               captcha_url,
                                               kwargs.get('error', None))

        #portal_cookie_name = kwargs.get('portal_cookie_name', None)
        #if portal_cookie_name:
        #    response.set_cookie(portal_cookie_name, self.redis_portal_session.key,
        #                        domain=self.get_redirect_url_domain(), httponly=True,
        #                        secure=self.get_redirect_url().startswith('https'))

        return response


class OAUTH2Authentication(Authentication):
    def __init__(self, portal_cookie, workflow, proto):
        self.redis_base = REDISBase()

    def retrieve_credentials(self, username, password, portal_cookie):
        assert (username)
        assert (password)
        self.credentials = [username, password]
        self.redis_portal_session = REDISPortalSession(self.redis_base, portal_cookie)

    def authenticate(self):
        self.oauth2_token = self.redis_portal_session.get_oauth2_token(self.authenticated_on_backend())
        if not self.oauth2_token:
            authentication_results = super().authenticate(None)
            logger.debug("OAUTH2_AUTH::authenticate: Oauth2 attributes : {}"
                         .format(str(authentication_results['data'])))
            if authentication_results['data'].get('oauth2', None) is not None:
                self.oauth2_token = str(uuid4())
                self.register_authentication(authentication_results['data']['oauth2'])
                authentication_results = authentication_results['data']['oauth2']
            elif self.application.enable_oauth2:
                authentication_results = {
                    'token_return_type': 'both',
                    'token_ttl': self.application.auth_timeout,
                    'scope': '{}'
                }
                self.oauth2_token = str(uuid4())
                self.register_authentication(authentication_results)
            else:
                raise AuthenticationError(
                    "OAUTH2_AUTH::authenticate: OAuth2 is not enabled on this app nor on this repository")
        else:
            # REPLACE CREDENTIAL 'user"
            self.redis_oauth2_session = REDISOauth2Session(self.redis_base, "oauth2_" + self.oauth2_token)
            authentication_results = self.redis_oauth2_session.keys
        return authentication_results

    def register_authentication(self, authentication_results):
        self.redis_oauth2_session = REDISOauth2Session(self.redis_base, "oauth2_" + self.oauth2_token)
        self.redis_oauth2_session.register_authentication(str(self.backend_id),
                                                          authentication_results,
                                                          authentication_results['token_ttl'])
        logger.debug("AUTH::register_authentication: Redis oauth2 session successfully written in Redis")

    def generate_response(self, authentication_results):
        body = {
            "token_type": "Bearer",
            "access_token": self.oauth2_token
        }

        if authentication_results.get('token_return_type') == 'header':
            response = HttpResponse()
            response['Authorization'] = body["token_type"] + " " + body["access_token"]

        elif authentication_results.get('token_return_type') == 'json':
            response = JsonResponse(body)

        elif authentication_results.get('token_return_type') == 'both':
            response = JsonResponse(body)
            response['Authorization'] = body["token_type"] + " " + body["access_token"]

        return response
