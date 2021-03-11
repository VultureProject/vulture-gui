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

# Django project imports
from system.cluster.models import Cluster
from system.users.models import User
from portal.system.redis_sessions import REDISBase, REDISAppSession, REDISPortalSession
from portal.views.responses import self_message_response, self_ask_passwords, self_message_main

# Required exceptions imports
from portal.system.exceptions import RedirectionNeededError, PasswordMatchError
from toolkit.auth.exceptions import AuthenticationError

# Extern modules imports
from ast import literal_eval
from bson import ObjectId
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from jinja2 import Environment, FileSystemLoader
from oauth2.tokengenerator import Uuid4
from re import match as re_match
from smtplib import SMTP, SMTPException

# Logger configuration imports
import logging

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('portal_authentication')


class SELFService(object):
    def __init__(self, app_id, token_name):
        # DoesNotExists
        self.workflow = Workflow.objects.with_id(ObjectId(app_id))
        self.redis_base = REDISBase()
        self.token_name = token_name
        self.cluster = Cluster.objects.get()

        if not self.workflow.authentication:
            raise RedirectionNeededError("Application '{}' does not need authentication".format(self.workflow.name),
                                         self.workflow.get_redirect_uri())

    def get_username_by_email(self, backend, fallback_backends, email):
        e = None
        try:
            if backend.subtype == "internal":
                user = User.objects.get(email=email)
                result = {
                    'user': user,
                    'backend': backend
                }
            else:
                result = backend.get_backend().search_user_by_email(email)
            logger.info("SELF::get_user_by_email: User '{}' successfully found on backend '{}'".format(result['user'],
                                                                                                       result[
                                                                                                           'backend']))
            self.backend_id = str(backend.id)
            return result

        except Exception as e:
            logger.error(
                "SELF::get_user_by_email: Failed to find email '{}' on primary backend '{}' : '{}'".format(email,
                                                                                                           str(backend),
                                                                                                           str(e)))
            logger.exception(e)
            for fallback_backend in fallback_backends:
                try:
                    if backend.subtype == "internal":
                        user = User.objects.get(email=email)
                        result = {
                            'user': user,
                            'backend': backend
                        }
                    else:
                        result = fallback_backend.get_backend().search_user_by_email(email)
                    logger.info(
                        "SELF::get_user_by_email: User '{}' successfully found on backend '{}'".format(result['user'],
                                                                                                       result[
                                                                                                           'backend']))
                    self.backend_id = str(fallback_backend.id)
                    return result

                except Exception as e:
                    logger.error(
                        "SELF::get_user_by_email: Failed to find email '{}' on primary backend '{}' : '{}'".format(
                            email, str(backend), str(e)))
                    logger.exception(e)

        raise e or AuthenticationError

    def set_authentication_params(self, repo, authentication_results, username):
        if authentication_results:
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

            logger.debug("AUTH::set_authentication_params: Authentication results : {}".format(authentication_results))
            return result
        else:
            raise AuthenticationError(
                "SELF::authenticate: Authentication result is empty for username '{}'".format(username))

    def authenticate_on_backend(self, backend, username, password):

        if backend.subtype == "internal":
            authentication_results = self.set_authentication_params(backend,
                                                                    backend.get_backend().authenticate(username,
                                                                                                       password),
                                                                    username)
        else:
            authentication_results = backend.get_backend().authenticate(username, password,
                                                                        acls=self.application.access_mode,
                                                                        logger=logger)

        logger.info(
            "AUTH::authenticate: User '{}' successfully authenticated on backend '{}'".format(username, backend))
        self.backend_id = str(backend.id)

        return authentication_results

    def retrieve_credentials(self, request):
        """ Get portal_cookie name and application_cookie name from cluster """
        portal_cookie_name = self.cluster.getPortalCookie()
        """ Get portal cookie value (if exists) """
        portal_cookie = request.COOKIES.get(portal_cookie_name, None)
        assert portal_cookie, "SELF:: Portal cookie not found"

        self.redis_portal_session = REDISPortalSession(self.redis_base, portal_cookie)
        assert self.redis_portal_session.exists(), "SELF:: Invalid portal session"

        # And get username from redis_portal_session
        self.username = self.redis_portal_session.keys.get('login_' + str(self.application.getAuthBackend().id)) or (([
                                                                                                                          self.redis_portal_session.keys.get(
                                                                                                                              'login_' + str(
                                                                                                                                  backend_fallback.id))
                                                                                                                          for
                                                                                                                          backend_fallback
                                                                                                                          in
                                                                                                                          self.application.getAuthBackendFallback()
                                                                                                                          if
                                                                                                                          self.redis_portal_session.keys.get(
                                                                                                                              'login_' + str(
                                                                                                                                  backend_fallback.id))] or [
                                                                                                                          None])[
                                                                                                                         0])
        assert self.username, "Unable to find username in portal session !"

    def perform_action(self):
        # Retrieve all the hkeys in redis matching "backend_(app_id) = (backend_id)"
        # with portal_cookie
        backends_apps = self.redis_portal_session.get_auth_backends()

        backends = list()
        apps = list()
        for key, item in backends_apps.items():
            # Extract the id of the application in "backend_(id)"
            app = key[8:]
            if app not in apps:
                apps.append(app)
            # The item is the backend
            if item not in backends:
                backends.append(item)

        logger.debug("User successfully authenticated on following apps : '{}'".format(apps))
        logger.debug("User successfully authenticated on following backends : '{}'".format(backends))

        # Retrieve all the apps which need auth AND which the backend or backend_fallback is in common with the backend the user is logged on
        # And retrieve all the apps that does not need authentication
		# FIXME
        # Query = (Q(need_auth=True) & (Q(auth_backend__in=backends) | Q(auth_backend_fallbacks__in=backends))) | Q(need_auth=False)
        Query = None
        auth_apps = Application.objects(Query).only('name', 'public_name', 'public_dir', 'id', 'type', 'listeners',
                                                    'need_auth')

        final_apps = list()
        for app in auth_apps:
            final_apps.append({
                'name': app.name,
                'url': str(app.get_redirect_uri()),
                'status': app.need_auth and str(app.id) in apps
            })

        return final_apps

    def main_response(self, request, app_list, error=None):
        return self_message_main(request, self.application, self.token_name, app_list, self.username, error)

    def message_response(self, message):
        return self_message_response(self.application, self.token_name, message)

    def ask_credentials_response(self, request, action, error_msg):
        return self_ask_passwords(request, self.application, self.token_name,
                                  request.GET.get("rdm", None) or request.POST.get('rdm', None), action, error_msg)


class SELFServiceChange(SELFService):
    def __init__(self, app_id, token_name):
        super(SELFServiceChange, self).__init__(app_id, token_name)
        self.backend = None

    def authenticated_on_backend(self):
        backend_list = list(self.application.getAuthBackendFallback())
        backend_list.append(self.application.getAuthBackend())
        for backend in backend_list:
            if self.redis_portal_session.authenticated_backend(backend.id):
                return str(backend.id)
        return ""

    def retrieve_credentials(self, request):

        """ We may have a password reset token in URI """
        rdm = request.GET.get("rdm", None) or request.POST.get('rdm', None)

        if not rdm:
            super(SELFServiceChange, self).retrieve_credentials(request)

        old_password = None  # None if rdm
        new_passwd = request.POST['password_1']
        new_passwd_cfrm = request.POST['password_2']
        if new_passwd != new_passwd_cfrm:
            raise PasswordMatchError("Password and confirmation mismatches")

        auth_backend = self.application.getAuthBackend()
        auth_backend_fallbacks = self.application.getAuthBackendFallback()

        if rdm:
            assert re_match("^[0-9a-f-]+$", rdm), "PORTAL::self: Injection attempt on 'rdm'"

            email = self.redis_base.hget('password_reset_' + rdm, 'email')
            assert email, "SELF::Change: Invalid Random Key provided: '{}'".format(rdm)

            user_infos = self.get_username_by_email(auth_backend, auth_backend_fallbacks, email)
            self.username = user_infos['user']
            self.backend = user_infos['backend']

        else:
            # Get old_password
            old_password = request.POST['password_old']  # If raise -> ask credentials

            # Get redis_portal_session
            portal_cookie = request.COOKIES.get(self.cluster.getPortalCookie())
            self.redis_portal_session = REDISPortalSession(self.redis_base, portal_cookie)
            # If not present -> 403
            assert self.redis_portal_session.exists(), "PORTAL::self: portal session is not valid !"

            # And get username & backend from redis_portal_session
            user_infos = dict()
            auth_backend = self.application.getAuthBackend()
            if self.redis_portal_session.keys.get('login_' + str(self.application.getAuthBackend().id)):
                try:
                    user_infos = self.authenticate_on_backend(auth_backend, self.username, old_password)
                    self.username = self.redis_portal_session.keys.get('login_' + str(auth_backend.id))
                    self.backend = auth_backend
                except Exception as e:
                    logger.error(
                        "Seems to have wrong old password on backend : '{}', exception details : " + self.application.getAuthBackend().repo_name)
                    logger.exception(e)
            if not user_infos:
                for backend_fallback in self.application.getAuthBackendFallback():
                    if self.redis_portal_session.keys.get('login_' + str(backend_fallback.id)):
                        try:
                            user_infos = self.authenticate_on_backend(backend_fallback, self.username, old_password)
                            self.username = self.redis_portal_session.keys.get('login_' + str(backend_fallback.id))
                            self.backend = backend_fallback
                            break
                        except:
                            logger.error("Seems to have wrong old password on backend : " + backend_fallback.repo_name)

            if not self.backend:
                raise AuthenticationError("Wrong old password")
            logger.debug("PORTAL::self: Found username from portal session: {}".format(self.username))

        return old_password

    # Change password
    def perform_action(self, request, old_password):
        new_passwd = request.POST['password_1']
        new_passwd_cfrm = request.POST['password_2']

        rdm = (request.GET.get("rdm", None) or request.POST.get('rdm', None))

        # If not rdm : Verify password
        if not rdm:
            saved_app_id = self.redis_portal_session.keys['app_id_' + str(self.backend.id)]
            saved_app = Application.objects(id=ObjectId(saved_app_id)).only('id', 'name', 'pw_min_len',
                                                                            'pw_min_upper', 'pw_min_lower',
                                                                            'pw_min_number', 'pw_min_symbol').first()
            if not self.redis_portal_session.getAutologonPassword(str(saved_app.id), str(self.backend.id),
                                                                  self.username):
                raise AuthenticationError("Wrong old password")
        else:
            saved_app = self.application

        # Check if password meets required complexity
        upper_case = 0
        lower_case = 0
        number = 0
        symbol = 0

        min_len = int(saved_app.pw_min_len)
        min_upper = int(saved_app.pw_min_upper)
        min_lower = int(saved_app.pw_min_lower)
        min_number = int(saved_app.pw_min_number)
        min_symbol = int(saved_app.pw_min_symbol)

        for i in new_passwd:
            if i.isupper():
                upper_case += 1
            elif i.islower():
                lower_case += 1
            elif i.isdigit():
                number += 1
            else:
                symbol += 1

        if not (len(
                new_passwd) >= min_len and upper_case >= min_upper and lower_case >= min_lower and number >= min_number and symbol >= min_symbol):
            logger.info("SELF::change_password: Password is too weak")
            raise AuthenticationError("Password do not meet complexity requirements")

        if self.backend.subtype == "internal":
            user = User.objects.get(username=str(self.username))
            new_password_hash = make_password(new_passwd)
            user.password = new_password_hash
            user.save()
        else:
            self.backend.change_password(self.username, old_password, new_passwd,
                                         krb5_service=self.application.app_krb_service)
        logger.info("SELF::change_password: Password successfully changed in backend")

        # If not rdm : set new password in Redis portal session
        if not rdm:
            if self.redis_portal_session.setAutologonPassword(str(saved_app.id), str(saved_app.name),
                                                              str(self.backend.id), self.username, old_password,
                                                              new_passwd) is None:
                # If setAutologonPasswd return None : the old_password was incorrect
                raise AuthenticationError("Wrong old password")
            logger.info("SELF::change_password: Password successfully changed in Redis")

        return "Password successfully changed"


class SELFServiceLost(SELFService):
    def __init__(self, app_id, token_name):
        super(SELFServiceLost, self).__init__(app_id, token_name)

    def retrieve_credentials(self, request):
        """ We may have a password reset token in URI """
        email = request.POST['email']  # -> ask email if raise KeyError

        # TODO : Verify email format : if wrong format => ask credentials + error msg || 403

        user_infos = self.get_username_by_email(self.application.getAuthBackend(),
                                                self.application.getAuthBackendFallback(), email)
        self.username = user_infos['user']

        return email

    def send_lost_mail(self, request, email):

        # """ Generate an UUID64 and store it in redis """
        reset_key = Uuid4().generate()

        redis_key = 'password_reset_' + reset_key

        """ Store the reset-key in Redis """
        # The 'a' is for Redis stats, to make a distinction with Token entries
        self.redis_base.hmset(redis_key, {'email': email, 'a': 1})
        """ The key will expire in 10 minutes """
        self.redis_base.expire(redis_key, 600)

        """ Send the email with the link """
        reset_link = self.application.get_redirect_uri() + str(self.token_name) + '/self/change?rdm=' + reset_key

        msg = MIMEMultipart('alternative')
        email_from = self.application.template.email_from
        msg['From'] = email_from
        msg['To'] = email
        obj = {'name': self.application.name, 'url': self.application.get_redirect_uri()}
        env = Environment(loader=FileSystemLoader("/home/vlt-gui/vulture/portal/templates/"))
        msg['subject'] = env.get_template("portal_%s_email_subject.conf" % (str(self.application.template.id))).render(
            {'app': obj})
        email_body = env.get_template("portal_%s_email_body.conf" % (str(self.application.template.id))).render(
            {'resetLink': reset_link, 'app': obj})
        msg.attach(MIMEText(email_body, "html"))

        node = self.cluster.get_current_node()
        if hasattr(node.system_settings, 'smtp_settings') and getattr(node.system_settings, 'smtp_settings'):
            settings = getattr(node.system_settings, 'smtp_settings')
        else:
            """ Not found, use cluster settings for configuration """
            settings = getattr(self.cluster.system_settings, 'smtp_settings')

        try:
            logger.debug("Sending link '{}' to '{}'".format(reset_link, email))
            smtpObj = SMTP(settings.smtp_server)
            # message = "Subject: " + unicode (email_subject) + "\n\n" + unicode (email_body)
            smtpObj.sendmail(email_from, email, msg.as_string())
        except Exception as e:
            logger.error("SELF::Lost: Failed to send email to '{}' : ".format(email))
            logger.exception(e)
            raise SMTPException("<b>Send mail failure</b> <br> Please contact your administrator")

        return "Mail successfully sent to '{}'".format(email)

    def perform_action(self, request, email):
        return self.send_lost_mail(request, email)

    # def ask_credentials_response(self):
    #	return self_response()


class SELFServiceLogout(SELFService):
    def __init__(self, app_id, token_name):
        super(SELFServiceLogout, self).__init__(app_id, token_name)

    def retrieve_credentials(self, request):
        super(SELFServiceLogout, self).retrieve_credentials(request)

        return literal_eval(self.redis_portal_session.keys['app_list'])

    def perform_action(self, request, app_cookie_list):
        if not app_cookie_list:
            logger.error("SELF::Logout: Application cookie list is empty")
        else:
            for app_cookie in app_cookie_list:
                try:
                    app_session = REDISAppSession(self.redis_base, cookie=app_cookie)
                    app_session.destroy()
                except Exception as e:
                    logger.error("SELF::Logout: Failed to destroy app cookie(s) : ")
                    logger.exception(e)

        self.redis_portal_session.destroy()

        return "{} successfully disconnected".format(self.username)
