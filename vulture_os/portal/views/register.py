#!/usr/bin/python
#-*- coding: utf-8 -*-
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
__maintainer__ ="Vulture Project"
__email__ = "contact@vultureproject.org"
__doc__ = 'Django views to display registration portal'



#import sys
#sys.path.append("/home/vlt-gui/vulture/portal")


# Django system imports
from django.conf                     import settings
from django.http                     import HttpResponseRedirect, HttpResponseServerError, HttpResponseForbidden
from django.shortcuts                import render_to_response
from django.utils.crypto             import get_random_string

# Django project imports
from system.cluster.models import Cluster
from system.users.models import User
from portal.views.responses          import register_ask1, register_ask2, render_stylesheet
from portal.system.redis_sessions    import REDISBase
from workflow.models import Workflow

# Required exceptions imports
from bson.errors                     import InvalidId
from django.core.exceptions          import ValidationError
from ldap                            import LDAPError
from portal.system.exceptions        import RedirectionNeededError, UserAlreadyExistsError, CredentialsError
from pymongo.errors                  import PyMongoError
from redis                           import ConnectionError as RedisConnectionError
from smtplib                         import SMTPException
from sqlalchemy.exc                  import DBAPIError
from toolkit.auth.exceptions import UserNotFound

# Extern modules imports
from base64                          import b64encode
from captcha.image                   import ImageCaptcha
from email.mime.multipart            import MIMEMultipart
from email.mime.text                 import MIMEText
from jinja2                          import Environment, FileSystemLoader
from re                              import match as re_match
from smtplib                         import SMTP
from uuid                            import uuid4

# Logger configuration
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('portal_authentication')


class Registration(object):
    def __init__(self, app_id, token_name):
        self.token_name  = token_name
        self.redis_base  = REDISBase()
        self.workflow = Workflow.objects.get(pk=app_id)
        self.cluster     = Cluster.objects.get()

        self.backend = self.workflow.repository
        if not self.application.enable_registration:
            raise RedirectionNeededError("Registration is not enabled in the workflow '{}'".format(self.workflow.name),
                                         self.workflow.get_redirect_uri())

    def verify_captcha(self, request):
        # Verify captcha:
        captcha_key = request.POST['captcha_token']
        captcha = self.redis_base.hget(captcha_key, 'captcha')
        # Delete the key
        self.redis_base.delete(captcha_key)
        if captcha != request.POST['captcha']:
            raise CredentialsError("Bad captcha")

    def generate_captcha(self, redis_key):
        chars       = 'ABCDEFGHIJKLMNPQRSTUVWXYZ123456789'
        captcha_key = get_random_string(6, chars)
        captcha     = b64encode(ImageCaptcha().generate(captcha_key).read())
        self.redis_base.hset(redis_key, 'captcha', captcha_key)
        # Expiration of captcha : 1 minute
        self.redis_base.expire(redis_key, 60)
        return captcha


class STEP1Registration(Registration):
    def __init__(self, app_id, token_name):
        super(STEP1Registration, self).__init__(app_id, token_name)

    def search_user_by_mail(self, email, backend):
        if backend.subtype == "internal":
            user = User.objects.get(email=email)  # TODO : Except User.doesNotExists
            result = {
                'user': user,
                'backend': backend
            }
        else:
            result = backend.search_user_by_email(email)

        return result

    def retrieve_credentials(self, request, token):
        # Try to retrieve and verify captcha
        self.verify_captcha(request)

        email = request.POST['vltrgstremail']

        # Verify email format:
        if '"' in email or "'" in email or not re_match(".*@.*\..{2,4}", email):
            raise CredentialsError("Bad format for email : '{}'".format(email))

        # Verify if the user already exists in application repository
        try:
            backend = self.workflow.repository
            user_infos = self.search_user_by_mail(email, backend)

            if not user_infos:
                raise UserNotFound()
            else:
                raise UserAlreadyExistsError("REGISTER::search_user: User '{}' already found on repository '{}' "
                                             "with email '{}'".format(user_infos['user'], backend.repo_name, email))
        except (User.DoesNotExist, UserNotFound) as e:
            pass

        # Verify if an email has already been sent
        for key in self.redis_base.keys("registration_*"):
            if self.redis_base.hget(key, "email") == email:
                raise CredentialsError("The registration key has already been sent.")

        return email

    def perform_action(self, request, email, token):
        # """ Generate an UUID64 and store it in redis """
        reset_key = str(uuid4())

        redis_key = 'registration_' + reset_key

        """ Send the email with the link """
        reset_link = self.workflow.get_redirect_uri() + str(self.token_name) + '/register?registrk=' + reset_key

        msg = MIMEMultipart('alternative')
        email_from  = self.workflow.template.email_register_from
        msg['From'] = email_from
        msg['To']   = email
        obj = {'name': self.workflow.name, 'url': self.workflow.get_redirect_uri()}
        env = Environment(loader=FileSystemLoader("/home/vlt-gui/vulture/portal/templates/"))
        msg['subject'] = env.get_template("portal_%s_email_register_subject.conf" % (str(self.workflow.template.id))).render(
            {'app': obj})
        email_body = env.get_template("portal_%s_email_register_body.conf" % (str(self.workflow.template.id))).render(
            {'registerLink': reset_link, 'app': obj})
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

        """ Store the reset-key in Redis """
        # The 'b' is for Redis stats, to make a distinction with Token entries
        self.redis_base.hmset(redis_key, {'email': email, 'b': 1})
        """ The key will expire in 10 minutes """
        self.redis_base.expire(redis_key, 600)

        return "Mail successfully sent to '{}'".format(email)

    def ask_credentials_response(self, request, token, error_msg=None):
        captcha_key = get_random_string(32)
        captcha     = self.generate_captcha(captcha_key)
        return register_ask1(request, self.application, self.token_name, captcha_key, captcha, error_msg)

    def message_response(self, message):
        style = render_stylesheet('/{}/templates/portal_{}.css'.format(str(self.token_name), str(self.workflow.template.id)))
        link_redirect = self.workflow.get_redirect_uri() + str(self.token_name) + "/register"
        return render_to_response("portal_%s_html_message.conf" % str(self.workflow.template.id),
                                  {'style': style, 'link_redirect': link_redirect, 'message': message})


class STEP2Registration(Registration):
    def __init__(self, app_id, token_name):
        super(STEP2Registration, self).__init__(app_id, token_name)

    def retrieve_credentials(self, request, token):
        # Try to retrieve and verify captcha
        self.verify_captcha(request)

        # Verify token format
        assert re_match("^[0-9a-f-]+$", token), "REGISTER::step2: Injection attempt on registration token"

        # Verify token value and mail provided
        email = self.redis_base.hget('registration_' + token, 'email')
        assert email, "SELF::Change: Invalid Random Key provided: '{}'".format(token)

        return email

    def perform_action(self, request, email, token):
        # Try to retrieve POST infos
        username  = request.POST['username']
        password1 = request.POST['password1']
        password2 = request.POST['password2']
        phone = None
        if self.backend.get_phone_column():
            phone = request.POST['phone']
            if phone.count('"') != 0:
                raise CredentialsError("Bad format for phone")

        if username.count('"') != 0:
            raise CredentialsError("Bad format for username")
        if password1.count('"') != 0:
            raise CredentialsError("Bad format for password1")
        if password2.count('"') != 0:
            raise CredentialsError("Bad format for password2")
        if password1 != password2:
            raise CredentialsError("Password and confirmation mismatches")

        # Implement add_new_user in backends/clients
        self.backend.add_new_user(username, password1, email, phone, application=self.workflow)

        # Delete the token
        self.redis_base.delete('registration_' + token)

        return "User '{}' successfully registered".format(username)


    def ask_credentials_response(self, request, token, message=None):
        captcha_key = get_random_string(32)
        captcha     = self.generate_captcha(captcha_key)
        return register_ask2(request, self.workflow, self.token_name, token, self.backend.get_phone_column() != "",
                             captcha_key, captcha, message)

    def message_response(self, message):
        style = render_stylesheet('/{}/templates/portal_{}.css'.format(str(self.token_name), str(self.workflow.template.id)))
        link_redirect = self.workflow.get_redirect_uri()
        return render_to_response("portal_%s_html_message.conf" % str(self.workflow.template.id),
                                  {'style': style, 'link_redirect': link_redirect, 'message': message})


def registration(request, token_name, proxy_app_id=None):

    """ Handle Vulture registration asking 
    :param request: Django request object
    :param request: Django request object
    :param request: Django request object
    :returns: Registration portal
    """
    registrk = request.GET.get('registrk')

    try:
        if registrk:
            registration = STEP2Registration(proxy_app_id, token_name)
        else:
            registration = STEP1Registration(proxy_app_id, token_name)

    # Redis connection error
    except RedisConnectionError as e:
        logger.error("REGISTER::init: Unable to connect to Redis server : {}".format(str(e)))
        return HttpResponseServerError()

    except (Workflow.DoesNotExist, ValidationError, InvalidId) as e:
        logger.error("REGISTER::init: Workflow with id '{}' not found".format(proxy_app_id))
        return HttpResponseForbidden()

    except RedirectionNeededError as e:
        logger.error(e)
        return HttpResponseRedirect(e.redirect_url)


    try:
        creds = registration.retrieve_credentials(request, registrk)
        return registration.message_response(registration.perform_action(request, creds, registrk))

    except AssertionError as e:
        logger.error(e)
        return HttpResponseForbidden()

    except KeyError as e:
        if request.method == "GET":
            return registration.ask_credentials_response(request, registrk)
        else:
            logger.error("REGISTER::step1: Field missing : '{}'".format(e))
            return registration.ask_credentials_response(request, registrk, "Field missing : '{}'".format(e))

    except UserAlreadyExistsError as e:
        logger.error(e)
        return registration.ask_credentials_response(request, registrk, "An user already exists with this email address")

    except CredentialsError as e:
        logger.error("REGISTER::step2: {}".format(e))
        return registration.ask_credentials_response(request, registrk, str(e))

    except SMTPException as e:
        return registration.ask_credentials_response(request, registrk, str(e))

    except (LDAPError, PyMongoError, DBAPIError) as e:
        logger.error("REGISTER::step2: Error contacting the database : ")
        logger.exception(e)
        return registration.ask_credentials_response(request, registrk, "Error contacting the database <br> <b> Please contact your administrator </b>")

    except Exception as e:
        logger.error("REGISTER::Error: An unknown error occurred while registering : ")
        logger.exception(e)
        return registration.ask_credentials_response(request, registrk, "An unknown error occurred <br> <b> Please contact your administrator </b>")


