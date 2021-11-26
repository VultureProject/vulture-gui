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
__author__ = "Jérémie Jourdin"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Django models dedicated to portal templates'

# Django system imports
from django.conf import settings
from django.template import Context, Template
from django.utils.translation import ugettext_lazy as _
from django.forms.models import model_to_dict
from djongo import models

# Django project imports
from services.haproxy.haproxy import HAPROXY_OWNER, HAPROXY_PATH, HAPROXY_PERMS
from system.config.models import write_conf

# Extern modules imports
import base64

# Required exceptions imports

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


INPUT_LOGIN = "vltprtlsrnm"
INPUT_PASSWORD = "vltprtlpsswrd"
INPUT_CAPTCHA = "vltprtlcaptcha"
INPUT_OTP_KEY = "vltprtlkey"
INPUT_OTP_RESEND = "vltotpresend"
RESET_PASSWORD_NAME = "rdm"
INPUT_PASSWORD_OLD = "password_old"
INPUT_PASSWORD_1 = "password_1"
INPUT_PASSWORD_2 = "password_2"
INPUT_EMAIL = "email"

HAPROXY_HEADER = "HTTP/1.1 200 OK\r\nContent-type: text/html\r\nConnection: close\r\n\r\n"


class PortalTemplate(models.Model):
    """ Vulture portal's template model representation
    name: A friendly name for the template
    css: css content
    html_login: html_content
    """
    name = models.TextField(
        unique=True,
        default="Portal template",
        help_text=_('Friendly name to reference the template')
    )
    css = models.TextField(
        default="""/*\n * Specific styles of signin component\n */\n/*\n * General styles\n */\nbody, html {\n    height: 100%;\n    background: #FBFBF0 linear-gradient(135deg, #70848D, #21282E) repeat scroll 0% 0%;\n}\n\n.card-container.card {\n    max-width: 350px;\n    padding: 40px 40px;\n}\n\n#self_service {\n    max-width: 450px;\n    padding: 40px 40px;\n}\n\n.list-group-item {\n    text-align: left;\n}\n\n.btn {\n    font-weight: 700;\n    height: 36px;\n    -moz-user-select: none;\n    -webkit-user-select: none;\n    user-select: none;\n    cursor: default;\n}\n\n/*\n * Card component\n */\n.card {\n    text-align:center;\n    background-color: #F7F7F7;\n    /* just in case there no content*/\n    padding: 20px 25px 30px;\n    margin: 0 auto 25px;\n    margin-top: 50px;\n    /* shadows and rounded borders */\n    -moz-border-radius: 2px;\n    -webkit-border-radius: 2px;\n    border-radius: 2px;\n    -moz-box-shadow: 0px 2px 2px rgba(0, 0, 0, 0.3);\n    -webkit-box-shadow: 0px 2px 2px rgba(0, 0, 0, 0.3);\n    box-shadow: 0px 2px 2px rgba(0, 0, 0, 0.3);\n}\n\n#vulture_img{\n    width:150px;\n}\n\n.form-signin{\n    text-align: center;\n}\n\n#captcha{\n    border:1px solid #c5c5c5;\n    margin-bottom: 10px;\n}\n\n.alert{\n    margin-bottom: 0px;\n    margin-top:15px;\n}\n\n.reauth-email {\n    display: block;\n    color: #404040;\n    line-height: 2;\n    margin-bottom: 10px;\n    font-size: 14px;\n    text-align: center;\n    overflow: hidden;\n    text-overflow: ellipsis;\n    white-space: nowrap;\n    -moz-box-sizing: border-box;\n    -webkit-box-sizing: border-box;\n    box-sizing: border-box;\n}\n\n.form-signin #inputEmail,\n.form-signin #inputPassword {\n    direction: ltr;\n    height: 44px;\n    font-size: 16px;\n}\n\ninput[type=email],\ninput[type=password],\ninput[type=text],\nbutton {\n    width: 100%;\n    display: block;\n    margin-bottom: 10px;\n    z-index: 1;\n    position: relative;\n    -moz-box-sizing: border-box;\n    -webkit-box-sizing: border-box;\n    box-sizing: border-box;\n}\n\n.form-signin .form-control:focus {\n    border-color: rgb(104, 145, 162);\n    outline: 0;\n    -webkit-box-shadow: inset 0 1px 1px rgba(0,0,0,.075),0 0 8px rgb(104, 145, 162);\n    box-shadow: inset 0 1px 1px rgba(0,0,0,.075),0 0 8px rgb(104, 145, 162);\n}\n\n.btn.btn-signin {\n    background-color: #F1A14C;\n    padding: 0px;\n    font-weight: 700;\n    font-size: 14px;\n    height: 36px;\n    -moz-border-radius: 3px;\n    -webkit-border-radius: 3px;\n    border-radius: 3px;\n    border: none;\n    -o-transition: all 0.218s;\n    -moz-transition: all 0.218s;\n    -webkit-transition: all 0.218s;\n    transition: all 0.218s;\n}\n\n.btn.btn-signin:hover{\n    cursor: pointer;\n}\n\n.forgot-password {\n    color: rgb(104, 145, 162);\n}\n\n.forgot-password:hover,\n.forgot-password:active,\n.forgot-password:focus{\n    color: rgb(12, 97, 33);\n}\n""",
        help_text=_('Cascading Style Sheet for template')
    )
    html_login = models.TextField(
        default="<!DOCTYPE html>\n<html>\n<head>\n    <meta charset=\"utf-8\"/>\n    <title>Vulture Login</title>\n    <link rel=\"stylesheet\" href=\"/templates/static/html/bootstrap.min.css\" integrity=\"sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7\" crossorigin=\"anonymous\">\n    <style>{{style}}</style>\n </head>\n <body>\n    <div class=\"container\">\n        <div class=\"card card-container\">\n            <form action='' method='POST' autocomplete='off' class='form-signin'>\n                <img id=\"vulture_img\" src=\"{{image_1}}\"/>\n                {% if error_message != \"\" %}\n                  <div class=\"alert alert-danger\" role=\"alert\">{{error_message}}</div>\n                {% endif %}\n                <span id=\"reauth-email\" class=\"reauth-email\"></span>\n                <input type=\"text\" name=\"{{input_login}}\" class=\"form-control\" placeholder=\"Login\" required/>\n                <input type=\"password\" name=\"{{input_password}}\" class=\"form-control\" placeholder=\"Password\" required/>\n                {% if captcha %}\n                    <img id=\"captcha\" src=\"{{captcha}}\"/>\n                    <input type=\"text\" name=\"{{input_captcha}}\" class=\"form-control\" placeholder=\"Captcha\" required/>\n\n                {% endif %}\n                <button class=\"btn btn-lg btn-warning btn-block btn-signin\" type=\"submit\">{{login_submit_field}}</button>\n                {% for repo in openid_repos %}\n                <a href=\"{{repo.start_url}}\">Login with {{repo.name}} ({{repo.provider}})</a><br>\n                {% endfor %}\n                <a href=\"{{lostPassword}}\">Forgotten password ?</a>\n            </form>\n        </div>\n    </div>\n </body>\n</html>",
        help_text=_('HTML Content for the login page')
    )
    html_learning = models.TextField(
        default="<!DOCTYPE html>\n<html>\n <head>\n    <meta charset=\"utf-8\" />\n    <title>Vulture Learning</title>\n    <link rel=\"stylesheet\" href=\"/templates/static/html/bootstrap.min.css\" integrity=\"sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7\" crossorigin=\"anonymous\">\n    <style>{{style}}</style>\n </head>\n <body>\n    <div class=\"container\">\n        <div class=\"card card-container\" style=\"text-align:center;\">\n            <p>Learning form</p>\n            {{form_begin}}\n                {{input_submit}}\n            {{form_end}}\n        </div>\n    </div>\n </body>\n</html>",
        help_text=_('HTML Content for the learning page')
    )
    html_logout = models.TextField(
        default="<!DOCTYPE html>\n<html>\n <head>\n    <meta charset=\"utf-8\" />\n    <title>Vulture Logout</title>\n     <link rel=\"stylesheet\" href=\"//templates/static/html/bootstrap.min.css\" integrity=\"sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7\" crossorigin=\"anonymous\">\n     <style>{{style}}</style>\n </head>\n <body>\n    <div class=\"container\">\n        <div class=\"card card-container\" style=\"text-align:center;\">\n            <p style=\"font-size:15px;font-weight:bold;\">You have been successfully disconnected</p>\n            <a href=\"{{app_url}}\">Return to the application</a>\n        </div>\n    </div>\n </body>\n</html>",
        help_text=_('HTML Content for the logout page')
    )
    html_self = models.TextField(
        default="<!DOCTYPE html>\n<html>\n <head>\n    <meta charset=\"utf-8\" />\n    <title>Vulture Self-Service</title>\n    <link rel=\"stylesheet\" href=\"/templates/static/html/bootstrap.min.css\" integrity=\"sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7\" crossorigin=\"anonymous\">\n    <style>{{style}}</style>\n </head>\n <body>\n    <div class=\"container\">\n        <div class=\"card card-container\" style=\"text-align:center;\" id=\"self_service\">\n            <img id=\"vulture_img\" src=\"{{image_1}}\"/>\n            <br><br>\n            {% if error_message != \"\" %}\n                <div class=\"alert alert-danger\">{{error_message}}</div>\n            {% endif %}\n            <p>Hello <b>{{username}}</b>!</p>\n            <p>You currently have access to the following apps:</p>\n            <ul class=\"list-group\">\n                {% for app in application_list %}\n                  <li class=\"list-group-item\"><b>{{app.name}}</b> - <a href=\"{{app.url}}\">{{app.url}}</a>{% if app.status %}<span class=\"badge\">Logged</span>{% endif %}</li>\n                {% endfor %}\n            </ul>\n            <a href=\"{{changePassword}}\">Change password</a>\n            <br><a href=\"{{logout}}\">Logout</a>\n        </div>\n    </div>\n </body>\n</html>",
        help_text=_('HTML Content for the self-service page')
    )
    html_password = models.TextField(
        default="<!DOCTYPE html>\n<html>\n <head>\n    <meta charset=\"utf-8\" />\n    <title>Vulture Change Password</title>\n    <link rel=\"stylesheet\" href=\"/templates/static/html/bootstrap.min.css\" integrity=\"sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7\" crossorigin=\"anonymous\">\n    <style>{{style}}</style>\n </head>\n <body>\n    <div class=\"container\">\n        <div class=\"card card-container\" style=\"text-align:center;\">\n            <form action='' method='POST' autocomplete='off' class='form-signin'>\n                <img id=\"vulture_img\" src=\"{{image_1}}\"/>\n                {% if error_message %}\n                    <div class=\"alert alert-danger\">{{error_message}}</div>\n                {% endif %}\n                {% if dialog_change %}\n                    <p>Hello <b>{{username}}</b></p>\n                    <p>Please fill the form to change your current password :</p>\n                    {% if reset_password_key %}\n                    <input type=\"hidden\" class=\"form-control\" name=\"{{reset_password_name}}\" value=\"{{reset_password_key}}\"/>\n                    {% else %}\n                    <input type=\"password\" class=\"form-control\" placeholder=\"Old password\" name=\"{{input_password_old}}\"/>\n                    {% endif %}\n                    <input type=\"password\" class=\"form-control\" placeholder=\"New password\" name=\"{{input_password_1}}\"/>\n                    <input type=\"password\" class=\"form-control\" placeholder=\"Confirmation\" name=\"{{input_password_2}}\"/>\n                    <button class=\"btn btn-lg btn-warning btn-block btn-signin\" type=\"submit\">Ok</button>\n\n                {% elif dialog_lost %}\n                    <p>Please enter an email address to reset your password:</p>\n                    <input type=\"email\" class=\"form-control\" placeholder=\"Email\" name=\"{{input_email}}\"/>\n                    <button class=\"btn btn-lg btn-warning btn-block btn-signin\" type=\"submit\">Ok</button>\n                    \n                {% endif %}\n            </form>\n        </div>\n    </div>\n </body>\n</html>",
        help_text=_('HTML Content for the password change page')
    )
    html_otp = models.TextField(
        default="<!DOCTYPE html>\n<html>\n <head>\n    <meta charset=\"utf-8\" />\n    <title>Vulture OTP Authentication</title>\n    <link rel=\"stylesheet\" href=\"/templates/static/html/bootstrap.min.css\" integrity=\"sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7\" crossorigin=\"anonymous\">\n    <style>{{style}}</style>\n </head>\n <body> \n    <div class=\"container\">\n        <div class=\"card card-container\" style=\"text-align:center;\">\n            {% if error_message != \"\" %}\n                  <div class=\"alert alert-danger\" role=\"alert\">{{error_message}}</div>\n            {% endif %}\n            <p>OTP Form</p>\n            <form class=\"form-signin\" autocomplete=\"off\" action=\"\" method=\"POST\">\n                {% if onetouch %}\n                  {{otp_onetouch_field}}\n                {% else %}\n                <input type=\"text\" name=\"vltprtlkey\" class=\"form-control\" placeholder=\"Key\" required/>\n                <button class=\"btn btn-lg btn-warning btn-block btn-signin\" type=\"submit\">{{otp_submit_field}}</button>\n                {% endif %}\n            </form>\n            <form class=\"form-signin\" autocomplete=\"off\" action=\"\" method=\"POST\">\n                {% if resend_button %}\n                    <button class=\"btn btn-lg btn-warning btn-block btn-signin\" name=\"{{input_otp_resend}}\" value=\"yes\">{{otp_resend_field}} {{otp_type}}</button>\n                {% endif %}\n                {% if qrcode %}\n                    <p>Register the following QRcode on your phone :\n                    <img src=\"{{qrcode}}\" alt=\"Failed to display QRcode\" height=\"270\" width=\"270\" />\n                    </p>\n                {% endif %}\n            </form>\n        </div>\n    </div>\n </body>\n</html>",
        help_text=_('HTML Content for the otp page')
    )
    html_message = models.TextField(
        default="<!DOCTYPE html>\n<html>\n <head>\n    <meta charset=\"utf-8\" />\n    <title>Vulture Info</title>\n    <link rel=\"stylesheet\" href=\"/templates/static/html/bootstrap.min.css\" integrity=\"sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7\" crossorigin=\"anonymous\">\n    <style>{{style}}</style>\n </head>\n <body>\n    <div class=\"container\">\n        <div class=\"card card-container\">\n            <img id=\"vulture_img\" src=\"{{image_1}}\"/>\n            <p>{{message}}</p>\n            {% if link_redirect %}<a href=\"{{link_redirect}}\">Go back</a>{% endif %}\n        </div>\n    </div>\n </body>\n</html>",
        help_text=_('HTML Content for the message page')
    )
    html_error = models.TextField(
        default="<!DOCTYPE html>\n<html>\n <head>\n    <meta charset=\"utf-8\" />\n    <title>Vulture Error</title>\n    <link rel=\"stylesheet\" href=\"/templates/static/html/bootstrap.min.css\" integrity=\"sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7\" crossorigin=\"anonymous\">\n    <style>\n        <style>{{style}}</style>\n    </style>\n </head>\n <body>\n    <div class=\"container\">\n        <div class=\"card card-container\">\n            <img id=\"vulture_img\" src=\"{{image_1}}\"/>\n            <p>{{message}}</p>\n        </div>\n    </div>\n </body>\n</html>",
        help_text=_('HTML General content for error pages')
    )
    html_registration = models.TextField(
        default="<!DOCTYPE html>\n<html>\n <head>\n    <meta charset=\"utf-8\" />\n    <title>Vulture Registration</title>\n    <link rel=\"stylesheet\" href=\"/templates/static/html/bootstrap.min.css\" integrity=\"sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7\" crossorigin=\"anonymous\">\n    <style>{{style}}</style>\n </head>\n <body>\n    <div class=\"container\">\n        <div class=\"card card-container\" style=\"text-align:center;\">\n            {{form_begin}}\n                <img id=\"vulture_img\" src=\"{{image_1}}\"/>\n                {% if error_message %}\n                    <div class=\"alert alert-danger\">{{error_message}}</div>\n                {% endif %}\n                {{captcha}}\n                {{input_captcha}}\n                {% if step2 %}\n                    <p>Please fill the form to register your account :</p>\n                    {{input_username}}\n                    {% if ask_phone %}\n                    {{input_phone}}\n                    {% endif %}\n                    {{input_password_1}}\n                    {{input_password_2}}\n                    {{input_submit}}\n\n                {% elif step1 %}\n                    <p>Please enter your email address to receive the registration mail :</p>\n                    {{input_email}}\n                    {{input_submit}}\n                {% endif %}\n            {{form_end}}\n        </div>\n    </div>\n </body>\n</html>",
        help_text=_('HTML Content for registration pages')
    )
    html_error_403 = models.TextField(
        default="403 Forbidden",
        help_text=_('HTML message for 403 Forbidden error')
    )
    html_error_404 = models.TextField(
        default="404 Not Found",
        help_text=_('HTML message for 404 Not Found error')
    )
    html_error_405 = models.TextField(
        default="405 Method Not Allowed",
        help_text=_('HTML message for 405 Method Not Allowed error')
    )
    html_error_406 = models.TextField(
        default="406 Not Acceptable",
        help_text=_('HTML message for 406 Not Acceptable error')
    )
    html_error_500 = models.TextField(
        default="500 Server Error",
        help_text=_('HTML message for 500 Server Error error')
    )
    html_error_501 = models.TextField(
        default="501 Not Implemented",
        help_text=_('HTML message for 501 Not Implemented error')
    )
    html_error_502 = models.TextField(
        default="502 Bad Gateway",
        help_text=_('HTML message for 502 Bad Gateway / Proxy error')
    )
    html_error_503 = models.TextField(
        default="503 Service Unavailable",
        help_text=_('HTML message for 503 Service Unavailable error')
    )
    html_error_504 = models.TextField(
        default="504 Gateway Time-out",
        help_text=_('HTML message for 504 Gateway Time-out error')
    )
    email_subject = models.TextField(
        default="Password reset request for {{ app.name }}",
        help_text=_('Email subject for password reset')
    )
    email_body = models.TextField(
        default="<html>\n<head>\n</head>\n<body>\n<p>Dear Sir/Madam <b>{{username}}</b>, <br><br>\n\nWe got a request to reset your account on {{ app.url }}.<br><br>\n\nClick here to reset your password: <a href=\"{{resetLink}}\">Reset password</a><br><br>\n\nIf you ignore this message, your password won't be changed.<br>\nIf you didn't request a password reset, <a href=\"mailto:abuse@vulture\">let us know</a><br>\n</body>\n</html>",
        help_text=_('Email content for password reset')
    )
    email_from = models.TextField(
        default="no-reply@vulture",
        help_text=_('Email "From" for password reset')
    )
    error_password_change_ok = models.TextField(
        default="Your password has been changed",
        help_text=_('Your password has been changed')
    )
    error_password_change_ko = models.TextField(
        default="Error when trying to change your password",
        help_text=_('Error when trying to change your password')
    )
    error_email_sent = models.TextField(
        default="An email has been sent to you with instructions to reset your password",
        help_text=_('An email has been sent to you with instruction to reset your password')
    )
    # images = models.JSONField(models.ImageField(null=True), default=[], help_text=_('Images you can use in your templates'))
    email_register_subject = models.TextField(
        default="Registration request for {{ app.name }}",
        help_text=_('Email subject for registration')
    )
    email_register_from = models.TextField(
        default="no-reply@vulture",
        help_text=_('Email address for registration')
    )
    email_register_body = models.TextField(
        default="<html>\n    <head>\n        <title>Vulture registration</title>\n    </head>\n    <body>\n        <p>Dear Sir/Madam <b>{{username}}</b>, <br><br>\n\n        We got a request to register your account on {{ app.url }}.<br><br>\n\n        Click here to validate the registration : <a href=\"{{registerLink}}\">Register account</a><br><br>\n\n        If you ignore this message, your account won't be confirmed.<br>\n        If you didn't request a registration, <a href=\"mailto:abuse@vulture\">let us know</a><br>\n    </body>\n</html>",
        help_text=_('Email sender for registration')
    )
    """ Input fields value """
    login_login_field = models.TextField(
        default="Login",
        help_text=_("Login field for the log-in page")
    )
    login_password_field = models.TextField(
        default="Password",
        help_text=_("Password field for the log-in page")
    )
    login_captcha_field = models.TextField(
        default="Captcha",
        help_text=_("Captcha field for the log-in page")
    )
    login_submit_field = models.TextField(
        default="Sign in",
        help_text=_("Submit field for the log-in page")
    )
    learning_submit_field = models.TextField(
        default="Save",
        help_text=_("Submit field for the learning page")
    )
    password_old_field = models.TextField(
        default="Old password",
        help_text=_("Old password field for the password page")
    )
    password_new1_field = models.TextField(
        default="New password",
        help_text=_("New password field for the password page")
    )
    password_new2_field = models.TextField(
        default="Confirmation",
        help_text=_("Confirmation password field for the password page")
    )
    password_email_field = models.TextField(
        default="Email",
        help_text=_("Email field for the password page")
    )
    password_submit_field = models.TextField(
        default="OK",
        help_text=_("Submit field for the password page")
    )
    otp_key_field = models.TextField(
        default="Key",
        help_text=_("OTP Key field for the OTP page")
    )
    otp_submit_field = models.TextField(
        default="Sign in",
        help_text=_("Submit field for the OTP page")
    )
    otp_resend_field = models.TextField(
        default="Resend",
        help_text=_("Resend field for the OTP page")
    )
    otp_onetouch_field = models.TextField(
        default="<p>Please approve the OneTouch request on your phone, and click on 'Sign in'</p>",
        help_text=_("Onetouch message for the OTP page")
    )
    register_captcha_field = models.TextField(
        default="Captcha",
        help_text=_("Captcha field for the registration page")
    )
    register_username_field = models.TextField(
        default="Username",
        help_text=_("Username field for the registration page")
    )
    register_phone_field = models.TextField(
        default="Phone number",
        help_text=_("Phone field for the registration page")
    )
    register_password1_field = models.TextField(
        default="Password",
        help_text=_("Password field for the registration page")
    )
    register_password2_field = models.TextField(
        default="Password confirmation",
        help_text=_("Password confirmation field for the registration page")
    )
    register_email_field = models.TextField(
        default="Email",
        help_text=_("Email field for the registration page")
    )
    register_submit_field = models.TextField(
        default="Register",
        help_text=_("Password confirmation field for the registration page")
    )

    def __str__(self):
        return str(self.name)

    def to_dict(self):
        data = model_to_dict(self)
        data['id'] = str(self.pk)
        return data

    def to_template(self):
        return self.to_dict()

    @staticmethod
    def str_attrs():
        """ List of attributes required by __str__ method """
        return ['name']

    def write_on_disk(self):
        """
        Write the templates on disk
        :return: True if everything went right, False otherwise
        """
        tpl_list = ('html_login',
                    'html_logout',
                    'html_otp',
                    'html_message',
                    'html_learning',
                    'html_self',
                    'html_password',
                    'html_registration',
                    'email_subject',
                    'email_body',
                    'html_error',
                    'email_register_subject',
                    'email_register_body'
                    )
        for tpl in tpl_list:
            if tpl == 'html_error':
                continue

            try:
                with open("/usr/local/etc/haproxy.d/templates/portal_%s_%s.conf" % (str(self.id), tpl),
                          'w') as f:
                    html = getattr(self, tpl)
                    if tpl not in ["email_subject", "email_body", "email_register_subject", "email_register_body"]:
                        html = html.replace("{{form_begin}}", "{{form_begin}}{% csrf_token %}")
                        html = "{% autoescape off %}\n" + html + "\n" + "{% endautoescape %}"

                    f.write(html.encode("UTF-8"))
            except Exception as e:
                pass

        try:
            with open("/home/vlt-gui/vulture/portal/templates/portal_%s.css" % (str(self.id)), 'w') as f:
                f.write(self.css.encode("UTF-8"))
        except Exception as e:
            pass

        for message in ('html_error_403', 'html_error_404', 'html_error_405', 'html_error_406', 'html_error_500', 'html_error_501', 'html_error_502', 'html_error_503', 'html_error_504'):
            tpl = Template(self.html_error)
            tpl = tpl.render(Context({'message': getattr(self, message), 'style': self.css}))
            with open("/home/vlt-gui/vulture/portal/templates/portal_{}_{}.html".format(str(self.id), message),
                      'w') as f:
                f.write(tpl.encode('UTF-8'))

    def attrs_dict(self):
        """ Return all fields attributes """
        result = {
            'login_login_field': self.login_login_field,
            'login_password_field': self.login_password_field,
            'login_captcha_field': self.login_captcha_field,
            'login_submit_field': self.login_submit_field,
            'learning_submit_field': self.learning_submit_field,
            'password_old_field': self.password_old_field,
            'password_new1_field': self.password_new1_field,
            'password_new2_field': self.password_new2_field,
            'password_email_field': self.password_email_field,
            'password_submit_field': self.password_submit_field,
            'otp_key_field': self.otp_key_field,
            'otp_submit_field': self.otp_submit_field,
            'otp_resend_field': self.otp_resend_field,
            'otp_onetouch_field': self.otp_onetouch_field,
            'register_captcha_field': self.register_captcha_field,
            'register_username_field': self.register_username_field,
            'register_phone_field': self.register_phone_field,
            'register_password1_field': self.register_password1_field,
            'register_password2_field': self.register_password2_field,
            'register_email_field': self.register_email_field,
            'register_submit_field': self.register_submit_field,
            'input_login': INPUT_LOGIN,
            'input_password': INPUT_PASSWORD,
            'input_captcha': INPUT_CAPTCHA,
            'input_otp_key': INPUT_OTP_KEY,
            'input_otp_resend': INPUT_OTP_RESEND,
            'reset_password_name': RESET_PASSWORD_NAME,
            'input_password_old': INPUT_PASSWORD_OLD,
            'input_password_1': INPUT_PASSWORD_1,
            'input_password_2': INPUT_PASSWORD_2,
            'INPUT_EMAIL': INPUT_EMAIL,
            'style': self.css
        }
        for image in TemplateImage.objects.all():
            result[f"image_{image.id}"] = image.create_preview_html()
        return result

    def render_template(self, tpl_name, **kwargs):
        tpl = Template(getattr(self, tpl_name))
        # Routine to concatenate kwargs to attibutes, to prevent erase of kwargs
        attrs = self.attrs_dict()
        for key in attrs.keys():
            if kwargs.get(key):
                # Kwargs will win, so put concatenation into kwargs
                kwargs[key] = attrs[key] + kwargs[key]
        return tpl.render(Context({**attrs, **kwargs}))

    def tpl_filename(self, tpl_name, portal_id=None):
        return f"{HAPROXY_PATH}/templates/{tpl_name}_{portal_id or self.id}.html"

    def write_template(self, tpl_name, **kwargs):
        """ This method has to be called by api_request (Vultured) """
        filename = self.tpl_filename(tpl_name)
        write_conf(logger, [self.tpl_filename(tpl_name, kwargs.get('portal_id')), HAPROXY_HEADER+self.render_template(tpl_name, **kwargs), HAPROXY_OWNER, HAPROXY_PERMS])
        return "Template {} successfully written".format(filename)


class TemplateImage(models.Model):
    """
    Vulture's portal template image.
    """
    name = models.TextField(default="", help_text=_('The name of the image'))
    image_type = models.TextField(default="")
    content = models.TextField(default="", help_text=_('Image you can use in the portal templates'))

    def to_dict(self):
        return {
            "id": str(self.pk),
            "name": self.name,
            "image_type": self.image_type,
            "create_preview_html": self.create_preview_html(),
            "get_image_uri": self.get_image_uri()
        }

    def get_image_uri(self):
        """
        Return the URI of the image.
        :return: String containing the URI of the image.
        """
        try:
            url = 'portal_statics/{}'.format(self.uid)
        except:
            return None

        return url

    def get_as_html(self):
        """
        Return a pre-formatted html containing the image.
        :return: A string with pre-formatted html for the image
        """

        return "<img src='data:image/{};base64,{}'/>".format(self.image_type, self.content)

    def create_preview_html(self):
        """
        Return a pre-formatted html containing the image.
        :return: A string with pre-formatted html for the image
        """

        return "data:image/{};base64,{}".format(self.image_type, self.content)
