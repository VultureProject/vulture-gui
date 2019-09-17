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
from djongo import models

# Django project imports

# Extern modules imports
import base64

# Required exceptions imports

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


class portalTemplate(models.Model):
    """ Vulture portal's template model representation
    name: A friendly name for the template
    css: css content
    html_login: html_content
    """
    name = models.TextField(help_text=_('Friendly name to reference the template'))
    css = models.TextField(help_text=_('Cascading Style Sheet for template'))
    html_login = models.TextField(help_text=_('HTML Content for the login page'))
    html_learning = models.TextField(null=True, default="", help_text=_('HTML Content for the learning page'))
    html_logout = models.TextField(null=True, default="", help_text=_('HTML Content for the logout page'))
    html_self = models.TextField(null=True, default="", help_text=_('HTML Content for the self-service page'))
    html_password = models.TextField(null=True, default="", help_text=_('HTML Content for the password change page'))
    html_otp = models.TextField(null=True, default="", help_text=_('HTML Content for the otp page'))
    html_message = models.TextField(null=True, default="", help_text=_('HTML Content for the message page'))
    html_error = models.TextField(null=True, default="", help_text=_('HTML General content for error pages'))
    html_registration = models.TextField(null=True, default="", help_text=_('HTML Content for registration pages'))
    html_error_403 = models.TextField(null=True, default="403 Forbidden", help_text=_('HTML message for 403 Forbidden error'))
    html_error_404 = models.TextField(null=True, default="404 Not Found", help_text=_('HTML message for 404 Not Found error'))
    html_error_405 = models.TextField(null=True, default="405 Method Not Allowed", help_text=_('HTML message for 405 Method Not Allowed error'))
    html_error_406 = models.TextField(null=True, default="406 Not Acceptable", help_text=_('HTML message for 406 Not Acceptable error'))
    html_error_500 = models.TextField(null=True, default="500 Server Error", help_text=_('HTML message for 500 Server Error error'))
    html_error_501 = models.TextField(null=True, default="501 Not Implemented", help_text=_('HTML message for 501 Not Implemented error'))
    html_error_502 = models.TextField(null=True, default="502 Bad Gateway", help_text=_('HTML message for 502 Bad Gateway / Proxy error'))
    html_error_503 = models.TextField(null=True, default="503 Service Unavailable", help_text=_('HTML message for 503 Service Unavailable error'))
    html_error_504 = models.TextField(null=True, default="504 Gateway Time-out", help_text=_('HTML message for 504 Gateway Time-out error'))
    email_subject = models.TextField(null=True, default="", help_text=_('Email subject for password reset'))
    email_body = models.TextField(null=True, default="", help_text=_('Email content for password reset'))
    email_from = models.TextField(null=True, default="", help_text=_('Email "From" for password reset'))
    error_password_change_ok = models.TextField(null=True, default="", help_text=_('Your password has been changed'))
    error_password_change_ko = models.TextField(null=True, default="", help_text=_('Error when trying to change your password'))
    error_email_sent = models.TextField(null=True, default="", help_text=_('An email has been sent to you with instruction to reset your password'))
    images = models.ListField(models.ImageField(null=True), default=[], help_text=_('Images you can use in your templates'))
    email_register_subject = models.TextField(null=True, default="", help_text=_('Email subject for registration'))
    email_register_from = models.TextField(null=True, default="", help_text=_('Email content for registration'))
    email_register_body = models.TextField(null=True, default="", help_text=_('Email sender for registration'))
    """ Input fields value """
    login_login_field = models.TextField(null=True, default="Login", help_text=_("Login field for the log-in page"))
    login_password_field = models.TextField(null=True, default="Password", help_text=_("Password field for the log-in page"))
    login_captcha_field = models.TextField(null=True, default="Captcha", help_text=_("Captcha field for the log-in page"))
    login_submit_field = models.TextField(null=True, default="Sign in", help_text=_("Submit field for the log-in page"))
    learning_submit_field = models.TextField(null=True, default="Save", help_text=_("Submit field for the learning page"))
    password_old_field = models.TextField(null=True, default="Old password", help_text=_("Old password field for the password page"))
    password_new1_field = models.TextField(null=True, default="New password", help_text=_("New password field for the password page"))
    password_new2_field = models.TextField(null=True, default="Confirmation", help_text=_("Confirmation password field for the password page"))
    password_email_field = models.TextField(null=True, default="Email", help_text=_("Email field for the password page"))
    password_submit_field = models.TextField(null=True, default="OK", help_text=_("Submit field for the password page"))
    otp_key_field = models.TextField(null=True, default="Key", help_text=_("OTP Key field for the OTP page"))
    otp_submit_field = models.TextField(null=True, default="Sign in", help_text=_("Submit field for the OTP page"))
    otp_resend_field = models.TextField(null=True, default="Resend", help_text=_("Resend field for the OTP page"))
    otp_onetouch_field = models.TextField(null=True, default="<p>Please approve the OneTouch request on your phone, and click on 'Sign in'</p>", help_text=_("Onetouch message for the OTP page"))
    register_captcha_field = models.TextField(null=True, default="Captcha", help_text=_("Captcha field for the registration page"))
    register_username_field = models.TextField(null=True, default="Username", help_text=_("Username field for the registration page"))
    register_phone_field = models.TextField(null=True, default="Phone number", help_text=_("Phone field for the registration page"))
    register_password1_field = models.TextField(null=True, default="Password", help_text=_("Password field for the registration page"))
    register_password2_field = models.TextField(null=True, default="Password confirmation", help_text=_("Password confirmation field for the registration page"))
    register_email_field = models.TextField(null=True, default="Email", help_text=_("Email field for the registration page"))
    register_submit_field = models.TextField(null=True, default="Register", help_text=_("Password confirmation field for the registration page"))

    def __str__(self):
        return str(self.name)

    @staticmethod
    def str_attrs():
        """ List of attributes required by __str__ method """
        return ['name']

    def render_html_login(self, kwargs):
        """  """
        return Template("{% autoescape off %}<style>" + self.css + "</style>" +
                        self.html_login +
                        "{% endautoescape %}").render(Context(kwargs))

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
                with open("/home/vlt-gui/vulture/portal/templates/portal_%s_%s.conf" % (str(self.id), tpl),
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

    def __str__(self):
        return "{}" .format(self.name.encode('utf8', 'ignore'))


class TemplateImage(models.Model):
    """
    Vulture's portal template image.
    """
    name = models.TextField(help_text=_('The name of the image'))
    content = models.ImageField(help_text=_('Image you can use in the portal templates'))
    uid = models.TextField(null=True, help_text=_('A unique identifier to get the image from portal'))

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

        return "<img src='data:image/{};base64,{}'/>".format(self.content.format.lower(), base64.b64encode(self.content.read()))

    def create_preview_html(self):
        """
        Return a pre-formatted html containing the image.
        :return: A string with pre-formatted html for the image
        """

        return "data:image/{};base64,{}".format(self.content.format.lower(), base64.b64encode(self.content.read()))
