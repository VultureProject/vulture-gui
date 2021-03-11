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
__author__ = "Kevin GUILLEMOT"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Backends & Servers dedicated form classes'

# Django system imports
from django.conf import settings
from django.forms import CheckboxInput, ModelForm, NumberInput, Select, TextInput, Textarea, Form, \
    ChoiceField, CharField

# Django project imports
from gui.forms.form_utils import NoValidationField
from authentication.portal_template.models import PortalTemplate, TemplateImage
from system.pki.models import TLSProfile

# Required exceptions imports

# Extern modules imports

# Logger configuration imports
import logging

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


class PortalTemplateForm(ModelForm):
    """ Application form representation
    """
    class Meta:
        model = PortalTemplate
        fields = ("name", "css",
                  "html_login", "html_learning", "html_logout", "html_self", "html_password", "html_otp", "html_message", "html_error", "html_registration",
                  "html_error_403", "html_error_404", "html_error_405", "html_error_406", "html_error_500", "html_error_501", "html_error_502", "html_error_503", "html_error_504",
                  "email_subject", "email_body", "email_from", "error_email_sent", "email_register_subject", "email_register_from", "email_register_body",
                  "login_login_field", "login_password_field", "login_captcha_field", "login_submit_field",
                  "learning_submit_field", "password_old_field", "password_new1_field", "password_new2_field", "password_email_field", "password_submit_field",
                  "otp_key_field", "otp_submit_field", "otp_resend_field", "otp_onetouch_field",
                  "register_captcha_field", "register_username_field", "register_phone_field", "register_password1_field", "register_password2_field", "register_email_field", "register_submit_field",
                  "error_password_change_ok", "error_password_change_ko")
        widgets = {
            'name': TextInput(attrs={'class': 'form-control'}),
            'css': Textarea(attrs={'class': 'form-control', 'data-placement':"right"}),
            'html_login': Textarea(attrs={'class': 'form-control', 'data-placement':"right"}),
            'html_learning': Textarea(attrs={'class': 'form-control', 'data-placement':"right"}),
            'html_logout': Textarea(attrs={'class': 'form-control', 'data-placement':"right"}),
            'html_self': Textarea(attrs={'class': 'form-control', 'data-placement':"right"}),
            'html_password': Textarea(attrs={'class': 'form-control', 'data-placement':"right"}),
            'html_otp': Textarea(attrs={'class': 'form-control', 'data-placement':"right"}),
            'html_message': Textarea(attrs={'class': 'form-control', 'data-placement':"right"}),
            'html_error': Textarea(attrs={'class': 'form-control', 'data-placement':"right"}),
            'html_registration': Textarea(attrs={'class': 'form-control', 'data-placement':"right"}),

            'html_error_403': Textarea(attrs={'class': 'form-control', 'data-placement':"right"}),
            'html_error_404': Textarea(attrs={'class': 'form-control', 'data-placement':"right"}),
            'html_error_405': Textarea(attrs={'class': 'form-control', 'data-placement':"right"}),
            'html_error_406': Textarea(attrs={'class': 'form-control', 'data-placement':"right"}),
            'html_error_500': Textarea(attrs={'class': 'form-control', 'data-placement':"right"}),
            'html_error_501': Textarea(attrs={'class': 'form-control', 'data-placement':"right"}),
            'html_error_502': Textarea(attrs={'class': 'form-control', 'data-placement':"right"}),
            'html_error_503': Textarea(attrs={'class': 'form-control', 'data-placement':"right"}),
            'html_error_504': Textarea(attrs={'class': 'form-control', 'data-placement':"right"}),
            'email_subject': TextInput(attrs={'class': 'form-control', 'data-placement':"right"}),
            'email_body': Textarea(attrs={'class': 'form-control', 'data-placement':"right"}),
            'email_from': TextInput(attrs={'class': 'form-control'}),
            'error_password_change_ok': TextInput(attrs={'class': 'form-control', 'data-placement':"right"}),
            'error_password_change_ko': TextInput(attrs={'class': 'form-control', 'data-placement':"right"}),
            'error_email_sent': Textarea(attrs={'class': 'form-control', 'data-placement':"right"}),
            'email_register_subject': TextInput(attrs={'class': 'form-control', 'data-placement':"right"}),
            'email_register_from': TextInput(attrs={'class': 'form-control'}),
            'email_register_body': Textarea(attrs={'class': 'form-control', 'data-placement':"right"}),
            'login_login_field': TextInput(attrs={'class': 'form-control'}),
            'login_password_field': TextInput(attrs={'class': 'form-control'}),
            'login_captcha_field': TextInput(attrs={'class': 'form-control'}),
            'login_submit_field': TextInput(attrs={'class': 'form-control'}),
            'learning_submit_field': TextInput(attrs={'class': 'form-control'}),
            'password_old_field': TextInput(attrs={'class': 'form-control'}),
            'password_new1_field': TextInput(attrs={'class': 'form-control'}),
            'password_new2_field': TextInput(attrs={'class': 'form-control'}),
            'password_email_field': TextInput(attrs={'class': 'form-control'}),
            'password_submit_field': TextInput(attrs={'class': 'form-control'}),
            'otp_key_field': TextInput(attrs={'class': 'form-control'}),
            'otp_submit_field': TextInput(attrs={'class': 'form-control'}),
            'otp_resend_field': TextInput(attrs={'class': 'form-control'}),
            'otp_onetouch_field': TextInput(attrs={'class': 'form-control'}),
            'register_captcha_field': TextInput(attrs={'class': 'form-control'}),
            'register_username_field': TextInput(attrs={'class': 'form-control'}),
            'register_phone_field': TextInput(attrs={'class': 'form-control'}),
            'register_password1_field': TextInput(attrs={'class': 'form-control'}),
            'register_password2_field': TextInput(attrs={'class': 'form-control'}),
            'register_email_field': TextInput(attrs={'class': 'form-control'}),
            'register_submit_field': TextInput(attrs={'class': 'form-control'}),
        }

    def __init__(self, *args, **kwargs):
        """ Initialize form and special attributes """
        super().__init__(*args, **kwargs)


class TemplateImageForm(ModelForm):
    """ Image insertion form représentation
    """

    class Meta:
        document = TemplateImage
        widgets = {
            'name': TextInput(attrs={'class': 'form-control'}),
        }
