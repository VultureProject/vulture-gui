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
__doc__ = 'OTP Repository model'

# Django system imports
from django.conf import settings
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils.translation import ugettext_lazy as _
from djongo import models

# Django project imports
from authentication.base_repository import BaseRepository
from toolkit.auth.authy_client import AuthyClient
from toolkit.auth.vulturemail_client import VultureMailClient
from toolkit.auth.totp_client import TOTPClient

# Extern modules imports

# Required exceptions imports

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')

OTP_TYPE = (
    ('phone', 'Phone'),
    ('email', 'Email'),
    ('onetouch', 'OneTouch'),
    ('totp', 'Time-based OTP'),
)

OTP_PHONE_SERVICE = (
    ('authy', 'Authy (sms and mobile app)'),
)

OTP_MAIL_SERVICE = (
    ('vlt_mail_service', 'Vulture mail service'),
)


class OTPRepository(BaseRepository):
    """ Class used to represent an OTP repository object

    api_key: API Key to contact Authy service
    key_length: Temporary key length sent to the user
    otp_type: Type of double authentication
    otp_phone_service: Type of phone service
    otp_mail_service: Type of mail service
    """
    """  """
    otp_type = models.TextField(
        verbose_name=_('Authentication type'),
        default=OTP_TYPE[0][0],
        choices=OTP_TYPE,
        help_text=_('Type of OTP authentication')
    )
    otp_phone_service = models.TextField(
        verbose_name=_("Phone service"),
        default=OTP_PHONE_SERVICE[0][0],
        choices=OTP_PHONE_SERVICE,
        help_text=_('Phone service for OTP')
    )
    api_key = models.TextField(
        default="",
        verbose_name=_("API Key"),
        help_text=_('API KEY for Authy service')
    )
    otp_mail_service = models.TextField(
        verbose_name=_("Mail service"),
        default=OTP_MAIL_SERVICE[0][0],
        choices=OTP_MAIL_SERVICE,
        help_text=_('Mail service for OTP')
    )
    key_length = models.PositiveIntegerField(
        verbose_name=_("Key length"),
        default=8,
        validators=[MinValueValidator(8), MaxValueValidator(20)],
        help_text=_('Key length for email authentication')
    )

    def __str__(self):
        return "{} ({})".format(self.name, self.str_otp_type())

    @staticmethod
    def str_attrs():
        """ List of attributes required by __str__ method """
        return ['name', 'otp_type']

    def str_otp_type(self):
        otp_type = "UNKNOWN"
        for otype in OTP_TYPE:
            if otype[0] == self.otp_type:
                otp_type = otype[1]
        return otp_type

    def str_phone_service(self):
        phone_service = "UNKNOWN"
        for service in OTP_PHONE_SERVICE:
            if service[0] == self.otp_phone_service:
                phone_service = service[1]
        return phone_service

    def str_mail_service(self):
        mail_service = "UNKNOWN"
        for service in OTP_MAIL_SERVICE:
            if service[0] == self.otp_mail_service:
                mail_service = service[1]
        return mail_service

    def to_template(self):
        """ Returns the attributes of the class """
        return {
            'id': str(self.id),
            'name': self.name
        }

    def to_html_template(self):
        """ Returns needed attributes for html rendering """
        result = {
            'id': str(self.id),
            'name': self.name,
            'otp_type': self.str_otp_type()
        }
        if self.otp_type == "mail":
            result['otp_service'] = self.str_mail_service()
            result['additional_infos'] = "Key length = {}".format(self.key_length)
        else:
            result['otp_service'] = self.str_phone_service()
            result['additional_infos'] = "API key = {}".format(self.api_key)
        return result

    # Do NOT forget this on all BaseRepository subclasses
    def save(self, *args, **kwargs):
        self.subtype = "OTP"
        super().save(*args, **kwargs)

    def get_client(self):
        if self.otp_phone_service == "authy" and self.otp_type in ["phone", "onetouch"]:
            return AuthyClient(self)
        elif self.otp_type == 'email' and self.otp_mail_service == 'vlt_mail_service':
            return VultureMailClient(self)
        elif self.otp_type == "totp":
            return TOTPClient(self)
        else:
            raise NotImplemented("OTP client type not implemented yet")

