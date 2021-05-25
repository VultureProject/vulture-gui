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
__doc__ = 'TOTP profiles model'

# Django system imports
from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from django.forms.models import model_to_dict
from djongo import models

# Django project imports
from toolkit.system.aes_utils import AESCipher

# Extern modules imports

# Required exceptions imports

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


class TOTPProfile(models.Model):
    """ Class for Learning Profiles

    Encryption is done via AES256
    """
    auth_repository = models.ForeignKey(
        to="authentication.BaseRepository",
        verbose_name=_("Authentication repository"),
        default=None,
        on_delete=models.CASCADE
    )
    totp_repository = models.ForeignKey(
        to="authentication.OTPRepository",
        verbose_name=_("TOTP authentication repository"),
        default=None,
        on_delete=models.CASCADE,
        related_name="totp_profiles_of"
    )
    login = models.TextField(
        verbose_name=_("User's login"),
        default=""
    )
    encrypted_value = models.TextField(default="")

    class meta:
        unique_together = ("auth_repository", "totp_repository", "login")

    def decrypt(self):
        """
        :return: Return the password in cleartext
        """
        aes = AESCipher(str(settings.SECRET_KEY)+str(self.login))
        data = aes.decrypt(self.encrypted_value)
        if str(data) == '':
            return None
        return data

    def set_data(self, value):
        """
        :return: Return the encrypted value
        """
        aes = AESCipher(str(settings.SECRET_KEY)+str(self.login))
        self.encrypted_value = aes.encrypt(str(value)).decode('utf8')
        return self.encrypted_value

    def store(self):
        self.save()

    def to_dict(self):
        return {
            'id': str(self.id),
            "auth_repository": str(self.auth_repository.id),
            "totp_repository": str(self.totp_repository.id),
            "login": str(self.login)
        }

    def to_template(self):
        """  returns the attributes of the class """
        return {
            'id': str(self.id),
            'auth_repository': str(self.auth_repository),
            'totp_repository': str(self.totp_repository),
            'login': self.login
        }
