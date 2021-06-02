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
__doc__ = 'LDAP Repository model'

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


class LearningProfile(models.Model):
    """ Class for Learning Profiles

    encrypted_name: The encrypted name of the stored value
    encrypted_value: The encrypted value

    Encryption Key is derived from the main user login, the application id, the backend_id  and the value name
        encryption_key=sha256('app_id' + 'backend_id' + 'login' + 'name')
        Encryption is done via AES256
    """
    app_name = models.TextField(
        verbose_name=_("Backend name of this Learning Profile"),
        default=""
    )
    repo_name = models.TextField(
        verbose_name=_("Authentication repository name of this Learning Profile"),
        default=""
    )
    login = models.TextField(
        verbose_name=_("Login of user using this Learning Profile"),
        default=""
    )
    encrypted_name = models.TextField(default="")
    encrypted_value = models.TextField(default="")

    def __str__(self):
        return f"Workflow='{self.app_name}' Repo='{self.repo_name}' User='{self.login}'"


    def get_data(self, to_decrypt, app_id, backend_id, login, name):
        """
        :return: Return the password in cleartext
        """
        self.encrypted_value = to_decrypt
        aes = AESCipher(str(settings.SECRET_KEY)+str(app_id)+str(backend_id)+str(login)+str(name))
        self.encrypted_name = aes.key.hex()
        data = aes.decrypt(self.encrypted_value)
        if str(data) == '':
            return None
        return data

    def set_data(self, app_id, app_name, backend_id, repo_name, login, name, value):
        """
        :return: Return the encrypted value
        """
        aes = AESCipher(str(settings.SECRET_KEY)+str(app_id)+str(backend_id)+str(login)+str(name))
        self.app_name = str(app_name)
        self.repo_name = str(repo_name)
        self.login = str(login)
        self.encrypted_value = aes.encrypt(str(value)).decode('utf8')
        self.encrypted_name = aes.key.hex()
        return self.encrypted_value

    def store(self):
        self.save()

    def to_dict(self):
        return model_to_dict(self)

    def to_template(self):
        """  returns the attributes of the class """
        return {
            'id': str(self.id),
            'app_name': self.app_name,
            'repo_name': self.repo_name,
            'login': self.login
        }
