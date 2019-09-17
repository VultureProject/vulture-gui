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
__author__ = "Kevin Guillemot"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'PyOTP wrapper (for TOTP authentication)'


# Django system imports
from django.conf import settings

# Django project imports
from authentication.learning_profiles.models import LearningProfile
from authentication.base_repository import BaseRepository
from toolkit.auth.base_auth import BaseAuth
from toolkit.system.aes_utils import AESCipher

# Required exceptions imports
from toolkit.auth.exceptions  import AuthenticationError, OTPError, RegisterAuthenticationError

# Extern modules imports
from pyotp import random_base32 as pyotp_random_base32, TOTP

# Logger configuration imports
import logging
logger = logging.getLogger('authentication')


class TOTPClient(BaseAuth):
    def __init__(self, settings):
        """ Instantiation method

        :param settings:
        :return:
        """
        # Connection settings
        self.type = settings.otp_type

    def generate_captcha(self, user_id, email):
        return TOTP(user_id).provisioning_uri(email, issuer_name="Vulture App")

    # WARNING : Do not touch this method, Big consequences !
    def authenticate(self, user_id, key):
        logger.debug("")
        totp = TOTP(user_id)
        if not totp.verify(key):
            raise AuthenticationError("TOTP taped token is not valid.")
        return True

    def register_authentication(self, app_id, app_name, backend_id, login):
        """ This method interract with SSOProfile objects in Mongo """
        """ Try to retrieve the SSOProfile in internal database """
        try:
            logger.debug("TOTP::Register_authentication: Trying to retrieve encrypted key in Mongo")
            aes = AESCipher("{}{}{}{}{}".format(settings.SECRET_KEY, app_id, backend_id, login, "totp"))
            encrypted_field = aes.key.encode('hex')
            sso_profile = LearningProfile.objects.filter(encrypted_name=encrypted_field, login=login).first()
            if sso_profile:
                logger.info("TOTP::Register_authentication: Encrypted key successfully retrieved from Mongo")
                decrypted_value = sso_profile.get_data(sso_profile.encrypted_value, app_id, backend_id, login, "totp")
                if decrypted_value:
                    logger.info("TOTP:Register_authentication: Encrypted key successfully decrypted")
                    return False, decrypted_value
        except Exception as e:
            logger.exception(e)
            raise e

        logger.info("TOTP secret key not found. Creating-it.")

        """ If the SSOProfile does not exists, create-it and save-it """
        try:
            # returns a 16 character base32 secret.
            # Compatible with Google Authenticator and other OTP apps
            new_key = pyotp_random_base32()
            # Save in Mongo
            sso_profile = LearningProfile()
            sso_profile.set_data(app_id, app_name, backend_id, BaseRepository.objects.get(pk=backend_id).name,
                                 login, "totp", new_key)
            sso_profile.store()
            return True, new_key
        except Exception as e:
            logger.exception(e)
            raise e
