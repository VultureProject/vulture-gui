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
from authentication.totp_profiles.models import TOTPProfile
from toolkit.auth.base_auth import BaseAuth

# Required exceptions imports
from toolkit.auth.exceptions  import AuthenticationError, OTPError, RegisterAuthenticationError

# Extern modules imports
from pyotp import random_base32 as pyotp_random_base32, TOTP

# Logger configuration imports
import logging
logger = logging.getLogger('portal_authentication')


class TOTPClient(BaseAuth):
    def __init__(self, settings):
        """ Instantiation method

        :param settings:
        :return:
        """
        # Connection settings
        self.type = settings.otp_type
        self.label = settings.totp_label
        self.otp_repo = settings

    def generate_captcha(self, user_id, email):
        return TOTP(user_id).provisioning_uri(email, issuer_name=self.label)

    # WARNING : Do not touch this method, Big consequences !
    def authenticate(self, user_id, key, **kwargs):
        results = {}
        totp = TOTP(user_id)
        if not totp.verify(key):
            raise AuthenticationError("Provided TOTP token is not valid for TOTP id {}.".format(user_id))

        logger.info("TOTP Token for user {} successfully verified.".format(user_id))

        # If the SSOProfile is not yet in MongoDB, set-it
        workflow = kwargs['app']
        auth_backend = kwargs['backend']
        login = kwargs['login']

        try:
            # Save in Mongo
            totp_profile, created = TOTPProfile.objects.get_or_create(auth_repository=auth_backend,
                                                             totp_repository=self.otp_repo,
                                                             login=login)
            if created:
                totp_profile.set_data(user_id)
                totp_profile.store()
                logger.info("TOTP token for user {} stored in database.".format(login))

            return results

        except Exception as e:
            logger.exception(e)
            raise e

    def register_authentication(self, **kwargs):
        auth_backend = kwargs['backend']
        login = kwargs['login']

        """ This method interract with SSOProfile objects in Mongo """
        """ Try to retrieve the SSOProfile in internal database """
        try:
            logger.debug("TOTP::Register_authentication: Trying to retrieve encrypted key in Mongo")
            totp_profile = TOTPProfile.objects.get(auth_repository=auth_backend,
                                                   totp_repository=self.otp_repo,
                                                   login=login)
            logger.info("TOTP::Register_authentication: Encrypted key successfully retrieved from Mongo")
            decrypted_value = totp_profile.decrypt()
            if decrypted_value:
                logger.info("TOTP:Register_authentication: Encrypted key successfully decrypted")
                return False, decrypted_value
        except TOTPProfile.DoesNotExist:
            pass
        except Exception as e:
            logger.exception(e)
            raise e

        logger.info("TOTP secret key not found. Creating-it.")

        """ If the SSOProfile does not exists, create-it and save-it """
        try:
            # returns a 16 character base32 secret.
            # Compatible with Google Authenticator and other OTP apps
            new_key = pyotp_random_base32()
            return True, new_key
        except Exception as e:
            logger.exception(e)
            raise e
