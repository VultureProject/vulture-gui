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
__doc__ = 'AuthyApiClient wrapper'


# Django system imports

# Django project imports
from django.conf import settings
from toolkit.auth.base_auth import BaseAuth

# Required exceptions imports
#from portal.system.exceptions import TwoManyOTPAuthFailure
from toolkit.auth.exceptions import AuthenticationError, OTPError, RegisterAuthenticationError

# Extern modules imports
from authy.api import AuthyApiClient

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('authentication')


class AuthyClient(BaseAuth):
    def __init__(self, settings):
        """ Instantiation method

        :param settings:
        :return:
        """
        # Connection settings
        self.type = settings.otp_type
        self.phone_service = settings.otp_phone_service
        self.mail_service = settings.otp_mail_service
        self.authy_api_key = settings.api_key

    # WARNING : Do not touch this method, Big consequences !
    def authenticate(self, user_id, key):
        authy_client = AuthyApiClient(str(self.authy_api_key))
        try:
            if self.type == 'phone':
                verification = authy_client.tokens.verify(str(user_id), str(key))
                if verification.ok():
                    return True
            elif self.type == 'onetouch':
                # It's not the user_id but the 'send_request()' response that is sent here (bad variable name)
                verification = authy_client.one_touch.get_approval_status(str(user_id))
        except Exception as e:
            logger.error("AUTHY_CLIENT::authenticate: Error while trying to verify given key : {}".format(e))
            raise OTPError("Authy error while verificating token : {}".format(str(e)))

        if self.type == 'onetouch':
            if verification.ok() and verification.status():
                if verification.content.get('approval_request', {}).get('status') == 'approved':
                    return True
                elif verification.content.get('approval_request', {}).get('status') == 'denied':
                    # FIXME
                    #raise TwoManyOTPAuthFailure("The OneTouch request has been denied by the user")
                    raise OTPError("The OneTouch request has been denied by the user")
                else:
                    raise OTPError("The OneTouch request is not yet approved, "
                                   "status : {}".format(verification.content.get('approval_request', {}).get('status')))

        # If we arrive here : verification.ok() returned False ; Authentication failure
        raise AuthenticationError("Authy authentication error while verificating token : "
                                  "{}".format(verification.errors()))

    def register_authentication(self, user_mail, user_phone):
        authy_client = AuthyApiClient(str(self.authy_api_key))
        user         = authy_client.users.create(str(user_mail), str(user_phone), 33)
        if not user.ok():
            logger.error("AUTHY_CLIENT::register_authentication: Creation of new user in authy with mail:'{}', "
                         "phone:'{}' failure : {}".format(user_mail, user_phone, user.errors()))
            raise RegisterAuthenticationError("Unable to register Authy user with mail:'{}', "
                                              "phone:'{}' : {}".format(user_mail, user_phone, user.errors()))

        authy_functions = {
            'phone'    : authy_client.users.request_sms(str(user.id)),
            'onetouch' : authy_client.one_touch.send_request(user.id, "Login requested for Vulture authentication",
                                                             120, {}, {},
                                                             [
                                                                 {
                                                                     'res': "default",
                                                                     'url': "https://www.vultureproject.org/assets/images/logo_mini.png"
                                                                 },
                                                                 {
                                                                     'res': "low",
                                                                     'url': "https://www.vultureproject.org/assets/images/logo_mobile.png"
                                                                 }
                                                             ])
        }

        response = authy_functions[self.type]
        if not response.ok():
            logger.error("AUTHY_CLIENT::register_authentication: Unable to send request to '{}':"
                         " {}".format(user_phone, response.errors()))
            raise RegisterAuthenticationError("Unable to send Authy request to '{}' : {}".format(user_phone,
                                                                                                 response.errors()))

        if self.type == 'phone':
            return str(user.id)

        return response.get_uuid()
