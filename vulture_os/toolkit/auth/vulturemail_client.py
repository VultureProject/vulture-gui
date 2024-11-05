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
from system.cluster.models import Cluster
from toolkit.auth.base_auth import BaseAuth

# Required exceptions imports

# Extern modules imports
import smtplib
from email.mime.text import MIMEText
from django.utils.crypto import get_random_string

# Logger configuration imports
import logging
logger = logging.getLogger('authentication')


class VultureMailClient(BaseAuth):
    def __init__(self, settings):
        """ Instantiation method

        :param settings:
        :return:
        """
        # Connection settings
        self.type = settings.otp_type
        self.mail_service = settings.otp_mail_service
        self.key_length = settings.key_length

    def authenticate(self, user_id, key):
        raise NotImplementedError('Simple compare does not require a function')

    def register_authentication(self, sender, recipient):
        chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
        secret_key = get_random_string(self.key_length, chars)

        msg = MIMEText("Vulture authentication\r\nThis is your secret key: {}".format(secret_key))
        msg['Subject'] = 'Vulture OTP Authentication'
        msg['From'] = sender
        msg['To'] = recipient

        config = Cluster.get_global_config()
        smtp_server = config.smtp_server

        if not smtp_server:
            logger.error("VultureMailClient::register_authentication: Cluster SMTP settings not configured")
            raise smtplib.SMTPException("Vulture mail service not configured")

        server = smtplib.SMTP(smtp_server)
        message = "Subject: " + str(msg['Subject']) + "\n\n" + str(msg)
        server.sendmail(msg['from'], recipient, message)
        server.quit()

        return secret_key
