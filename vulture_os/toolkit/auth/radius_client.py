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
__version__ = "3.0.0"
__maintainer__ = "Vulture Project"
__email__ = "contact@vultureproject.org"
__doc__ = 'Radius authentication client wrapper'


# Django system imports
from django.conf import settings

# Django project imports
from toolkit.auth.base_auth import BaseAuth

# Extern modules imports
from os.path import join as path_join
from pyrad.client import Client
from pyrad.client import Timeout
from pyrad.dictionary import Dictionary
import pyrad.packet

# Required exceptions imports
from toolkit.auth.exceptions import AuthenticationError

# Logger configuration
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('authentication')


DICTIONARY_PATH = path_join(settings.LOCALETC_PATH, "radiusclient/dictionary")


class RadiusClient(BaseAuth):

    def __init__(self, settings):
        """ Instantiation method

        :param settings:
        :return:
        """
        # Connection settings
        self.host = settings.host
        self.port = settings.port
        self.nas_id = settings.nas_id
        try:
            self.secret = settings.secret.encode('utf-8')
        except Exception:
            self.secret = ""
        self.max_retry = settings.retry
        self.max_timeout = settings.timeout

    def authenticate(self, username, password, **kwargs):
        # """Authentication method of LDAP repository, which returns dict of specified attributes:their values
        # :param username: String with username
        # :param password: String with password
        # :param oauth2_attributes: List of attributes to retrieve
        # :return: None and raise if failure, server message otherwise
        # """
        logger.debug("Trying to authenticate username {}".format(username.encode('utf-8')))
        # try:
        # Create client
        srv = Client(server=self.host, secret=self.secret,
                     dict=Dictionary(DICTIONARY_PATH))
        srv.retries = self.max_retry
        srv.timeout = self.max_timeout
        # create request
        req = srv.CreateAuthPacket(code=pyrad.packet.AccessRequest,
                                   User_Name=username, NAS_Identifier=self.nas_id)
        req["Password"] = req.PwCrypt(password)

        # send request
        reply = srv.SendPacket(req)

        logger.debug("Radius authentication username:{}, return code : {}".format(username, reply.code))

        if reply.code == pyrad.packet.AccessAccept:
            ret = ""
            for key, item in reply.iteritems():
                ret += str(key) + ":" + str(item)
        else:
            logger.error("RADIUS_CLI::authenticate: Authentication failure for user '{}'".format(username))
            raise AuthenticationError("Authentication failure on Radius backend for user '{}'".format(username))

        logger.debug("RADIUS_CLI::authenticate: Authentication reply from server : '{}'".format(ret))
        logger.info("RADIUS_CLI::authenticate: Autentication succeed for user '{}'".format(username))
        # except Timeout:
        #     raise Timeout
        # except Exception, e:
        #     logger.error("Unable to authenticate username {} : exception : {}".format(username, str(e)))

        return {
            'dn': username,
            'user_phone': 'N/A',
            'user_email': 'N/A',
            'password_expired': False,
            'account_locked': False
        }

    def test_user_connection(self, username, password):
        """ Method used to perform test search over RADIUS Repository
        :param username: String with username
        :param password: String with password
        """
        logger.debug("Radius_authentication_test::Trying to authenticate username {}".format(username.encode('utf-8')))
        response = {
            'status': None,
            'reason': None
        }
        try:
            # Create client
            srv = Client(server=self.host, secret=self.secret,
                         dict=Dictionary(DICTIONARY_PATH))
            srv.retries = self.max_retry
            srv.timeout = self.max_timeout

            # create request
            req = srv.CreateAuthPacket(code=pyrad.packet.AccessRequest,
                                       User_Name=username, NAS_Identifier=self.nas_id)
            req["Password"] = req.PwCrypt(password)

            # send request
            reply = srv.SendPacket(req)

            logger.debug("Radius_authentication_test:: Username:{}, return code:{}".format(username, reply.code))

            msg = ""
            if reply.code == pyrad.packet.AccessAccept:
                response['status'] = True
                logger.info("RADIUS::Auth: Authentication succeed for user {}".format(username))
                for key, item in reply.iteritems():
                    msg += str(key) + ":" + str(item)
            else:
                response['status'] = False
                msg = "Authentication failed"
                logger.info("RADIUS::Auth: Authentication failure for user {}".format(username))

            response['reason'] = msg

        except Timeout:
            response['status'] = False
            logger.info("RADIUS::Auth: Authentication failure for user {} : Timeout expired while connecting".format(username))
            response['reason'] = "Timeout expired while connecting"

        except Exception as e:
            response['status'] = False
            logger.error("Radius_authentication_test::Unable to authenticate username:{}, exception:{}".format(username, str(e)))
            response['reason'] = "Exception : " + str(e)

        return response
