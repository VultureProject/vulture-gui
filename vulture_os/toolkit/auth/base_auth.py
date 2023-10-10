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
__author__ = "Florian Hagniel"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Base authentication, mother of authentication wrappers'

# Django system imports
from django.contrib.auth.hashers import make_password
from django.utils.crypto import constant_time_compare, pbkdf2, get_random_string

# Django project imports

# Extern modules imports
import base64
import hashlib

# Required exceptions imports

# Logger configuration imports
import logging
logger = logging.getLogger('authentication')


class BaseAuth(object):

    def __init__(self, **kwargs):
        """ Abstract class, we can't instantiate it

        """
        raise NotImplementedError()

    def _get_password_hash(self, password, fixed_salt=None):
        """ Return password after hash operation

        :param password: String with plain text password
        :param fixed_salt: If Set, use the given fixed_salt in pbkdf2 operation instead of computing a new one
        This is used to compare existing password
        :return: String with hashed password
        """
        if self.password_salt is not None:
            salt = self.password_salt
            if self.password_salt_position == 'begin':
                password = "{}{}".format(salt, password)
            elif self.password_salt_position == 'end':
                password = "{}{}".format(password, salt)

        hash_algo = self.password_hash_algo
        if hash_algo == 'plain':
            return password
        elif hash_algo == 'md5':
            return hashlib.md5(password).hexdigest()
        elif hash_algo == 'sha1':
            return hashlib.sha1(password).hexdigest()
        elif hash_algo == 'sha256':
            return hashlib.sha256(password).hexdigest()
        elif hash_algo == 'sha384':
            return hashlib.sha384(password).hexdigest()
        elif hash_algo == 'sha512':
            return hashlib.sha512(password).hexdigest()
        elif hash_algo == 'make_password':
            return make_password(password)
        elif hash_algo.startswith('pbkdf2'):
            args=hash_algo.split('-')
            hash=args[1]
            iter=args[2]

            for alg in hashlib.algorithms:
                if str(hash) in alg:
                    algo=getattr(hashlib, 'sha'+str(hash))
                    if not fixed_salt:
                        rdm_str=get_random_string(length=12)
                    else:
                        rdm_str=fixed_salt
                    pwd=base64.b64encode (pbkdf2(password, rdm_str, int(iter), digest=algo))
                    return "pbkdf2_sha"+str(hash)+'$'+str(iter)+'$'+rdm_str+'$'+pwd

        else:
            raise NotImplemented("Password hash algorithm not implemented, "
                                 "algo: {}".format(hash_algo))

    def _check_password(self, plain_password, hashed_password):
        """Verify that password provided by user match password hash stored in
        database

        :param plain_password: Plain text password (provided by user)
        :param hashed_password: Hashed version of password (from Database result)
        :return: True if password correspond, False otherwise
        """

        """ Get the SALT used in stored password """
        fixed_salt=None
        if self.password_hash_algo.startswith('pbkdf2'):
            tmp=hashed_password.split('$')
            fixed_salt=tmp[2]

        password = self._get_password_hash(plain_password, fixed_salt)

        return constant_time_compare(password, hashed_password)

    def _is_password_expired(self, user_info):
        """ Check if user password is expired

        :param user_info: object with user information
        :return: True if password is expired, False otherwise
        """
        if self.change_pass_column is not None \
                and self.change_pass_value is not None:
            change_pass_value = user_info[self.change_pass_column]
            change_pass_value = str(change_pass_value)
            self.change_pass_value = str(self.change_pass_value)
            return constant_time_compare(change_pass_value, self.change_pass_value)
        else:
            return False

    def _is_user_account_locked(self, user_info):
        """ Check if user account is locked

        :param user_info: object with user information
        :return: True if account is locked, False otherwise
        """
        if self.locked_column is not None \
                and self.locked_value is not None:
            locked_value = user_info[self.locked_column]
            locked_value = str(locked_value)
            self.locked_value = str(self.locked_value)
            return constant_time_compare(locked_value, self.locked_value)
        else:
            return False
