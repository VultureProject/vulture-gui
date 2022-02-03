#!/usr/bin/python
# --*-- coding: utf-8 --*--
"""This file is part of Vulture 3.

Vulture 3 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Vulture 3 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Vulture 3.  If not, see http://www.gnu.org/licenses/.
"""
__author__ = "Kevin Guillemot"
__credits__ = []
__license__ = "GPLv3"
__version__ = "3.0.0"
__maintainer__ =\
    "Vulture Project"
__email__ = "contact@vultureproject.org"
__doc__ = 'Portal utils exceptions'


class TokenNotFoundError(Exception):
    def __init__(self, message):
        super(TokenNotFoundError, self).__init__(message)


class RedirectionNeededError(Exception):
    def __init__(self, message, redirect_url):
        super(RedirectionNeededError, self).__init__(message)
        self.redirect_url = redirect_url


class CredentialsMissingError(Exception):
    def __init__(self, message, fields_missing):
        super(CredentialsMissingError, self).__init__(message)
        self.fields_missing = fields_missing


class CredentialsError(Exception):
    def __init__(self, message):
        super(CredentialsError, self).__init__(message)


class REDISWriteError(Exception):
    def __init__(self, message):
        super(REDISWriteError, self).__init__(message)


class ACLError(Exception):
    def __init__(self, message):
        super(ACLError, self).__init__(message)


class TwoManyOTPAuthFailure(Exception):
    def __init__(self, message):
        super(TwoManyOTPAuthFailure, self).__init__(message)


class PasswordMatchError(Exception):
    def __init__(self, message):
        super(PasswordMatchError, self).__init__(message)


class PasswordEmptyError(Exception):
    def __init__(self, message):
        super(PasswordEmptyError, self).__init__(message)


class UserAlreadyExistsError(Exception):
    def __init__(self, message):
        super(UserAlreadyExistsError, self).__init__(message)
