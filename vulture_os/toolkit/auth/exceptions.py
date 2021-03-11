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
__doc__ = 'Authentication utils exceptions'


class AuthenticationError(Exception):
    """Base Authentication Exception
    """
    def __init__(self, message):
        super(Exception, self).__init__(message)


class UserNotFound(AuthenticationError):
    """ Exception raised when user is not found inside repository

    """
    pass


class AuthenticationFailed(AuthenticationError):
    """ Exception raised when user / password is invalid

    """
    pass


class PasswordExpired(AuthenticationError):
    """ Exception raised when password is expired

    """
    pass


class RegisterAuthenticationError(Exception):
    def __init__(self, message):
        super(Exception, self).__init__(message)


class OTPError(Exception):
    def __init__(self, message):
        super(OTPError, self).__init__(message)


class ChangePasswordError(Exception):
    def __init__(self, message):
        super(ChangePasswordError, self).__init__(message)


class LDAPSizeLimitExceeded(Exception):
    def __init__(self, max_size, partial_results):
        super(Exception, self).__init__("Size limit exceeded")
        self.max_size = max_size
        self.partial_results = partial_results
