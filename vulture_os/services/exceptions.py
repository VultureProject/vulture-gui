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
__version__ = "4.0.0"
__maintainer__ = "Vulture Project"
__email__ = "contact@vultureproject.org"
__doc__ = 'Services exceptions'

from sys import exc_info
from traceback import format_exception


class ServiceExit(Exception):
    """
    Custom exception which is used to trigger the clean exit
    of all running threads and the main program.
    """
    pass


class ServiceError(Exception):
    """ Global services exception """

    def __init__(self, message, service_name, trying_to, traceback=""):
        super().__init__(message)
        self.service_name = service_name
        self.trying_to = trying_to
        self.traceback = traceback or str.join('', format_exception(*exc_info()))

    def __str__(self):
        return "Failed to {} {} : {}".format(self.trying_to, self.service_name, super().__str__())


class ServiceConfigError(ServiceError):
    """ Error while trying to check service conf """

    def __init__(self, message, service_name, **kwargs):
        super().__init__(message, service_name, "write conf", **kwargs)


class ServiceTestConfigError(ServiceError):
    """ Error while trying to test conf (of a frontend for example) """

    def __init__(self, message, service_name, **kwargs):
        super().__init__(message, service_name, "test conf", **kwargs)


class ServiceNoConfigError(ServiceError):
    """ Raised if no such file while trying to get conf """

    def __init__(self, message, service_name, **kwargs):
        super().__init__(message, service_name, "get conf", **kwargs)


class ServiceStartError(ServiceError):
    """ Raised if error while trying to start service """

    def __init__(self, message, service_name, **kwargs):
        super().__init__(message, service_name, "start", **kwargs)


class ServiceStopError(ServiceError):
    """ Raised if error while trying to stop service """

    def __init__(self, message, service_name, **kwargs):
        super().__init__(message, service_name, "stop", **kwargs)


class ServiceJinjaError(ServiceError):
    """ Raised if error while trying to generate conf """

    def __init__(self, message, service_name, **kwargs):
        super().__init__(message, service_name, "generate conf", **kwargs)


class ServiceStatusError(ServiceError):
    """ Raised if error while trying to get status of service """

    def __init__(self, message, service_name, **kwargs):
        super().__init__(message, service_name, "get status", **kwargs)


class ServiceReloadError(ServiceError):
    """ Raised if error while trying to reload (or graceful) service """

    def __init__(self, message, service_name, **kwargs):
        super().__init__(message, service_name, "reload", **kwargs)


class ServiceRestartError(ServiceError):
    """ Raised if error while trying to restart service """

    def __init__(self, message, service_name, **kwargs):
        super().__init__(message, service_name, "restart", **kwargs)
