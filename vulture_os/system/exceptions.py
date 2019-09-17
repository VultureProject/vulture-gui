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
__author__ = "Olivier de Régis"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture Project"
__email__ = "contact@vultureproject.org"
__doc__ = 'System exceptions'


from sys import exc_info
from traceback import format_exception


# System class named SystemError already exists
class VultureSystemError(Exception):
    """ Global system exception """

    def __init__(self, message, trying_to, traceback=""):
        super().__init__(message)
        self.trying_to = trying_to
        self.traceback = traceback or str.join('', format_exception(*exc_info()))


class VultureSystemJinjaError(VultureSystemError):
    """ Raised if error while trying to generate config from jinja template"""

    def __init__(self, message, **kwargs):
        super().__init__(message, "generate config", **kwargs)


class VultureSystemConfigError(VultureSystemError):
    """ Raised if error while trying to write config """

    def __init__(self, message, **kwargs):
        super().__init__(message, "write config", **kwargs)


class VultureSystemSaveError(VultureSystemError):
    """ Raised if error while trying to save object """

    def __init__(self, message, **kwargs):
        super().__init__(message, "save object", **kwargs)
