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
__author__ = "Jérémie JOURDIN"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture Project"
__email__ = "contact@vultureproject.org"
__doc__ = 'Applications exceptions'


# Do not instantiate directly, create a subclass if needed !
class AppsException(Exception):
    """ Global system exception - Abstract class """

    def __init__(self, message, trying_to):
        super().__init__(message)
        self.trying_to = trying_to
        self.message = message

    def __str__(self):
        return "Error while trying to {}: '{}'".format(self.trying_to, self.message)
