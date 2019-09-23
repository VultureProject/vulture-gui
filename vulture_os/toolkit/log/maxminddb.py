#!/usr/bin/python
# -*- coding: utf-8 -*-
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
__doc__ = 'Toolkit for MaxMindDB databases management'

# Django system imports

# Django project imports

# Required exceptions imports

# Extern modules imports
from io import BytesIO
from maxminddb import open_database as open_mmdb_database, MODE_FD


def test_mmdb_database(mmdb_content):
    """ Test MaxMindDB database format with only its content as binary
    :return True if the database is correct, False otherwise
    """
    # Check if the response content is MMDB database
    tmpfile = BytesIO()
    tmpfile.write(mmdb_content)
    tmpfile.seek(0)
    setattr(tmpfile, "name", "test")
    try:
        open_mmdb_database(tmpfile, mode=MODE_FD)
        return True
    except Exception:
        return False
