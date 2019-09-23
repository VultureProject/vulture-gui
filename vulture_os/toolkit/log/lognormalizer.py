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
__doc__ = 'Toolkit for lognormalizer (liblognorm)'

# Django system imports
from django.conf import settings

# Django project imports

# Required exceptions imports
from services.exceptions import ServiceTestConfigError
from subprocess import CalledProcessError

# Extern modules imports
import io
from json import loads as json_loads
from subprocess import check_output, PIPE

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api')


TEST_CONF_PATH = "/tmp"


def test_lognormalizer(filename, rulebase_content, to_parse):
    """ Launch lognormalizer with rulebase to test
    :return String result of check_call command or raise 
    """
    """ First open the file and write the rulebase """
    test_filename = "{}/{}".format(TEST_CONF_PATH, filename)

    try:
        with io.open(test_filename, mode='w', encoding='utf-8') as fd:
            fd.write(str(rulebase_content).replace("\r\n", "\n"))
    except FileNotFoundError as e:
        raise ServiceTestConfigError("Directory '{}' does not seem to exist, "
                                     "cannot write file {}".format(TEST_CONF_PATH, test_filename), "liblognorm")
    except PermissionError as e:
        raise ServiceTestConfigError("Incorrect permissions on '{}' directory, "
                                     "cannot write file {}".format(test_filename, TEST_CONF_PATH), "liblognorm")
    except Exception as e:
        raise ServiceTestConfigError("Unknown error writing file {} : {}".format(test_filename, str(e)), "liblognorm")

    """ Then test the conf with lognormalizer command """
    try:
        # check_call raise CallProcessError if return code is not 0
        raw = check_output(["/usr/local/bin/lognormalizer", "-r", test_filename, "-e", "json"],
                           input=(to_parse+"\n").encode('utf8')
                           ).decode('utf8', 'ignore')

        parsed = "[{}]".format(raw.replace("}\n{", "},\n{"))

        logger.debug("Parsed output: {}".format(str(parsed.encode('utf8'))))

        # And try to decode as JSON
        return json_loads(parsed)

    except CalledProcessError as e:
        stdout = e.stdout.decode('utf8')
        stderr = e.stderr.decode('utf8')
        logger.error(stderr)
        logger.exception("The lognormalizer command failed with the following results: {}".format(stderr or stdout))
        if "/usr/local/bin/lognormalizer: not found" in stderr:
            raise ServiceTestConfigError("Liblognorm is not installed.", "liblognorm", traceback=(stderr or stdout))
        raise ServiceTestConfigError("Invalid configuration.", "liblognorm", traceback=(stderr or stdout))
