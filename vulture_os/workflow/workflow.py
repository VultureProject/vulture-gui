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
__author__ = "Jérémie JOURDIN"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'LogForwarder main models'


from django.utils.translation import ugettext as _
from django.conf import settings
from django.core.exceptions import ObjectDoesNotExist

# Local imports
from system.config.models import write_conf
from system.exceptions import VultureSystemError

import logging
import logging.config

logging.config.dictConfig(settings.LOG_SETTINGS)


class Workflows:

    def __init__(self):
        self.logger = logging.getLogger('gui')

    @property
    def menu(self):
        MENU = {
            'link': 'workflow',
            'icon': 'fab fa-connectdevelop',
            'text': _('Workflow'),
            'url': "/workflow/"
        }

        return MENU

def build_conf(node_logger, workflow_id):
    """ Generate and save conf of workflow on node
    :param node_logger: Logger sent to all API requests
    :param workflow_id: The id of the workflow
    :return:
    """
    result = ""
    reload = False
    """ Firstly, try to retrieve Frontend with given id """
    from workflow.models import Workflow, WORKFLOW_OWNER, WORKFLOW_PERMS  # avoid circular imports

    try:
        workflow = Workflow.objects.get(pk=workflow_id)
        """ Generate and save workflow conf on current node only """
        write_conf(node_logger, [workflow.get_filename(), workflow.generate_conf(),
                                 WORKFLOW_OWNER, WORKFLOW_PERMS])

    except ObjectDoesNotExist:
        raise VultureSystemError("Workflow with id {} not found, failed to generate conf.".format(workflow_id),
                                 "build HAProxy conf", traceback=" ")

    return result
