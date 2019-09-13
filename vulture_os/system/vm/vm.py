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
__doc__ = 'VM (bhyve) service wrapper utils'

# Django system imports
from django.conf import settings

# Django project imports
from system.vm.models import VM
from system.cluster.models import Cluster

from subprocess import Popen, PIPE

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('services')


def delete_vm(logger, object_id):
    """
        Destroy a Virtual Machine, both on system and in MongoDB
    """
    try:
        vm = VM.objects.get(id=object_id)
    except VM.DoesNotExist:
        logger.error("VM::delete_vm: Invalid VM {}".format(object_id))
        return False

    proc = Popen(['/usr/local/bin/sudo', '/usr/local/sbin/vm', 'destroy', vm.name], stdout=PIPE, stderr=PIPE)
    success, error = proc.communicate()
    if not error:
        logger.info ("VM {} destroyed".format(vm.name))
        vm.delete()
        return True
    else:
        logger.error ("VM {} NOT destroyed. Error is: {}".format(vm.name, error))
        return False


def start_vm(logger, object_id):
    """
        Start a Virtual Machine, both on system and in MongoDB
    """
    try:
        vm = VM.objects.get(id=object_id)
    except VM.DoesNotExist:
        logger.error("VM::delete_vm: Invalid VM {}".format(object_id))
        return False

    proc = Popen(['/usr/local/bin/sudo', '/usr/local/sbin/vm', 'start', vm.name], stdout=PIPE, stderr=PIPE)
    success, error = proc.communicate()
    if not error:
        logger.info ("VM {} started".format(vm.name))
        vm.delete()
        return True
    else:
        logger.error ("VM {} NOT started. Error is: {}".format(vm.name, error))
        return False

def stop_vm(logger, object_id):
    """
        Stop a Virtual Machine, both on system and in MongoDB
    """
    try:
        vm = VM.objects.get(id=object_id)
    except VM.DoesNotExist:
        logger.error("VM::delete_vm: Invalid VM {}".format(object_id))
        return False

    proc = Popen(['/usr/local/bin/sudo', '/usr/local/sbin/vm', 'stop', vm.name], stdout=PIPE, stderr=PIPE)
    success, error = proc.communicate()
    if not error:
        logger.info ("VM {} stopped".format(vm.name))
        vm.delete()
        return True
    else:
        logger.error ("VM {} NOT stopped. Error is: {}".format(vm.name, error))
        return False

def vm_update_status():

    proc = Popen(['/usr/local/bin/sudo', '/usr/local/sbin/vm', 'list'], stdout=PIPE, stderr=PIPE)
    success, error = proc.communicate()
    if not error:

        for s in success.decode('utf-8').split('\n'):
            #['Kali', 'default', 'grub', '2', '2G', '-', 'Yes', '[1]', 'Running', '(29774)']
            tmp = " ".join(s.split()).split(" ")
            if tmp[0] == "NAME" or tmp[0] == "":
                continue


            logger.debug("Updating VM {}".format(tmp[0]))
            vm, created = VM.objects.get_or_create(node=Cluster.get_current_node(), name=tmp[0])
            vm.name = tmp[0]
            vm.datastore = tmp[1]
            vm.loader = tmp[2]
            vm.cpu = tmp[3]
            vm.ram = tmp[4]
            vm.vnc = tmp[5]
            vm.autostart = tmp[6]
            if tmp[6] == "No":
                vm.status = tmp[7]
            else:
                vm.status = tmp[8]

            vm.save()

        #Delete VM that no longer exists in system
        for vm in VM.objects.all():
            is_good=False
            for s in success.decode('utf-8').split('\n'):
                tmp = " ".join(s.split()).split(" ")
                if tmp[0] == "NAME":
                    continue

                if vm.name == tmp[0]:
                    is_good=True
                    break

            if not is_good:
                logger.info("VM has disapear: {}".format (vm.name))
                vm.delete()
