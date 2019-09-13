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
__doc__ = 'Openvpn service wrapper utils'

# Django system imports
from django.conf import settings
from system.zfs.models import ZFS
from system.cluster.models import Cluster
from subprocess import Popen, PIPE
import datetime

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('system')


def delete_snapshot(logger, object_id):
    """
        Destroy the ZFS Snapshot identifier by object_id
    """
    try:
        zfs = ZFS.objects.get(id=object_id)
    except ZFS.DoesNotExist:
        logger.error("ZFS::delete_snapshot: Invalid Snapshot {}".format(object_id))
        return False

    proc = Popen(['/sbin/zfs', 'destroy', zfs.name], stdout=PIPE, stderr=PIPE)
    success, error = proc.communicate()
    if not error:
        logger.info ("ZFS Snapshot {} destroyed".format(zfs.name))
        zfs.delete()
        return True
    else:
        logger.error ("ZFS Snapshot {} NOT destroyed. Error is: {}".format(zfs.name, error))
        return False


def create_snapshot(logger, dataset):
    """
        Destroy the ZFS Snapshot identifier by the given dataset name
    """

    this_node = Cluster.get_current_node()
    now = datetime.datetime.now()
    snapshot = dataset+'@'+this_node.name+'-'+str(now.year)+str(now.month)+str(now.day)+'.'+str(now.hour)+str(now.minute)

    proc = Popen(['/sbin/zfs', 'snapshot', snapshot], stdout=PIPE, stderr=PIPE)
    success, error = proc.communicate()
    if not error:
        logger.info ("ZFS Snapshot {} created".format(snapshot))
        return True
    else:
        logger.error ("ZFS Snapshot {} NOT created. Error is: {}".format(snapshot, error))
        return False

def restore_snapshot(logger, dataset):
    """
        Destroy the ZFS Snapshot identifier by the given dataset name
    """

    proc = Popen(['/sbin/zfs', 'rollback', dataset], stdout=PIPE, stderr=PIPE)
    success, error = proc.communicate()
    if not error:
        logger.info ("ZFS Snapshot {} rollbacked".format(dataset))
        return True
    else:
        logger.error ("ZFS Snapshot {} NOT rollbacked. Error is: {}".format(dataset, error))
        return False


def refresh(self):


    """ Refresh ZFS datasets """
    proc = Popen(['/sbin/zfs', 'list', '-t', 'all'], stdout=PIPE)
    proc2 = Popen(['/usr/bin/grep', '-v', '-e', 'MOUNTPOINT', '-e', 'none'], stdin=proc.stdout, stdout=PIPE, stderr=PIPE)
    proc.stdout.close()
    success, error = proc2.communicate()

    if not error:
        for s in success.decode('utf-8').split('\n'):
            tmp = " ".join(s.split()).split(" ")
            try:
                #This is because the last tmp entry is None
                test=tmp[1]

                zfs_dataset, created = ZFS.objects.get_or_create (node=Cluster.get_current_node(), name=tmp[0])
                zfs_dataset.used = tmp[1]
                zfs_dataset.avail = tmp[2]
                zfs_dataset.refer = tmp[3]
                zfs_dataset.mount = tmp[4]
                zfs_dataset.save()
            except:
                continue
