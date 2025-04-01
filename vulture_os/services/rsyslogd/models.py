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
__doc__ = 'Rsyslog settings model'

# Django system imports
from typing import Any
from django.conf import settings
from djongo import models
from django.core.validators import MinValueValidator, MaxValueValidator
from django.db.models import Q
from django.utils.translation import gettext_lazy as _

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('services')


class RsyslogSettings(models.Model):
    """ Model used to manage global configuration fields of Rsyslogd """

    def to_template(self):
        """ Dictionary used to create configuration file

        :return     Dictionnary of configuration parameters
        """
        """ Variables used by template rendering """
        from applications.logfwd.models import LogOM
        from applications.reputation_ctx.models import DATABASES_PATH
        from services.frontend.models import Frontend, Listener
        from system.cluster.models import Cluster
        from system.config.models import Config
        current_node = Cluster.get_current_node()
        frontends = set(listener.frontend for listener in Listener.objects.filter(network_address__nic__node=current_node).distinct())
        frontends.update(Frontend.objects.filter(
            Q(mode="log", listening_mode__in=['redis', 'kafka', 'file'], node=current_node) |
            Q(mode="log", listening_mode__in=['redis', 'kafka', 'file'], node=None) |
            Q(mode="filebeat", filebeat_listening_mode__in=["file", "api"], node=current_node) |
            Q(mode="log", listening_mode="api")).distinct())
        return {
            'frontends': frontends,
            'node': current_node,
            'max_tcp_listeners': Listener.objects.filter(frontend__listening_mode__icontains="tcp",frontend__enabled=True).count() + Frontend.objects.filter(enabled=True, listening_mode="api").count() + 1,
            'log_forwarders': LogOM.objects.all(),
            'DATABASES_PATH': DATABASES_PATH,
            'tenants_name': Config.objects.get().internal_tenants.name
        }

    def __str__(self):
        return "Rsyslogd settings"

class RsyslogQueue(models.Model):
    """ Parameters used for Rsyslog actions and queues
    """

    #This class is not in DB, only used to define common fields in different models
    class Meta:
        abstract = True

    class QueueTypes(models.TextChoices):
        DIRECT = "direct", _("Direct (no queuing)")
        LINKEDLIST = "linkedlist", _("LinkedList (queue with fixed size but dynamic allocation)")
        FIXEDARRAY = 'fixedarray', "FixedArray (queue with fixed and preallocated size)"

    queue_type = models.TextField(
        default=QueueTypes.LINKEDLIST,
        choices=QueueTypes.choices,
        help_text=_("Set a queue type for the rsyslog's Frontend/LogForwarder configuration"),
        verbose_name=_("Rsyslog queue type")
    )
    queue_size = models.PositiveIntegerField(
        blank=True,
        null=True,
        help_text=_("Size of the queue in nb of message"
                    " (default to 1000 for LogForwarders, 50000 for Frontends)"),
        verbose_name=_("Size of the queue in nb of message"),
        validators=[MinValueValidator(100)]
    )
    dequeue_batch_size = models.PositiveIntegerField(
        blank=True,
        null=True,
        help_text=_("Maximum number of messages to use in a dequeuing batch"
                    " (default to 128 for LogForwarders, 1024 for Frontends)"),
        verbose_name=_("Size of the batch to dequeue"),
        validators=[MinValueValidator(1)]
    )
    nb_workers = models.PositiveIntegerField(
        default=8,
        help_text=_("Maximum number of workers for the rsyslog's LogForwarder/Frontend configuration"),
        verbose_name=_("Maximum parser workers"),
        validators=[MinValueValidator(1)]
    )
    new_worker_minimum_messages = models.PositiveIntegerField(
        blank=True,
        null=True,
        help_text=_("Number of messages still in queue to start a new worker thread"),
        verbose_name=_("Minimum messages to start a new worker"),
        validators=[MinValueValidator(1)]
    )
    shutdown_timeout = models.PositiveIntegerField(
        default=5000,
        blank=True,
        help_text=_("Time to wait for the queue to finish processing entries (in ms) before shutting down"),
        verbose_name=_("Queue timeout shutdown (ms)"),
        validators=[MinValueValidator(1)]
    )
    save_on_shutdown = models.BooleanField(
        default=True,
        help_text=_("Prevent message loss by writing on disk during a shutdown"),
        verbose_name=_("Save remaining queue logs on shutdown")
    )
    enable_disk_assist = models.BooleanField(
        default=False,
        help_text=_("Save logs on disk if queue reaches high usage"),
        verbose_name=_("Enable disk queue on high queue usage")
    )
    high_watermark = models.PositiveIntegerField(
        blank=True,
        default=90,
        help_text=_("Write logs on disk if size of queue reaches this threshold"),
        verbose_name=_("High watermark for disk queuing (between 1 and 99%)"),
        validators=[MinValueValidator(1), MaxValueValidator(99)]
    )
    low_watermark = models.PositiveIntegerField(
        blank=True,
        default=70,
        help_text=_("Stop using disk when queue size falls below this threshold"),
        verbose_name=_("Low watermark for disk queuing (between 1 and 99%)"),
        validators=[MinValueValidator(1), MaxValueValidator(99)]
    )
    max_file_size = models.PositiveIntegerField(
        blank=True,
        null=True,
        help_text=_("Set the max value of a queue file in MB"
                    " (default to 1MB for actions and 16MB for rulesets)"),
        verbose_name=_("Max size of a queue file (in MB)"),
        validators=[MinValueValidator(1)]
    )
    max_disk_space = models.PositiveIntegerField(
        blank=True,
        null=True,
        help_text=_("Limit the maximum disk space used by the queue in MB"),
        verbose_name=_("Max total disk space used by the queue (in MB)"),
        validators=[MinValueValidator(1)]
    )
    checkpoint_interval = models.PositiveIntegerField(
        blank=True,
        null=True,
        help_text=_("To improve reliability, write/update bookkeeping information every Nth record handled"),
        verbose_name=_("Update bookkeeping information every Nth entry"),
    )
    spool_directory = models.TextField(
        default="/var/tmp",
        help_text=_("Set a writable folder to store DA queue"),
        verbose_name=_("Disk-Assisted queue folder")
    )

    def get_rsyslog_queue_parameters(self) -> dict[str, Any]:
        """ get ruleset/action's explicitely defined options
        :return  Dict containing the fields set
        """
        options_dict = {
            "type": self.queue_type,
        }
        if self.queue_type != RsyslogQueue.QueueTypes.DIRECT:
            options_dict |= {
                "size": self.queue_size,
                "dequeueBatchSize": self.dequeue_batch_size,
                "workerThreads": self.nb_workers,
                "workerThreadMinimumMessages": self.new_worker_minimum_messages,
                "timeoutshutdown": self.shutdown_timeout,
                "saveOnShutdown": "on" if self.save_on_shutdown else None,
            }
        if self.enable_disk_assist:
            high_watermark = int(self.queue_size * self.high_watermark / 100) if self.queue_size else None
            low_watermark = int(self.queue_size * self.low_watermark / 100) if self.queue_size else None
            options_dict |= {
                "highWatermark": high_watermark,
                "lowWatermark": low_watermark,
                "spoolDirectory": self.spool_directory,
                "maxFileSize": f"{self.max_file_size}m" if self.max_file_size else None,
                "maxDiskSpace": f"{self.max_disk_space}m" if self.max_disk_space else None,
                "checkpointInterval": self.checkpoint_interval or None,
            }

        #Filter out None values and format them all as string
        options_dict = dict(filter(lambda x: x[1] is not None, options_dict.items()))

        return options_dict
