from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from system.cluster.models import Cluster
from gui.crontab.generate_tzdbs import generate_timezone_dbs

import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('system')


class Command(BaseCommand):
    help = 'Force re-generation of TZDB lookup files for Rsyslog'

    def handle(self, *args, **options):
        logger.addHandler(logging.StreamHandler(self.stdout))

        if not Cluster.is_node_bootstrapped():
            raise CommandError('Error: Node is not bootstrapped')

        logger.info("Beginning tzdbs update...")
        generate_timezone_dbs(logger)
        logger.info(self.style.SUCCESS("Task completed"))
