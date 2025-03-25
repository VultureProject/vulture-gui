from django.conf import settings
from django.core.management.base import BaseCommand, CommandError
from system.cluster.models import Cluster
from gui.crontab.feed import update_reputation_ctx_now

import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('system')

class Command(BaseCommand):
    help = 'Force the update of the Reputation DBs'

    def handle(self, *args, **options):
        logger.addHandler(logging.StreamHandler(self.stdout))

        if not Cluster.is_node_bootstrapped():
            raise CommandError('Error: Node is not bootstrapped')

        logger.info("Beginning databases update...")
        if update_reputation_ctx_now(logger):
            logger.info(self.style.SUCCESS("Task completed"))
        else:
            raise CommandError('Error while updating databases!')
