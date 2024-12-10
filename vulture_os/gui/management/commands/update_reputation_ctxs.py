from django.core.management.base import BaseCommand, CommandError
from system.cluster.models import Cluster
from gui.crontab.feed import update_reputation_ctx_now


class Command(BaseCommand):
    help = 'Place a node in maintenance state'

    def handle(self, *args, **options):
        if not Cluster.is_node_bootstrapped():
            raise CommandError('Error: Node is not bootstrapped')

        self.stdout.write("Beginning databases update...")
        if update_reputation_ctx_now():
            self.stdout.write(self.style.SUCCESS("Task completed"))
        else:
            raise CommandError('Error while updating databases!')
