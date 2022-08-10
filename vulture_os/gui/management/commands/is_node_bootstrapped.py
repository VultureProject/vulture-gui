from django.core.management.base import BaseCommand, CommandError
from system.cluster.models import Cluster


class Command(BaseCommand):
    help = 'Checks if the node is bootstrapped'

    def add_arguments(self, parser):
        pass

    def handle(self, *args, **options):
        if not Cluster.is_node_bootstrapped():
            raise CommandError('Error: Node is not bootstrapped')