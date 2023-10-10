from django.core.management.base import BaseCommand, CommandError
from system.cluster.models import Cluster


class Command(BaseCommand):
    help = 'Get cluster api key'

    def add_arguments(self, parser):
        pass

    def handle(self, *args, **options):
        if not Cluster.is_node_bootstrapped():
            raise CommandError('Error: Node is not bootstrapped')

        global_config = Cluster().get_global_config()
        cluster_api_key = global_config.cluster_api_key
        self.stdout.write(self.style.SUCCESS(cluster_api_key))