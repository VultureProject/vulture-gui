from django.core.management.base import BaseCommand, CommandError
from system.cluster.models import Cluster


class Command(BaseCommand):
    help = 'Place a node in maintenance state'

    def add_arguments(self, parser):
        pass

    def handle(self, *args, **options):
        if not Cluster.is_node_bootstrapped():
            raise CommandError('Error: Node is not bootstrapped')

        if node := Cluster.get_current_node():
            try:
                if node.state == "MAINTENANCE":
                    node.set_state("DOWN")
                    self.stdout.write(self.style.SUCCESS(f"The Node has been put out of MAINTENANCE."))
                else:
                    node.set_state("MAINTENANCE")
                    self.stdout.write(self.style.SUCCESS(f"The Node is now in MAINTENANCE."))
            except Exception as e:
                self.stdout.write(self.style.ERROR(f"{e}\n\nPlease relaunch this script after solving the issue."))
        else:
            raise CommandError("Current node not found. Maybe the cluster has not been initialised yet.")