#!/home/vlt-os/env/bin/python

"""This file is part of Vulture 4.

Vulture 4 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Vulture 4 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Vulture 4.  If not, see http://www.gnu.org/licenses/.
"""
__author__ = "Fabien Amelinck"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture Project"
__email__ = "contact@vultureproject.org"
__doc__ = "Reload Rsyslog configurations for TCP+UDP (LOG) Frontends"

import sys
import os

# Django setup part
sys.path.append('/home/vlt-os/vulture_os')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", 'vulture_os.settings')

import django
django.setup()

from re import compile as re_compile

from system.cluster.models import Cluster
from toolkit.mongodb.postgres_base import PostgresBase

if not Cluster.is_node_bootstrapped():
    sys.exit(0)

if __name__ == "__main__":

    node = Cluster.get_current_node()
    if not node:
        print("Current node not found. Maybe the cluster has not been initialised yet.")
    else:
        try:
            postgres = PostgresBase()
            assert postgres.connect_primary(), "Could not conect to the primary"
            assert postgres.db, "No valid database to work on"
            rctx_coll = postgres.db['vulture']['applications_reputationcontext']
            pattern = re_compile(r"^name(_[0-9]+)?$")
            for index_name, index_options in rctx_coll.index_information().items():
                if pattern.match(index_name) and index_options.get('unique', False):
                    print(f"Dropping index with unicity: '{index_name}'")
                    rctx_coll.drop_index(index_name)
                    print("Creating new index without unicity")
                    rctx_coll.create_index("name")

        except Exception as e:
            print(f"Failed to update index for ReputationContext collection: {e}")
            print("Please relaunch this script after solving the issue.")

        print("Done.")
