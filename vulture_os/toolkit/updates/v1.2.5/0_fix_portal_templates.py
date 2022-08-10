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
__author__ = "Kevin Guillemot"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture Project"
__email__ = "contact@vultureproject.org"
__doc__ = "Update portal template(s) content with initial image"

import sys
import os

# Django setup part
sys.path.append('/home/vlt-os/vulture_os')
os.environ.setdefault("DJANGO_SETTINGS_MODULE", 'vulture_os.settings')

import django
from django.conf import settings
django.setup()

from system.cluster.models import Cluster, Node

if not Cluster.is_node_bootstrapped():
    sys.exit(0)
from authentication.portal_template.models import PortalTemplate, TemplateImage

if __name__ == "__main__":

    node = Cluster.get_current_node()
    if not node:
        print("Current node not found. Maybe the cluster has not been initiated yet.")
    else:
        try:
            for template in PortalTemplate.objects.all():
                logout_tpl = template.html_logout
                replace = False
                for line in logout_tpl.split("\n"):
                    if "{{style}}" in line and "<style>" not in line:
                        replace = True
                if replace:
                    template.html_logout = logout_tpl.replace("{{style}}", "<style>{{style}}</style>")
                error_tpl = template.html_error
                if "https://www.vultureproject.org/assets/images/logo_mini.png" in error_tpl:
                    template.html_error = error_tpl.replace("src=\"https://www.vultureproject.org/assets/images/logo_mini.png\"", "src=\"{{image_1}}\"")
                template.save()
                print("Portal template {} updated".format(template))
        except Exception as e:
            print("Failed to update portal templates: {}".format(e))
            print("Please relaunch this script after solving the issue.")

        print("Done.")
