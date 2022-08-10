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
__doc__ = "Fix portal template(s) content"

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
                template.html_learning = "<!DOCTYPE html>\n<html>\n <head>\n    <meta charset=\"utf-8\" />\n    <title>Vulture Learning</title>\n    <link rel=\"stylesheet\" href=\"/templates/static/html/bootstrap.min.css\" integrity=\"sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7\" crossorigin=\"anonymous\">\n    <style>{{style}}</style>\n </head>\n <body>\n    <div class=\"container\">\n        <div class=\"card card-container\" style=\"text-align:center;\">\n            <p>Learning form</p>\n            <form action='' method='POST' autocomplete='off' class='form-signin'>\n                {% for field_name, field_type in fields_to_prompt.items %}\n                <input type=\"{{field_type}}\" name=\"{{field_name}}\" class=\"form-control\" placeholder=\"{{field_name}}\" required/>\n                {% endfor %}\n                <button class=\"btn btn-lg btn-warning btn-block btn-signin\" type=\"submit\">Submit</button>\n            </form>\n        </div>\n    </div>\n </body>\n</html>"
                template.html_password = template.html_password.replace('<input type="text" class="form-control" name="{{reset_password_name}}" value="{{reset_password_key}}"/>', '<input type="hidden" class="form-control" name="{{reset_password_name}}" value="{{reset_password_key}}"/>')
                template.save()
                print("Portal template {} updated".format(template))
        except Exception as e:
            print("Failed to update portal templates: {}".format(e))
            print("Please relaunch this script after solving the issue.")

        print("Done.")
