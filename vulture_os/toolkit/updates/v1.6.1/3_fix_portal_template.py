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
__author__ = "Theo Bertin"
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
django.setup()

from system.cluster.models import Cluster

if not Cluster.is_node_bootstrapped():
    sys.exit(0)
from authentication.portal_template.models import PortalTemplate

if __name__ == "__main__":

    node = Cluster.get_current_node()
    if not node:
        print("Current node not found. Maybe the cluster has not been initiated yet.")
    else:
        try:
            # Only update default template
            template = PortalTemplate.objects.get(pk=1)
            # Repair captcha input
            template.html_login = "<!DOCTYPE html>\n<html>\n<head>\n    <meta charset=\"utf-8\"/>\n    <title>Vulture Login</title>\n    <link rel=\"stylesheet\" href=\"/templates/static/css/bootstrap.min.css\" integrity=\"sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7\" crossorigin=\"anonymous\">\n    <style>{{style}}</style>\n </head>\n <body>\n    <div class=\"container\">\n        <div class=\"card card-container\">\n            <form action='' method='POST' autocomplete='off' class='form-signin'>\n                <img id=\"vulture_img\" src=\"{{image_1}}\"/>\n                {% if error_message != \"\" %}\n                  <div class=\"alert alert-danger\" role=\"alert\">{{error_message}}</div>\n                {% endif %}\n                <span id=\"reauth-email\" class=\"reauth-email\"></span>\n                <input type=\"text\" name=\"{{input_login}}\" class=\"form-control\" placeholder=\"Login\" required/>\n                <input type=\"password\" name=\"{{input_password}}\" class=\"form-control\" placeholder=\"Password\" required/>\n                {% if captcha %}\n                    <img id=\"captcha\" src=\"{{captcha}}\"/>\n                    <input type=\"text\" name=\"{{input_captcha}}\" class=\"form-control\" placeholder=\"Captcha\" required/>\n\n                {% endif %}\n                <button class=\"btn btn-lg btn-warning btn-block btn-signin\" type=\"submit\">{{login_submit_field}}</button>\n                {% for repo in openid_repos %}\n                <a href=\"{{repo.start_url}}\">Login with {{repo.name}} ({{repo.provider}})</a><br>\n                {% endfor %}\n                <a href=\"{{lostPassword}}\">Forgotten password ?</a>\n            </form>\n        </div>\n    </div>\n </body>\n</html>"
            # put reset_password_key as hidden input
            template.html_password = "<!DOCTYPE html>\n<html>\n <head>\n    <meta charset=\"utf-8\" />\n    <title>Vulture Change Password</title>\n    <link rel=\"stylesheet\" href=\"/templates/static/css/bootstrap.min.css\" integrity=\"sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7\" crossorigin=\"anonymous\">\n    <style>{{style}}</style>\n </head>\n <body>\n    <div class=\"container\">\n        <div class=\"card card-container\" style=\"text-align:center;\">\n            <form action='' method='POST' autocomplete='off' class='form-signin'>\n                <img id=\"vulture_img\" src=\"{{image_1}}\"/>\n                {% if error_message %}\n                    <div class=\"alert alert-danger\">{{error_message}}</div>\n                {% endif %}\n                {% if dialog_change %}\n                    <p>Hello <b>{{username}}</b></p>\n                    <p>Please fill the form to change your current password :</p>\n                    {% if reset_password_key %}\n                    <input type=\"hidden\" class=\"form-control\" name=\"{{reset_password_name}}\" value=\"{{reset_password_key}}\"/>\n                    {% else %}\n                    <input type=\"password\" class=\"form-control\" placeholder=\"Old password\" name=\"{{input_password_old}}\"/>\n                    {% endif %}\n                    <input type=\"password\" class=\"form-control\" placeholder=\"New password\" name=\"{{input_password_1}}\"/>\n                    <input type=\"password\" class=\"form-control\" placeholder=\"Confirmation\" name=\"{{input_password_2}}\"/>\n                    <button class=\"btn btn-lg btn-warning btn-block btn-signin\" type=\"submit\">Ok</button>\n\n                {% elif dialog_lost %}\n                    <p>Please enter an email address to reset your password:</p>\n                    <input type=\"email\" class=\"form-control\" placeholder=\"Email\" name=\"{{input_email}}\"/>\n                    <button class=\"btn btn-lg btn-warning btn-block btn-signin\" type=\"submit\">Ok</button>\n                    \n                {% endif %}\n            </form>\n        </div>\n    </div>\n </body>\n</html>"

            template.save()
            print("Default Portal template {} updated".format(template))

            # Reload template for all portals that uses this template
            print("Reloading templates for portals using it")
            for portal in template.userauthentication_set.all().only('pk'):
                node.api_request("authentication.user_portal.api.write_templates", portal.id)
        except Exception as e:
            print("Failed to update portal templates: {}".format(e))
            print("Please relaunch this script after solving the issue.")

        print("Done.")
