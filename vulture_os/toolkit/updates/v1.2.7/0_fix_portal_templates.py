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
            for template in PortalTemplate.objects.all():
                for attr in ("html_learning", "html_logout", "html_self", "html_password", "html_otp", "html_message",
                             "html_error", "html_registration"):
                    attr_content = getattr(template, attr)
                    if "<style>" not in attr_content:
                        setattr(template, attr, attr_content.replace("{{style}}", "<style>{{style}}</style>"))
                template.html_otp = "<!DOCTYPE html>\n<html>\n <head>\n    <meta charset=\"utf-8\" />\n    <title>Vulture OTP Authentication</title>\n    <link rel=\"stylesheet\" href=\"/templates/static/css/bootstrap.min.css\" integrity=\"sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7\" crossorigin=\"anonymous\">\n    <style>{{style}}</style>\n </head>\n <body> \n    <div class=\"container\">\n        <div class=\"card card-container\" style=\"text-align:center;\">\n            {% if error_message != \"\" %}\n                  <div class=\"alert alert-danger\" role=\"alert\">{{error_message}}</div>\n            {% endif %}\n            <p>OTP Form</p>\n            <form class=\"form-signin\" autocomplete=\"off\" action=\"\" method=\"POST\">\n                {% if onetouch %}\n                  {{otp_onetouch_field}}\n                {% else %}\n                <input type=\"text\" name=\"vltprtlkey\" class=\"form-control\" placeholder=\"Key\" required/>\n                <button class=\"btn btn-lg btn-warning btn-block btn-signin\" type=\"submit\">{{otp_submit_field}}</button>\n                {% endif %}\n            </form>\n            <form class=\"form-signin\" autocomplete=\"off\" action=\"\" method=\"POST\">\n                {% if resend_button %}\n                    <button class=\"btn btn-lg btn-warning btn-block btn-signin\" name=\"{{input_otp_resend}}\" value=\"yes\">{{otp_resend_field}} {{otp_type}}</button>\n                {% endif %}\n                {% if qrcode %}\n                    <p>Register the following QRcode on your phone :\n                    <img src=\"{{qrcode}}\" alt=\"Failed to display QRcode\" height=\"270\" width=\"270\" />\n                    </p>\n                {% endif %}\n            </form>\n        </div>\n    </div>\n </body>\n</html>"
                template.html_password = "<!DOCTYPE html>\n<html>\n <head>\n    <meta charset=\"utf-8\" />\n    <title>Vulture Change Password</title>\n    <link rel=\"stylesheet\" href=\"/templates/static/css/bootstrap.min.css\" integrity=\"sha384-1q8mTJOASx8j1Au+a5WDVnPi2lkFfwwEAa8hDDdjZlpLegxhjVME1fgjWPGmkzs7\" crossorigin=\"anonymous\">\n    <style>{{style}}</style>\n </head>\n <body>\n    <div class=\"container\">\n        <div class=\"card card-container\" style=\"text-align:center;\">\n            <form action='' method='POST' autocomplete='off' class='form-signin'>\n                <img id=\"vulture_img\" src=\"{{image_1}}\"/>\n                {% if error_message %}\n                    <div class=\"alert alert-danger\">{{error_message}}</div>\n                {% endif %}\n                {% if dialog_change %}\n                    <p>Please fill the form to change your current password :</p>\n                    {% if reset_password_key %}\n                    <input type=\"text\" class=\"form-control\" name=\"{{reset_password_name}}\" value=\"{{reset_password_key}}\"/>\n                    {% else %}\n                    <input type=\"password\" class=\"form-control\" placeholder=\"Old password\" name=\"{{input_password_old}}\"/>\n                    {% endif %}\n                    <input type=\"password\" class=\"form-control\" placeholder=\"New password\" name=\"{{input_password_1}}\"/>\n                    <input type=\"password\" class=\"form-control\" placeholder=\"Confirmation\" name=\"{{input_password_2}}\"/>\n                    <button class=\"btn btn-lg btn-warning btn-block btn-signin\" type=\"submit\">Ok</button>\n\n                {% elif dialog_lost %}\n                    <p>Please enter an email address to reset your password:</p>\n                    <input type=\"email\" class=\"form-control\" placeholder=\"Email\" name=\"{{input_email}}\"/>\n                    <button class=\"btn btn-lg btn-warning btn-block btn-signin\" type=\"submit\">Ok</button>\n                    \n                {% endif %}\n            </form>\n        </div>\n    </div>\n </body>\n</html>"
                template.html_error = template.html_error.replace("https://www.vultureproject.org/assets/images/logo_mini.png", "{{image_1}}")
                template.save()
                print("Portal template {} updated".format(template))
        except Exception as e:
            print("Failed to update portal templates: {}".format(e))
            print("Please relaunch this script after solving the issue.")

        print("Done.")
