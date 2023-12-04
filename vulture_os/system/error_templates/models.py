#!/home/vlt-os/env/bin/python
"""This file is part of Vulture OS.

Vulture OS is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Vulture OS is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Vulture OS.  If not, see http://www.gnu.org/licenses/.
"""
__author__ = "Kevin GUILLEMOT"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'ErrorTemplate model classes'

# Django system imports
from django.conf import settings
from django.utils.translation import gettext_lazy as _
from django.forms.models import model_to_dict
from djongo import models

# Django project imports
from system.cluster.models import Cluster
from services.haproxy.haproxy import HAPROXY_OWNER, HAPROXY_PATH, HAPROXY_PERMS

# Extern modules imports

# Required exceptions imports

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


ERROR_MODE_CHOICES = (
    ('display', "Render HTML"),
    ('302', "Redirect with 302"),
    ('303', "Redirect with 303"),
)

# FIXME : See w/ JJO
CONF_PATH = HAPROXY_PATH + "/templates"
TEMPLATE_OWNER = HAPROXY_OWNER
TEMPLATE_PERMS = HAPROXY_PERMS


class ErrorTemplate(models.Model):
    """ """
    name = models.TextField(
        unique=True,
        default="Default template",
        help_text=_("Name of the ErrorTemplate to use in Listener/Application")
    )
    """ *** ERROR TEMPLATES *** """
    """ HAProxy template used to render 400 error code """
    error_400_mode = models.TextField(
        default="display",
        choices=ERROR_MODE_CHOICES,
        help_text=_("Display the error or redirect with 302/303 code.")
    )
    error_400_url = models.TextField(
        default="http://www.example.com/test/ or /test/",
        help_text=_("Absolute or relative url to redirect to when the error code is encountered.")
    )
    error_400_html = models.TextField(
        default="""HTTP/1.1 400 Bad Request\r\nContent-type: text/html\r\nConnection: close\r\n\r\n
<html><body><h1>400 Bad request</h1>
<p>Your browser sent an invalid request.</p>
</body></html>""",
        help_text=_("HTML code to render if 400 (Bad Request) code is returned.")
    )
    """ HAProxy template used to render 403 error code """
    error_403_mode = models.TextField(
        default="display",
        choices=ERROR_MODE_CHOICES,
        help_text=_("Display the error or redirect with 302/303 code.")
    )
    error_403_url = models.TextField(
        default="http://www.example.com/test/ or /test/",
        help_text=_("Absolute or relative url to redirect to when the error code is encountered.")
    )
    error_403_html = models.TextField(
        default="""HTTP/1.1 403 Forbidden\r\nContent-type: text/html\r\nConnection: close\r\n\r\n
<html><body><h1>403 Forbidden</h1>
<p>You don't have permission to access this url on this server.<br/></p>
</body></html>""",
        help_text=_("HTML code to render if 403 (Forbidden) code is returned.")
    )
    """ HAProxy template used to render 405 error code """
    error_405_mode = models.TextField(
        default="display",
        choices=ERROR_MODE_CHOICES,
        help_text=_("Display the error or redirect with 302/303 code.")
    )
    error_405_url = models.TextField(
        default="http://www.example.com/test/ or /test/",
        help_text=_("Absolute or relative url to redirect to when the error code is encountered.")
    )
    error_405_html = models.TextField(
        default="""HTTP/1.1 405 Method Not Allowed\r\nContent-type: text/html\r\nConnection: close\r\n\r\n
<html><body><h1>405 Method Not Allowed</h1>
<p>The requested method is not allowed for that URL.</p>
</body></html>""",
        help_text=_("HTML code to render if 405 (Method Not Allowed) code is returned.")
    )
    """ HAProxy template used to render 408 error code """
    error_408_mode = models.TextField(
        default="display",
        choices=ERROR_MODE_CHOICES,
        help_text=_("Display the error or redirect with 302/303 code.")
    )
    error_408_url = models.TextField(
        default="http://www.example.com/test/ or /test/",
        help_text=_("Absolute or relative url to redirect to when the error code is encountered.")
    )
    error_408_html = models.TextField(
        default="""HTTP/1.1 408 Request Timeout\r\nContent-type: text/html\r\nConnection: close\r\n\r\n
<html><body><h1>408 Request Timeout</h1>
<p>Server timeout waiting for the HTTP request from the client.</p>
</body></html>""",
        help_text=_("HTML code to render if 408 (Request Timeout) code is returned.")
    )
    """ HAProxy template used to render 425 error code """
    error_425_mode = models.TextField(
        default="display",
        choices=ERROR_MODE_CHOICES,
        help_text=_("Display the error or redirect with 302/303 code.")
    )
    error_425_url = models.TextField(
        default="http://www.example.com/test/ or /test/",
        help_text=_("Absolute or relative url to redirect to when the error code is encountered.")
    )
    error_425_html = models.TextField(
        default="""HTTP/1.1 425 Too Early\r\nContent-type: text/html\r\nConnection: close\r\n\r\n
<html><body><h1>425 Too Early</h1>
<p>.</p>
</body></html>""",
        help_text=_("HTML code to render if 425 (Too Early) code is returned.")
    )
    """ HAProxy template used to render 429 error code """
    error_429_mode = models.TextField(
        default="display",
        choices=ERROR_MODE_CHOICES,
        help_text=_("Display the error or redirect with 302/303 code.")
    )
    error_429_url = models.TextField(
        default="http://www.example.com/test/ or /test/",
        help_text=_("Absolute or relative url to redirect to when the error code is encountered.")
    )
    error_429_html = models.TextField(
        default="""HTTP/1.1 429 Too Many Requests\r\nContent-type: text/html\r\nConnection: close\r\n\r\n
<html><body><h1>429 Too Many Requests</h1>
<p>The user has sent too many requests in a given amount of time.</p>
</body></html>""",
        help_text=_("HTML code to render if 429 (Too Many Requests) code is returned.")
    )
    """ HAProxy template used to render 500 error code """
    error_500_mode = models.TextField(
        default="display",
        choices=ERROR_MODE_CHOICES,
        help_text=_("Display the error or redirect with 302/303 code.")
    )
    error_500_url = models.TextField(
        default="http://www.example.com/test/ or /test/",
        help_text=_("Absolute or relative url to redirect to when the error code is encountered.")
    )
    error_500_html = models.TextField(
        default="""HTTP/1.1 500 Internal Server Error\r\nContent-type: text/html\r\nConnection: close\r\n\r\n
<html><body><h1>500 Internal Server Error</h1>
<p>The server encountered an internal error or
misconfiguration and was unable to complete
your request.</p>
<p>Please contact the server administrator
to inform them of the time this error occurred,
and the actions you performed just before this error.</p>
<p>More information about this error may be available
in the server error log.</p>
</body></html>""",
        help_text=_("HTML code to render if 500 (Internal Server Error) code is returned.")
    )
    """ HAProxy template used to render 502 error code """
    error_502_mode = models.TextField(
        default="display",
        choices=ERROR_MODE_CHOICES,
        help_text=_("Display the error or redirect with 302/303 code.")
    )
    error_502_url = models.TextField(
        default="http://www.example.com/test/ or /test/",
        help_text=_("Absolute or relative url to redirect to when the error code is encountered.")
    )
    error_502_html = models.TextField(
        default="""HTTP/1.1 502 Bad Gateway\r\nContent-type: text/html\r\nConnection: close\r\n\r\n
<html><body><h1>502 Bad Gateway</h1>
<p>The proxy server received an invalid response from an upstream server.<br/></p>
</body></html>""",
        help_text=_("HTML code to render if 502 (Bad Gateway) code is returned.")
    )
    """ HAProxy template used to render 503 error code """
    error_503_mode = models.TextField(
        default="display",
        choices=ERROR_MODE_CHOICES,
        help_text=_("Display the error or redirect with 302/303 code.")
    )
    error_503_url = models.TextField(
        default="http://www.example.com/test/ or /test/",
        help_text=_("Absolute or relative url to redirect to when the error code is encountered.")
    )
    error_503_html = models.TextField(
        default="""HTTP/1.1 503 Service Unavailable\r\nContent-type: text/html\r\nConnection: close\r\n\r\n
<html><body><h1>503 Service Unavailable</h1>
<p>The server is temporarily unable to service your
request due to maintenance downtime or capacity
problems. Please try again later.</p>
</body></html>""",
        help_text=_("HTML code to render if 503 (Service Unavailable) code is returned.")
    )
    """ HAProxy template used to render 504 error code """
    error_504_mode = models.TextField(
        default="display",
        choices=ERROR_MODE_CHOICES,
        help_text=_("Display the error or redirect with 302/303 code.")
    )
    error_504_url = models.TextField(
        default="http://www.example.com/test/ or /test/",
        help_text=_("Absolute or relative url to redirect to when the error code is encountered.")
    )
    error_504_html = models.TextField(
        default="""HTTP/1.1 504 Gateway Timeout\r\nContent-type: text/html\r\nConnection: close\r\n\r\n
<html><body><h1>504 Gateway Timeout</h1>
<p>The gateway did not receive a timely response
from the upstream server or application.</p>
</body></html>""",
        help_text=_("HTML code to render if 504 (Gateway Timeout) code is returned.")
    )

    def __str__(self):
        return "{}".format(self.name)

    @staticmethod
    def str_attrs():
        """ List of attributes required by __str__ method """
        return ['name']

    def to_template(self):
        """  returns the attributes of the class """
        return {
            'id': str(self.id),
            'name': self.name,
            # Test self.pk to prevent M2M errors when object isn't saved in DB
            'frontends': [str(frontend) for frontend in self.frontend_set.all()] if self.pk else []
        }

    def to_dict(self, fields=None):
        result = model_to_dict(self, fields=fields)
        if not fields or "id" in fields:
            result['id'] = str(result['id'])
        if not fields or "frontends" in fields:
            # Test self.pk to prevent M2M errors when object isn't saved in DB
            result['frontends'] = [str(frontend) for frontend in self.frontend_set.all()] if self.pk else []

        return result

    def get_base_filename(self, code):
        return "{}_{}.html".format(self.name, code)

    def get_filename(self, code):
        return "{}/{}".format(CONF_PATH, self.get_base_filename(code))

    def generate_frontend_conf(self):
        result = ""
        for error_code in [400, 403, 405, 408, 425, 429, 500, 502, 503, 504]:
            mode = getattr(self, "error_{}_mode".format(error_code))
            if mode == "display":
                result += "errorfile {} {}".format(error_code, self.get_filename(error_code))
            elif mode == "302":
                result += "errorloc302 {} {}".format(error_code, getattr(self, "error_{}_url".format(error_code)))
            elif mode == "303":
                result += "errorloc303 {} {}".format(error_code, getattr(self, "error_{}_url".format(error_code)))
            result += "\n"
        return result

    def write_conf(self):
        api_res = {'status': True}
        for error_code in [400, 403, 405, 408, 425, 429, 500, 502, 503, 504]:
            mode = getattr(self, "error_{}_mode".format(error_code))
            if mode == "display":
                api_res = Cluster.api_request("system.config.models.write_conf",
                                    [self.get_filename(error_code),
                                     getattr(self, "error_{}_html".format(error_code)),
                                     TEMPLATE_OWNER, TEMPLATE_PERMS])
        # Return the last API request result
        return api_res

    def delete_conf(self):
        api_res = {'status': True}
        for error_code in [400, 403, 405, 408, 425, 429, 500, 502, 503, 504]:
            api_res = Cluster.api_request("system.config.models.delete_conf", self.get_base_filename(error_code))
            if not api_res.get('status'):
                # If error, return-it
                return api_res
        # Return True if no API error
        return {'status': True}
