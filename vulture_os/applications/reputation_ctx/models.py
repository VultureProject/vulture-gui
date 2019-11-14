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
__doc__ = 'Frontends & Listeners model classes'

# Django system imports
from django.conf import settings
from django.core.validators import MinValueValidator, MaxValueValidator
from django.utils.translation import ugettext_lazy as _
from djongo import models

# Django project imports
from toolkit.network.network import get_proxy
from system.cluster.models import Cluster, NetworkAddress, Node

# Extern modules imports
from io import BytesIO
import requests
from requests.auth import HTTPBasicAuth, HTTPDigestAuth

# Required exceptions imports
from maxminddb import open_database as open_mmdb_database, MODE_FD
from services.exceptions import ServiceConfigError
from system.exceptions import VultureSystemError, VultureSystemConfigError

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


# Database types
DBTYPE_CHOICES = (
    ('ipv4_mmdb', 'IPv4 MMDB'),
    ('ipv6_mmdb', 'IPv6 MMDB'),
    ('ipv4-6_mmdb', 'IPv4/6 Netset'),
    ('ipv4_netset', 'IPv4 Netset'),
    ('ipv6_netset', 'IPv6 Netset'),
    ('ipv4-6_netset', 'IPv4/6 Netset'),
    ('host', 'Hostnames'),
)

HTTP_METHOD_CHOICES = (
    ("GET", "GET"),
    ("POST", "POST")
)

HTTP_AUTH_TYPE_CHOICES = (
    ("", "No authentication"),
    ("basic", "Basic"),
    ("digest", "Digest"),
)

AUTH_TYPE_CLASSES = {
    'basic': HTTPBasicAuth,
    'digest': HTTPDigestAuth
}

DATABASE_PATH = "/var/db/reputation_ctx"
CONTEXT_OWNER = "vlt-os:vlt-web"
CONTEXT_PERMS = "640"


class ReputationContext(models.Model):
    """ Model used to enrich logs in Rsyslog with mmdb database"""
    """ Name of the ReputationContext, unique constraint """
    name = models.TextField(
        unique=True,
        default="Reputation context",
        verbose_name=_("Friendly name"),
        help_text=_("Custom name of the current object"),
    )
    """ Database type """
    db_type = models.TextField(
        default=DBTYPE_CHOICES[0][0],
        choices=DBTYPE_CHOICES,
        verbose_name=_("Database type"),
        help_text=_("Type of database"),
    )
    method = models.SlugField(
        default=HTTP_METHOD_CHOICES[0][0],
        choices=HTTP_METHOD_CHOICES,
        verbose_name=_("HTTP method to use"),
        help_text=_("HTTP method to use while retrieving url")
    )
    url = models.URLField(
        help_text=_("URL to retrieve the database from"),
        verbose_name=_("Database URL")
    )
    verify_cert = models.BooleanField(
        default=True,
        help_text=_("Verify certificate to prevent connexion to self-signed certificates."),
        verbose_name=_("Verify server certificate")
    )
    post_data = models.TextField(
        default="",
        null=True,
        verbose_name=_("POST body"),
        help_text=_("Body to send if method is POST")
    )
    custom_headers = models.DictField(
        default={},
        verbose_name=_("Custom headers"),
        help_text=_("Headers to send while retrieving url")
    )
    auth_type = models.TextField(
        default=HTTP_AUTH_TYPE_CHOICES[0][0],
        choices=HTTP_AUTH_TYPE_CHOICES,
        verbose_name=_("Authentication"),
        help_text=_("Authentication type used to retrieve url")
    )
    user = models.SlugField(
        default=None,
        null=True,
        verbose_name=_("Username"),
        help_text=_("Username to use for authentication")
    )
    password = models.TextField(
        default=None,
        null=True,
        verbose_name=_("Password"),
        help_text=_("Password to use for authentication")
    )
    tags = models.ListField(
        models.SlugField(default=""),
        default=[],
        help_text=_("Tags to set on this object for search")
    )
    """ Field not stored in DB, it's just used as cache between fonction classes """
    content = models.BinaryField(
        default=""
    )

    def save(self, *args, **kwargs):
        """ Override mother fonction to prevent save of content attribute in MongoDB 
        """
        self.content = ""
        super().save(*args, **kwargs)

    @staticmethod
    def str_attrs():
        """ List of attributes required by __str__ method """
        return ['name']

    def __str__(self):
        return "ReputationContext '{}'".format(self.name)

    def to_dict(self):
        """ This method MUST be used in API instead of to_template() method
                to prevent no-serialization of sub-models 
        :return     A JSON object
        """
        result = {
            'id': self.id,
            'name': self.name,
            'db_type': self.db_type,
            'method': self.method,
            'url': self.url,
            'post_data': self.post_data,
            'custom_headers': self.custom_headers,
            'tags': self.tags
        }
        return result

    def to_html_template(self):
        """ Dictionary used to render object as html
        :return     Dictionnary of configuration parameters
        """
        result = {
            'id': str(self.id),
            'name': self.name,
            'db_type': self.db_type,
            'tags': self.tags
        }
        uri = "{} {}".format(self.method, self.url)
        if self.auth_type:
            uri += " {}({}:xxx)".format(self.auth_type, self.user)
        result['uri'] = uri
        """ Retrieve list/custom objects """
        return result

    def to_template(self):
        """ Dictionary used to create configuration file

        :return     Dictionnary of configuration parameters
        """
        result = {
            'id': str(self.id),
            'name': self.name,
            'method': self.method,
            'url': self.url,
            'post_data': self.post_data,
            'custom_headers': self.custom_headers,
            'tags': self.tags
        }
        """ Download url """
        #result['content'] = self.download_file()

        """ And returns the attributes of the class """
        return result

    def download_file(self):
        """ """
        """ If we haven't already downloaded url """
        if self.content:
            return self.content

        """ Retrieve url and content """
        auth = None
        if self.auth_type:
            auth_type = AUTH_TYPE_CLASSES.get(self.auth_type)
            if auth_type:
                auth = auth_type(self.user, self.password)
        logger.info("Try to get URL {}".format(self.url))
        try:
            response = requests.request(self.method, self.url,
                                        data=self.post_data if self.method == "POST" else None,
                                        headers=self.custom_headers,
                                        auth=auth,
                                        allow_redirects=True,
                                        proxies=get_proxy(),
                                        timeout=(2.0, 2.0))
            logger.debug("URL '{}' retrieved, status code = {}".format(self.url, response.status_code))
            assert response.status_code == 200, "Response code is not 200 ({})".format(response.status_code)
        except Exception as e:
            logger.exception(e)
            raise VultureSystemError(str(e), "download '{}'".format(self.url))
        return response.content

    def download_mmdb(self):
        """ Always call this method first, to be sure the MMDB is OK """
        self.content = self.download_file()
        tmpfile = BytesIO()
        tmpfile.write(self.content)
        tmpfile.seek(0)
        setattr(tmpfile, "name", "test")
        try:
            return open_mmdb_database(tmpfile, mode=MODE_FD)
        except Exception as e:
            logger.error("Downloaded content is not a valid MMDB database")
            raise VultureSystemError("Downloaded content is not a valid MMDB database",
                                     "download '{}'".format(self.url))

    def get_filename(self):
        """ Return filename depending on current frontend object
        """
        return "{}/reputation_ctx_{}.mmdb".format(DATABASE_PATH, self.id)

    def save_conf(self):
        """ Write configuration on disk
        """
        params = [self.get_filename(), self.download_file(), CONTEXT_OWNER, CONTEXT_PERMS]
        try:
            Cluster.api_request('system.config.models.write_conf', config=params)
        except Exception as e:  # e used by VultureSystemConfigError
            raise VultureSystemConfigError("on cluster.\n"
                                           "Request failure to write conf of Reputation context '{}'".format(self.name))

    def get_nodes(self):
        """ Return the list of nodes used by frontends using the current object """
        # for listener in Listener.objects.filter()
        return Node.objects.filter(networkinterfacecard__frontend__reputation_ctxs=self.id)

    def reload_frontend_conf(self):
        """ Send API request on each Nodes using the frontends that uses the current CTX 
        :return     The list of concerned nodes  
        """
        from services.frontend.models import Listener
        res = []
        # Loop on Nodes
        for node in self.get_nodes():
            frontends = []
            for listener in Listener.objects.filter(frontend__enabled=True,
                                                    frontend__reputation_ctxs=self.id,
                                                    network_address__nic__node=node.id).distinct():
                if listener.frontend.id not in frontends:
                    api_res = node.api_request("services.rsyslogd.rsyslog.build_conf", listener.frontend.id)
                    if not api_res:
                        raise ServiceConfigError("on node '{}' \n API request error.".format(node.name), "rsyslog",
                                                 traceback=api_res.get('message'))
                    frontends.append(listener.frontend.id)
                    res.append(node)
        return res
