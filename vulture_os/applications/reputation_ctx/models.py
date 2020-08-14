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
from django.utils import timezone
from django.utils.translation import ugettext_lazy as _
from djongo import models

# Django project imports
from toolkit.network.network import get_proxy
from toolkit.log.maxminddb import test_mmdb_database, open_mmdb_database

# Extern modules imports
from gzip import decompress as gzip_decompress
from io import BytesIO
import requests
from requests.auth import HTTPBasicAuth, HTTPDigestAuth
from re import compile as re_compile

# Required exceptions imports
from services.exceptions import ServiceConfigError
from system.exceptions import VultureSystemError, VultureSystemConfigError

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


# Database types
DBTYPE_CHOICES = (
    ('ipv4', 'IPv4 MMDB'),
    ('ipv6', 'IPv6 MMDB'),
    ('ipv4_netset', 'IPv4 Netset'),
    ('ipv6_netset', 'IPv6 Netset'),
    ('domain', 'Host/Domain names'),
    ('GeoIP', 'GeoIP'),
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

DATABASES_PATH = "/var/db/darwin"
DATABASES_OWNER = "vlt-os:vlt-conf"
DATABASES_PERMS = "644"

REGEX_GZ = re_compile("filename=\"?([^\";]+)\"?")


class ReputationContext(models.Model):
    """ Model used to enrich logs in Rsyslog with mmdb database"""
    name = models.TextField(
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
    """ MMDB database attributes """
    # There cannot be multiple files with the same filename
    filename = models.FilePathField(path=DATABASES_PATH, default="", unique=True)
    description = models.TextField(default="")
    # When saving object, last_update will be automatically updated
    last_update = models.DateTimeField(auto_now=True)
    nb_netset = models.IntegerField(default=0)
    nb_unique = models.IntegerField(default=0)
    internal = models.BooleanField(default=False)

    """ Use DjongoManager to use mongo_find() & Co """
    objects = models.DjongoManager()

    def save(self, *args, **kwargs):
        """ Override mother fonction to prevent save of content attribute in MongoDB 
        """
        self.content = ""
        super().save(*args, **kwargs)

    def delete(self):
        """ Delete file on disk on all nodes """
        from system.cluster.models import Cluster
        Cluster.api_request("system.config.models.delete_conf", self.absolute_filename)
        super().delete()

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
            'description': self.description,
            'db_type': self.db_type,
            'method': self.method,
            'url': self.url,
            'verify_cert': self.verify_cert,
            'post_data': self.post_data,
            'auth_type': self.auth_type,
            'user': self.user,
            'password': self.password,
            'custom_headers': self.custom_headers,
            'internal': self.internal,
            'tags': self.tags
        }
        return result

    def to_html_template(self):
        """ Dictionary used to render object as html
        :return     Dictionnary of configuration parameters
        """
        db_type = self.db_type
        for d in DBTYPE_CHOICES:
            if self.db_type == d[0]:
                db_type = d[1]
        uri = "{} {}".format(self.method, self.url)
        if self.auth_type:
            uri += " {}({}:xxx)".format(self.auth_type, self.user)
        """ Retrieve list/custom objects """
        return {
            'id': str(self.id),
            'name': self.name,
            'db_type': db_type,
            'uri': uri,
            'internal': self.internal,
            'tags': self.tags
        }

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
        logger.debug("Try to get URL {}".format(self.url))
        try:
            response = requests.request(self.method, self.url,
                                        data=self.post_data if self.method == "POST" else None,
                                        headers=self.custom_headers,
                                        auth=auth,
                                        allow_redirects=True,
                                        proxies=get_proxy(),
                                        timeout=(2.0, 2.0))
            # logger.info("URL '{}' retrieved, status code = {}".format(self.url, response.status_code))
            assert response.status_code == 200, "Response code is not 200 ({})".format(response.status_code)
            """ If its a .gz file, dezip-it """
            if self.url[-3:] == ".gz":
                self.filename = self.url.split('/')[-1][:-3]
                return gzip_decompress(response.content)
            if response.headers.get("Content-Disposition"):
                match = REGEX_GZ.search(response.headers.get("Content-Disposition"))
                if match and match[1][-3:] == ".gz":
                    self.filename = match[1][:-3]
                    return gzip_decompress(response.content)
            if not self.filename:
                self.filename = self.url.split('/')[-1]
        except Exception as e:
            raise VultureSystemError(str(e), "download '{}'".format(self.url))
        return response.content

    def download_mmdb(self):
        """ Always call this method first, to be sure the MMDB is OK """
        content = self.download_file()
        if self.db_type in ("ipv4", "ipv6", "GeoIP"):
            try:
                return open_mmdb_database(content)
            except Exception as e:
                logger.error("Downloaded content is not a valid MMDB database")
                raise VultureSystemError("Downloaded content is not a valid MMDB database",
                                         "download '{}'".format(self.url))
        else:
            return None

    def download(self):
        content = self.download_file()
        if self.db_type in ("ipv4", "ipv6", "GeoIP"):
            db_reader = open_mmdb_database(content)
            db_metadata = db_reader.metadata()
            db_reader.close()
            # Do not erase nb_netset in internal db, its retrieved in index.json
            if not self.internal:
                self.nb_netset = db_metadata.node_count
        else:
            self.nb_unique = len(content.decode('utf8').split("\n"))
        return content

    @property
    def absolute_filename(self):
        """ Return filename depending on current frontend object
        """
        # Escape quotes to prevent injections in config or in commands
        return "{}/{}".format(DATABASES_PATH, self.filename.replace('"', '\"'))

    def save_conf(self):
        """ Write configuration on disk
        """
        params = [self.absolute_filename, self.download_file(), DATABASES_OWNER, DATABASES_PERMS]
        try:
            from system.cluster.models import Cluster
            Cluster.api_request('system.config.models.write_conf', config=params)
        except Exception as e:  # e used by VultureSystemConfigError
            raise VultureSystemConfigError("on cluster.\n"
                                           "Request failure to write conf of Reputation context '{}'".format(self.name))

    def get_nodes(self):
        """ Return the list of nodes used by frontends using the current object """
        # for listener in Listener.objects.filter()
        from system.cluster.models import NetworkAddress, Node
        return Node.objects.filter(networkinterfacecard__frontend__reputation_ctxs=self.id)

    def reload_frontend_conf(self):
        """ Send API request on each Nodes using the frontends that uses the current CTX 
        :return     The list of concerned nodes  
        """
        from services.frontend.models import Listener
        from system.cluster.models import Cluster, NetworkAddress, Node
        res = []
        # Loop on Nodes
        for node in Node.objects.all():
            frontends = []
            # Get listeners enabled on this node, using the current reputation context
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
