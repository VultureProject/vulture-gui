#!/home/vlt-os/env/bin/python
"""This file is part of Vulture 3.

Vulture 3 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Vulture 3 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Vulture 3.  If not, see http://www.gnu.org/licenses/.
"""
__author__ = "Jérémie JOURDIN"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'PKI main models'


from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from M2Crypto import X509
from djongo import models
import logging
import OpenSSL
import urllib.request
import datetime

from system.exceptions import VultureSystemConfigError
from toolkit.system.x509 import mk_signed_cert

import subprocess

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


PROTOCOL_CHOICES = (
    ('tlsv13', 'TLSv1.3'),
    ('tlsv12', 'TLSv1.2'),
    ('tlsv11', 'TLSv1.1'),
    ('tlsv10', 'TLSv1.0'),
    ('sslv3', 'SSLv3')
)

BROWSER_CHOICES = (
    ('advanced', 'Advanced (A)'),
    ('broad', 'Broad Compatibility (B)'),
    ('widest', 'Widest Compatibility (C)'),
    ('legacy', 'Legacy (D)'),
    ('custom', 'Custom')
)

PROTOCOLS_HANDLER = {
    'advanced': 'tlsv13,tlsv12',
    'broad': 'tlsv13,tlsv12',
    'widest': 'tlsv13,tlsv12,tlsv11,tlsv10',
    'legacy': 'tlsv13,tlsv12,tlsv11,tlsv10'
}

CIPHER_SUITES = {
    'advanced': 'TLS_AES_256_GCM_SHA384:'
                'TLS_CHACHA20_POLY1305_SHA256:'
                'TLS_AES_128_GCM_SHA256:'
                'DHE-RSA-AES256-GCM-SHA384:'
                'DHE-RSA-AES128-GCM-SHA256:'
                'ECDHE-RSA-AES256-GCM-SHA384:'
                'ECDHE-RSA-AES128-GCM-SHA256',
    'broad': 'TLS_AES_256_GCM_SHA384:'
            'TLS_CHACHA20_POLY1305_SHA256:'
            'TLS_AES_128_GCM_SHA256:'
            'DHE-RSA-AES256-GCM-SHA384:'
            'DHE-RSA-AES128-GCM-SHA256:'
            'ECDHE-RSA-AES256-GCM-SHA384:'
            'ECDHE-RSA-AES128-GCM-SHA256:'
            'DHE-RSA-AES256-SHA256:'
            'DHE-RSA-AES128-SHA256:'
            'ECDHE-RSA-AES256-SHA384:'
            'ECDHE-RSA-AES128-SHA256',
    'widest': 'TLS_AES_256_GCM_SHA384:'
            'TLS_CHACHA20_POLY1305_SHA256:'
            'TLS_AES_128_GCM_SHA256:'
            'DHE-RSA-AES256-GCM-SHA384:'
            'DHE-RSA-AES128-GCM-SHA256:'
            'ECDHE-RSA-AES256-GCM-SHA384:'
            'ECDHE-RSA-AES128-GCM-SHA256:'
            'DHE-RSA-AES256-SHA256:'
            'DHE-RSA-AES128-SHA256:'
            'ECDHE-RSA-AES256-SHA384:'
            'ECDHE-RSA-AES128-SHA256:'
            'ECDHE-RSA-AES256-SHA:'
            'ECDHE-RSA-AES128-SHA:'
            'DHE-RSA-AES256-SHA:DHE-RSA-AES128-SHA',
    'legacy': 'TLS_AES_256_GCM_SHA384:'
            'TLS_CHACHA20_POLY1305_SHA256:'
            'TLS_AES_128_GCM_SHA256:'
            'DHE-RSA-AES256-GCM-SHA384:'
            'DHE-RSA-AES128-GCM-SHA256:'
            'ECDHE-RSA-AES256-GCM-SHA384:'
            'ECDHE-RSA-AES128-GCM-SHA256:'
            'DHE-RSA-AES256-SHA256:'
            'DHE-RSA-AES128-SHA256:'
            'ECDHE-RSA-AES256-SHA384:'
            'ECDHE-RSA-AES128-SHA256:'
            'ECDHE-RSA-AES256-SHA:'
            'ECDHE-RSA-AES128-SHA:'
            'AES256-GCM-SHA384:'
            'AES128-GCM-SHA256:'
            'AES256-SHA256:'
            'AES128-SHA256:'
            'AES256-SHA:'
            'AES128-SHA:'
            'DHE-RSA-AES256-SHA:'
            'DHE-RSA-AES128-SHA'
}

ALPN_CHOICES = (
    ('h2', "HTTP2"),
    ('http/1.1', "HTTP1.1"),
    ('http/1.0', "HTTP1.0"),
)

VERIFY_CHOICES = (
    ('none', 'No'),
    ('optional', 'Optional'),
    ('required', 'Required')
)

CERT_PATH = "/var/db/pki"
CERT_OWNER = "vlt-os:haproxy"
CERT_PERMS = "640"


class X509Certificate(models.Model):
    """ SSL Certificate model representation
    name: name gave to the certificate
    cert: Certificate file
    key: Key file
    chain : certification chain
    """

    name = models.TextField()

    """ Serial is ONLY used for internal PKI
        For external certificate, it is forced to zero
    """
    serial = models.SmallIntegerField(default=1)
    status = models.TextField(blank=True, default='V')

    cert = models.TextField(blank=True)
    key = models.TextField(blank=True)
    chain = models.TextField(blank=True)
    csr = models.TextField(blank=True)
    crl = models.TextField(blank=True)

    # Is the certificate a Certificate Authority
    is_ca = models.BooleanField(default=False)

    # If True: This is the Internal Vulture ROOT CA
    is_vulture_ca = models.BooleanField(default=False)

    # This is for external certificate, not managed by us
    is_external = models.BooleanField(default=False)
    crl_uri = models.TextField(blank=True, default='')

    rev_date = models.TextField(blank=True)

    def __init__(self, *args, **kwargs):
        super(X509Certificate, self).__init__(*args, **kwargs)

    def get_base_filename(self):
        return "{}/{}-{}".format(CERT_PATH, self.name, self.id)

    def gen_letsencrypt(self, cn, name):
        """
        Create a Let's encrypt certificate and save it into mongoDB.
        These certificate are automatically renewed: A crontab job maintains the expiration date and the status

        :param cn: CN attribute of the certificate
        :param name: Friendly name
        :return: the bundled certificate, or False in case of a failure
        """

        # Abort if there is an existing certificate with this name (can occur during bootstrap failure)
        try:
            pki = X509Certificate.objects.get(is_vulture_ca=False, name=name)
            return {'cert': pki.cert, 'key': pki.key}
        except Exception as e:
            pass

        # Call let's encrypt to issue a certificate.
        # This may take some time

        try:
            proc = subprocess.Popen(['/usr/local/sbin/acme.sh', '--issue', '-d', cn, '--webroot',
                                     '/var/db/acme/'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)
            success, error = proc.communicate()
            if error:
                logger.error("X509Certificate::gen_letsencrypt(): {}".format(error.decode('utf-8')))
                return False

        except Exception as e:
            logger.error("X509Certificate::gen_letsencrypt(): {}".format(e))
            return False

        # Read certificate, private key and chain file
        with open("/var/db/acme/.acme.sh/{}/{}.cer".format(cn, cn)) as pem_cert:
            with open("/var/db/acme/.acme.sh/{}/{}.key".format(cn, cn)) as pem_key:
                with open("/var/db/acme/.acme.sh/{}/fullchain.cer".format(cn)) as pem_chain:

                    try:
                        tmp_crt = X509.load_cert_string(pem_cert)
                    except Exception as e:
                        logger.error("X509Certificate::gen_letsencrypt(): {}".format(e))
                        return False

                    # Store the certificate
                    try:
                        self.name = name
                        self.cert = pem_cert.decode('utf-8')
                        self.key = pem_key.decode('utf-8')
                        self.status = 'V'
                        self.is_vulture_ca = False
                        self.is_external = True
                        self.serial = tmp_crt.get_serial_number().decode('utf-8')
                        self.chain = pem_chain.decode('utf-8')
                        self.save()
                    except Exception as e:
                        logger.error("X509Certificate::gen_letsencrypt: {}".format(e))
                        return False

        return {'cert': self.cert, 'key': self.key}

    def gen_cert(self, cn, name):
        """
        Create a Vulture internal certificate and save it into mongoDB.

        :param cn: CN attribute of the certificate
        :param name: Friendly name
        :return: the bundled certificate, or False in case of a failure
        """

        # Abort if there is an existing certificate with this name (can occur during bootstrap failure)
        try:
            pki = X509Certificate.objects.get(is_vulture_ca=False, name=name)
            return {'cert': pki.cert, 'key': pki.key}
        except X509Certificate.DoesNotExist:
            pass

        internal_ca = X509Certificate.objects.get(is_vulture_ca=True, name__startswith="Vulture_PKI")
        next_serial = internal_ca.get_next_serial
        attributes = internal_ca.explose_dn()

        try:
            crt, pk2 = mk_signed_cert(cn, attributes['C'], attributes['ST'], attributes[
                                      'L'], attributes['O'], attributes['OU'], next_serial)

            # Store the certificate
            self.name = name
            self.cert = crt.as_pem().decode('utf-8')
            self.key = pk2.as_pem(cipher=None).decode('utf-8')
            self.status = 'V'
            self.is_vulture_ca = False
            self.is_external = False
            self.serial = str(next_serial)
            self.chain = str(internal_ca.cert)
            self.save()
        except Exception as e:
            logger.error("X509Certificate::gen_cert: {}".format(str(e)))
            return False

        return {'cert': self.cert, 'key': self.key}

    @property
    def get_next_serial(self):
        """
        :return: An integer for the next serial number of self-signed Vulture certificate
        """
        try:
            x = X509Certificate.objects.filter(serial__gt=1).order_by('-serial')[0]
            return x.serial + 1
        except Exception:
            return 2

    def to_template(self):
        """ Dictionary used to create configuration file related to the node
        :return     Dictionnary of configuration parameters
        """
        cert = X509.load_cert_string(str(self.cert))
        conf = {
            'id': str(self.id),
            'name': self.name,
            'subject': cert.get_subject().as_text(),
            'issuer': cert.get_issuer().as_text(),
            'status': self.status,
            'validfrom': str(cert.get_not_before()),
            'validtill': str(cert.get_not_after()),
            'is_vulture_ca': self.is_vulture_ca,
            'is_ca': self.is_ca,
            'is_external': self.is_external,
            'crl': self.crl,
            'crl_uri': self.crl_uri
        }

        return conf

    def explose_dn(self):
        """
        :return: A dictionary with the explosed subject
        """
        attributes = dict()
        cert = X509.load_cert_string(self.cert)
        for attr in cert.get_subject().as_text().split(", "):
            k, v = attr.split("=")
            attributes[k] = v

        return attributes

    def get_vulture_ca(self):
        """
        :return: The X509Certificate object related to the internal Vulture ROOT CA
        """

        return X509Certificate.objects.get(is_vulture_ca=True)

    def is_ca_cert(self):
        """
        :return: True if the certificate is a Certificate Authority
        """
        cert = X509.load_cert_string(self.cert)
        if cert.check_ca() == 1:
            return True
        return False

    def gen_crl(self):
        """ Build and return the CRL associated to the Vulture's internal ROOT CA
        """

        if self.is_vulture_ca:
            logger.debug("PKI::gen_crl: Building Vulture's internal CRL")
            CRL = OpenSSL.crypto.CRL()
            certs = X509Certificate.objects.filter(status='R').order_by('serial')
            for cert in certs:
                try:
                    rev = OpenSSL.crypto.Revoked()
                    rev.set_rev_date(str(cert.rev_date).encode('ascii'))
                    rev.set_serial(str(cert.serial).encode('ascii'))
                    rev.set_reason(None)
                    CRL.add_revoked(rev)
                except Exception as e:
                    logger.error("PKI::gen_crl: {}".format(str(e)))
                    return False

            # Now generate the CRL
            logger.debug("PKI::gen_crl: Storing the CRL into vulture_ca_cert")
            vulture_ca_cert = self.get_vulture_ca()
            ca_key = OpenSSL.crypto.load_privatekey(OpenSSL.crypto.FILETYPE_PEM, str(vulture_ca_cert.key))
            ca_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM, str(vulture_ca_cert.cert))
            ca_crl = CRL.export(ca_cert, ca_key, OpenSSL.crypto.FILETYPE_PEM, 365, b"sha256")
            vulture_ca_cert.crl = ca_crl
            vulture_ca_cert.save()
            return ca_crl

        elif self.is_external and self.crl_uri:
            logger.debug("PKI::gen_crl: Fetching external CRL")
            self.crl = self.download_crl()
            logger.debug("PKI::gen_crl: Storing the CRL into database")
            self.save()
            return self.crl

    def download_crl(self):
        if self.is_external and self.crl_uri:
            try:
                response = urllib.request.urlopen(self.crl_uri)
                data = response.read()
                return data.decode('utf-8')
            except Exception as e:
                logger.error("PKI::getCRL: {}".format(str(e)))
                return None

        return None

    def get_crl(self):
        """
        :return: Return the CRL associated to the certificate
        """

        if self.crl:
            return self.crl
        else:
            return None

    def revoke(self):
        """
        Revoke a certificate
        :return: True / False
        """

        if self.is_external:
            logger.error("PKI::revoke: Trying to revoke external certificate")
            return False
        elif self.is_vulture_ca:
            logger.critical("PKI::revoke: Trying to revoke Vulture's CA !")
            return False
        else:
            self.rev_date = "{:%Y%m%d%H%M%SZ}".format(datetime.datetime.now())
            self.status = 'R'
            self.save()
            self.gen_crl()

    def as_bundle(self):
        """
        :return: An all-in-one PEM file with private Key + Certificate + Chain
        """

        buffer = self.cert + "\n" + self.key
        if self.chain:
            buffer = buffer + "\n" + self.chain

        return buffer

    def get_extensions(self):
        """ Return the list of extensions of this certificate 
        depending on attributes """
        extensions = {
            '.pem': self.as_bundle(),
            '.crt': self.cert,
            '.key': self.key
        }
        """ If this is a CA, write the cert as .crt """
        if self.is_ca_cert():
            extensions['.crt'] = self.cert
        else:
            extensions['.chain'] = self.chain

        return extensions

    def save_conf(self):
        """ Write cert as all formats currently supported
        This function raise VultureSystemConfigError if failure """
        from system.cluster.models import Cluster
        extensions = self.get_extensions()

        # Retrieve and stock variable to improve loop perf
        base_filename = self.get_base_filename()

        """ For each extensions to be written """
        for extension, buffer in extensions.items():
            params = [base_filename + extension, buffer, CERT_OWNER, CERT_PERMS]

            """ API request """
            api_res = Cluster.api_request('system.config.models.write_conf', config=params, internal=True)
            if not api_res.get('status'):
                raise VultureSystemConfigError(". API request failure ", traceback=api_res.get('message'))

    def delete_conf(self):
        """ Delete all format of the current certificate
        :return   True if success
        raise VultureSystemConfigError if failure
        """
        from system.cluster.models import Cluster
        # Firstly try to delete the conf, if it fails the object will not be deleted
        extensions = self.get_extensions()

        for extension in extensions.keys():
            api_res = Cluster.api_request("system.config.models.delete_conf", self.get_base_filename()+extension)
            if not api_res.get('status'):
                raise VultureSystemConfigError(". API request failure.", traceback=api_res.get('message'))
        return True

    def save(self, **kwargs):
        """ Override of save method to write cert on disk """
        """ First of all, save the object to get an id """
        self.is_ca = self.is_ca_cert()
        super().save(**kwargs)

        """ Only then, write the file(s) on disk """
        self.save_conf()

    @staticmethod
    def str_attrs():
        """ List of attributes required by __str__ method """
        return ['name']

    def __str__(self):
        return "{}" .format(self.name)


class TLSProfile(models.Model):
    """ Representation of all needed attributes for tls binding/connect """
    """ Name of the current tls profile """
    name = models.TextField(
        unique=True,
        default="TLS Profile",
        help_text=_("Name of the TLS profile"),
    )
    """ X509Certificate reference """
    x509_certificate = models.ForeignKey(
        to=X509Certificate,
        on_delete=models.CASCADE,
        related_name="certificate_of",
        help_text=_("X509Certificate object to use.")
    )
    """ Compatibility of web browsers """
    compatibility = models.TextField(
        default="broad",
        choices=BROWSER_CHOICES,
        help_text=_("Compatibility of web browsers.")
    )
    """ Allowed listening protocols """
    protocols = models.ListField(
        models.TextField(choices=PROTOCOL_CHOICES),
        default=["tlsv12"],
        help_text=_("Allowed protocol ciphers.")
    )
    """ List of cipher algorithms (cipher suite) allowed 
    during the SSL/TLS handshake """
    cipher_suite = models.TextField(
        default=CIPHER_SUITES['broad'],
        help_text=_("Allowed protocol ciphers.")
    )
    """ Allowed http protocols """
    alpn = models.ListField(
        models.TextField(choices=ALPN_CHOICES),
        default=["h2", "http/1.1"],
        help_text=_("Advertise the TLS ALPN extensions list.")
    )
    """ Verification mode of the client certificate """
    verify_client = models.TextField(
        default="none",
        choices=VERIFY_CHOICES,
        help_text=_("If set to 'none', client certificate is not requested. This is the default. In other cases, "
                    "a client certificate is requested.")
    )
    """ CA certificate as PEM, used to verify client cert """
    ca_cert = models.ForeignKey(
        to=X509Certificate,
        on_delete=models.CASCADE,
        null=True,
        blank=False,
        related_name="ca_cert_of",
        help_text=_("CA certificate used to verify client's certificate if verify != none.")
    )

    def __str__(self):
        return "TLS Profile '{}' ({}:{})".format(self.name, str(self.x509_certificate), self.protocols)

    def to_html_template(self):
        return {
            'id': str(self.id),
            'name': self.name,
            'x509_certificate': str(self.x509_certificate),
            'protocols': self.protocols,
            'verify_client': self.verify_client,
            'ca_cert': str(self.ca_cert) if self.verify_client != "none" else ""
        }

    def to_template(self):
        return {
            'id': str(self.id),
            'name': self.name,
            'x509_certificate': self.x509_certificate,
            'protocols': self.protocols,
            'cipher_suite': self.cipher_suite,
            'alpn': self.alpn
        }

    @property
    def client_ca_cert_filename(self):
        return "/var/db/pki/client_{}.crt".format(self.id)

    def save_conf(self):
        # self.x509_certificate.save_conf()
        if self.verify_client != "none":
            self.ca_cert.save_conf()

    def generate_conf(self, backend=False):
        """ Most important : the cert """
        result = " ssl crt '{}'".format(self.x509_certificate.get_base_filename() + ".pem")
        """ ALPN is not compatible with Backend """
        if not backend:
            """ Add list of ALPN """
            result += " alpn " + ",".join(self.alpn)
        """ Add force-<proto> or no-<proto> to enable and disable chosen protocols """
        if len(self.protocols) == 1:
            result += " force-{}".format(self.protocols[0])
        else:
            for proto in PROTOCOL_CHOICES:
                if proto[0] not in self.protocols:
                    result += " no-{}".format(proto[0])
        # FIXME : Only if custom ?
        """ Add ciphers """
        result += " ciphers {}".format(self.cipher_suite)
        """ If verify client -> add ca-cert """
        result += " verify {}".format(self.verify_client)
        if self.verify_client != "none":
            result += " ca-file {}".format(self.ca_cert.get_base_filename() + ".crt")
        return result
