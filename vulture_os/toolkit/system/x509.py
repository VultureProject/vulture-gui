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
__maintainer__ = "Vulture Project"
__email__ = "contact@vultureproject.org"
__doc__ = 'System Utils X509 Toolkit'

import sys
import time
from M2Crypto import X509, EVP, RSA, ASN1
sys.path.append("/home/vlt-os/vulture_os/")


def mk_ca_issuer(CN, C, ST, L, O, OU):
    """Our default CA issuer name.

    :param CN: Common Name field
    :param C: Country Name
    :param ST: State or province name
    :param L: Locality
    :param O: Organization
    :param OU: Organization Unit
    :return:
    """
    issuer = X509.X509_Name()
    issuer.C = C
    issuer.CN = CN
    issuer.ST = ST
    issuer.L = L
    issuer.O = O
    issuer.OU = OU
    return issuer


def mk_cert_valid(cert, days=3652):
    """Make a cert valid from now and til 'days' from now.

    :param cert: cert to make valid
    :param days: number of days cert is valid for from now.
    """
    t = int(time.time())
    now = ASN1.ASN1_UTCTIME()
    now.set_time(t)
    expire = ASN1.ASN1_UTCTIME()
    expire.set_time(t + days * 24 * 60 * 60)
    cert.set_not_before(now)
    cert.set_not_after(expire)


def mk_request(bits, CN, C, ST, L, O, OU):
    """Create a X509 request with the given number of bits in they key.

    :param bits: number of RSA key bits
    :param CN: Common Name field
    :param C: Country Name
    :param ST: State or province name
    :param L: Locality
    :param O: Organization
    :param OU: Organization Unit
    :returns: a X509 request and the private key (EVP)
    """
    pk = EVP.PKey()
    x = X509.Request()
    rsa = RSA.gen_key(bits, 65537, lambda: None)
    pk.assign_rsa(rsa)
    x.set_pubkey(pk)

    subject_name = X509.X509_Name()
    subject_name.add_entry_by_txt(field="CN", type=ASN1.MBSTRING_ASC, entry=CN or "", len=-1, loc=-1, set=0)
    subject_name.add_entry_by_txt(field="C", type=ASN1.MBSTRING_ASC, entry=C or "", len=-1, loc=-1, set=0)
    subject_name.add_entry_by_txt(field="ST", type=ASN1.MBSTRING_ASC, entry=ST or "", len=-1, loc=-1, set=0)
    subject_name.add_entry_by_txt(field="L", type=ASN1.MBSTRING_ASC, entry=L or "", len=-1, loc=-1, set=0)
    subject_name.add_entry_by_txt(field="O", type=ASN1.MBSTRING_ASC, entry=O or "", len=-1, loc=-1, set=0)
    subject_name.add_entry_by_txt(field="OU", type=ASN1.MBSTRING_ASC, entry=OU or "", len=-1, loc=-1, set=0)
    x.set_subject_name(subject_name)

    x.sign(pk, 'sha256')
    return x, pk


def mk_ca_cert(CN, C, ST, L, O, OU):
    """Make a CA certificate.

    :param CN: Common Name field
    :param C: Country Name
    :param ST: State or province name
    :param L: Locality
    :param O: Organization
    :param OU: Organization Unit
    :returns: the certificate, private key and public key.
    """
    req, pk = mk_request(2048, CN, C, ST, L, O, OU)
    pkey = req.get_pubkey()
    cert = X509.X509()
    cert.set_serial_number(1)
    cert.set_version(2)
    mk_cert_valid(cert, 7200)
    cert.set_issuer(mk_ca_issuer(CN, C, ST, L, O, OU))
    cert.set_subject(cert.get_issuer())
    cert.set_pubkey(pkey)
    cert.add_ext(X509.new_extension('basicConstraints', 'CA:TRUE'))
    cert.add_ext(X509.new_extension(
        'subjectKeyIdentifier', str(cert.get_fingerprint()))
    )
    cert.sign(pk, 'sha256')
    return cert, pk, pkey


def mk_cert(serial):
    """Make a certificate.

    :return: a new cert.
    """
    cert = X509.X509()
    cert.set_serial_number(serial)
    cert.set_version(2)
    mk_cert_valid(cert, 1825)
    cert.add_ext(X509.new_extension(
        'keyUsage', 'digitalSignature, keyEncipherment'
    ))
    cert.add_ext(X509.new_extension(
        'nsComment', 'Issued by VulturePKI'
    ))
    cert.add_ext(X509.new_extension(
        'extendedKeyUsage', 'serverAuth, clientAuth'
    ))

    return cert


def mk_ca_cert_files(CN, C, ST, L, O, OU):
    """Create CA cacert files (cert + key).

    :param CN: Common Name field
    :param C: Country Name
    :param ST: State or province name
    :param L: Locality
    :param O: Organization
    :param OU: Organization Unit
    """
    ca_cert, pk1, pkey = mk_ca_cert(CN, C, ST, L, O, OU)

    # Save files
    ca_cert.save_pem("/var/db/pki/ca.pem")
    pk1.save_key("/var/db/pki/ca.key", cipher=None)
    return ca_cert, pk1


def mk_signed_cert(CN, C, ST, L, O, OU, serial):
    """Create certificate (cert+key) signed by the given CA, and with the
    given parameters.

    :param CN: Common Name field
    :param C: Country Name
    :param ST: State or province name
    :param L: Locality
    :param O: Organization
    :param OU: Organization Unit
    :param serial: Certificate serial number
    :return: Certificate and certificate key
    """
    cert_req, pk2 = mk_request(2048, CN, C, ST, L, O, OU)
    ca_cert = X509.load_cert("/var/db/pki/ca.pem")
    pk1 = EVP.load_key("/var/db/pki/ca.key")

    # Sign certificate
    cert = mk_cert(serial)
    cert.set_subject(cert_req.get_subject())
    cert.set_pubkey(cert_req.get_pubkey())
    cert.set_issuer(ca_cert.get_issuer())
    cert.sign(pk1, 'sha256')

    return cert, pk2


def mk_signed_cert_files(CN, C='fr', ST='', L='', O='', OU='', serial=1):
    """Create certificate files (cert+key) signed by the given CA, and with the
    given parameters.

    :param CN: Common Name field
    :param C: Country Name
    :param ST: State or province name
    :param L: Locality
    :param O: Organization
    :param OU: Organization Unit
    """
    cert, pk2 = mk_signed_cert(CN, C, ST, L, O, OU, serial)

    # Writing PEM File for MongoDB
    f = open("/var/db/pki/node.pem", 'wb')
    cert_and_key = cert.as_pem() + pk2.as_pem(None)
    f.write(cert_and_key)
    f.close()
    # Writing Cert and Key
    f_cert = open("/var/db/pki/node.cert", 'wb')
    f_cert.write(cert.as_pem())
    f_cert.close()
    f_key = open("/var/db/pki/node.key", 'wb')
    f_key.write(pk2.as_pem(None))
    f_key.close()
    return cert, pk2
