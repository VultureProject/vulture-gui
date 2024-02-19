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
from datetime import datetime, timezone, timedelta
from cryptography import x509
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
sys.path.append("/home/vlt-os/vulture_os/")


def get_cert_PEM(cert: x509.Certificate) -> bytes:
    return cert.public_bytes(serialization.Encoding.PEM)

def get_key_PEM(key: rsa.RSAPrivateKey) -> bytes:
    return key.private_bytes(encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption())

def mk_cert_subject(CN: str, C: str, ST: str, L: str, O: str, OU: str) -> x509.Name:
    """Generate an issuer/subject name infos

    :param CN: Common Name field
    :param C: Country Name
    :param ST: State or province name
    :param L: Locality
    :param O: Organization
    :param OU: Organization Unit
    :return:
    """
    return x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, C),
        x509.NameAttribute(NameOID.COMMON_NAME, CN),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, ST),
        x509.NameAttribute(NameOID.LOCALITY_NAME, L),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, O),
        x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, OU),
    ])


def mk_cert_valid(builder: x509.CertificateBuilder, start: datetime = datetime.now(timezone.utc), days: int =3652) -> x509.CertificateBuilder:
    """Make a cert valid from start to 'days' from start.

    :param cert: cert to make valid
    :param start: valid datetime object specifying the start of validity for the certificate (will be forced to URC if timezone-naive)
    :param days: number of days cert is valid for from start.
    """
    if not start.tzinfo:
        start = start.replace(tzinfo=timezone.utc)
    builder = builder.not_valid_before_utc(start)
    builder = builder.not_valid_after_utc(start + timedelta(days=days))

    return builder


def mk_request(bits: int, CN: str, C: str, ST: str, L: str, O: str, OU: str) -> tuple([x509.CertificateSigningRequest, rsa.RSAPrivateKey]):
    """Create a X509 request with the given number of bits in the key.

    :param bits: number of RSA key bits
    :param CN: Common Name field
    :param C: Country Name
    :param ST: State or province name
    :param L: Locality
    :param O: Organization
    :param OU: Organization Unit
    :returns: a X509 request and its private key
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=bits,
    )

    csr = x509.CertificateSigningRequestBuilder().subject_name(mk_cert_subject(
        CN=CN,
        C=C,
        ST=ST,
        L=L,
        O=O,
        OU=OU
    )).sign(private_key, hashes.SHA256())

    return csr, private_key


def mk_ca_cert(CN: str, C: str, ST: str, L: str, O: str, OU: str) -> tuple([x509.Certificate, rsa.RSAPrivateKey]):
    """Make a CA certificate.

    :param CN: Common Name field
    :param C: Country Name
    :param ST: State or province name
    :param L: Locality
    :param O: Organization
    :param OU: Organization Unit
    :returns: the certificate and private key.
    """
    csr, private_key = mk_request(2048, CN=CN, C=C, ST=ST, L=L, O=O, OU=OU)

    builder = x509.CertificateBuilder().subject_name(csr.subject)
    # Make certificate valid for 2 years
    builder = mk_cert_valid(builder, days=7200)

    builder = builder.issuer_name(csr.subject)
    builder = builder.public_key(private_key.public_key())
    # TODO this seems wrong, serial should be randomly generated
    builder = builder.serial_number(1)
    builder = builder.add_extension(
        x509.BasicConstraints(ca=True, path_length=None),
        critical=False
    )

    cert = builder.sign(private_key, hashes.SHA256())

    return cert, private_key


def mk_cert_builder(serial: int) -> x509.CertificateBuilder:
    """Make a certificate.

    :return: a new cert.
    """
    builder = x509.CertificateBuilder()
    builder = builder.serial_number(serial)
    builder = mk_cert_valid(builder, days=1825)

    builder = builder.add_extension(
        x509.KeyUsage(
        digital_signature=True,
        key_encipherment=True,
        content_commitment=False,
        data_encipherment=False,
        key_agreement=False,
        key_cert_sign=False,
        crl_sign=False,
        encipher_only=False,
        decipher_only=False,
        ),
        critical=False
    )
    # TODO is it still necessary?
    # nsComment extension
    builder = builder.add_extension(
        x509.UnrecognizedExtension(x509.ObjectIdentifier("2.16.840.1.113730.1.13"), b"Issued by VulturePKI"),
        critical=False
    )
    builder = builder.add_extension(
        x509.ExtendedKeyUsage([
            ExtendedKeyUsageOID.SERVER_AUTH,
            ExtendedKeyUsageOID.CLIENT_AUTH
        ]),
        critical=False
    )

    return builder


def mk_ca_cert_files(CN: str, C: str, ST: str, L: str, O: str, OU: str) -> tuple([x509.Certificate, rsa.RSAPrivateKey]):
    """Write CA cacert files (cert + key).

    :param CN: Common Name field
    :param C: Country Name
    :param ST: State or province name
    :param L: Locality
    :param O: Organization
    :param OU: Organization Unit
    """
    ca_cert, private_key = mk_ca_cert(CN=CN, C=C, ST=ST, L=L, O=O, OU=OU)
    ca_cert_pem = get_cert_PEM(ca_cert)
    private_key_pem = get_key_PEM(private_key)

    with open("/var/db/pki/ca.pem", "wb") as cert_file:
        cert_file.write(ca_cert_pem)
    with open("/var/db/pki/ca.key", "wb") as key_file:
        key_file.write(private_key_pem)

    return ca_cert_pem, private_key_pem


# TODO update calls to include ca_cert and ca_key
def mk_signed_cert(CN: str, C: str, ST: str, L: str, O: str, OU: str, serial: str, ca_cert: bytes, ca_key: bytes):
    """Create certificate (cert+key) signed by the root CA, and with the
    given parameters.

    :param CN: Common Name field
    :param C: Country Name
    :param ST: State or province name
    :param L: Locality
    :param O: Organization
    :param OU: Organization Unit
    :param serial: Certificate serial number
    :param ca_cert: CA certificate to sign new certificate with (PEM format)
    :param ca_key: CA private key to sign new certificate with (PEM format)
    :return: Certificate and certificate key
    """
    ca_cert_obj = x509.load_pem_x509_certificate(data=ca_cert)
    ca_key_obj = serialization.load_pem_private_key(data=ca_key, password=None)

    csr, private_key = mk_request(2048, CN=CN, C=C, ST=ST, L=L, O=O, OU=OU)

    cert = mk_cert_builder(serial=serial).subject_name(
        csr.subject
    ).public_key(
        csr.public_key()
    ).issuer_name(
        ca_cert_obj.issuer
    ).sign(ca_key_obj, hashes.SHA256())

    return cert, private_key


def mk_signed_cert_files(CN: str, C: str, ST: str, L: str, O: str, OU: str, serial: int, ca_cert: bytes, ca_key: bytes):
    """Create certificate files (cert+key) signed by the given CA, and with the
    given parameters.

    :param CN: Common Name field
    :param C: Country Name
    :param ST: State or province name
    :param L: Locality
    :param O: Organization
    :param OU: Organization Unit
    :param serial: serial number
    :param ca_cert: bytes representing the certificate (PEM format)
    :param ca_key: bytes representing the private key (PEM format)
    """
    cert, private_key = mk_signed_cert(CN, C, ST, L, O, OU, serial, ca_cert, ca_key)

    cert_pem = get_cert_PEM(cert)
    key_pem = get_key_PEM(private_key)
    node_pem = cert_pem + key_pem

    with open("/var/db/pki/node.pem", "wb") as node_file:
        node_file.write(node_pem)
    with open("/var/db/pki/node.cert", "wb") as cert_file:
        cert_file.write(cert_pem)
    with open("/var/db/pki/node.key", "wb") as key_file:
        key_file.write(key_pem)

    return cert, private_key

