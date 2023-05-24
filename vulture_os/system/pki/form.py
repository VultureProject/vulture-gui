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
__author__ = "Jérémie JOURDIN"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Haproxy dedicated form class'

# Django system imports
from django.conf import settings
from django.forms import (ModelChoiceField, ModelForm, Select, SelectMultiple, TextInput, Textarea, ValidationError,
    CharField, ChoiceField, RadioSelect)
from system.pki.models import (ALPN_CHOICES, BROWSER_CHOICES, PROTOCOL_CHOICES, TLSProfile, X509Certificate,
                               VERIFY_CHOICES)

from ast import literal_eval
from cryptography import x509
from ssl import PROTOCOL_TLS, SSLContext, SSLError

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


class X509InternalCertificateForm(ModelForm):

    cn = CharField(required=True)
    type = ChoiceField(required=True,choices=(('internal','Self-Signed Vulture Certificate'),('letsencrypt','Let\'s Encrypt Certificate'),('external','External certificate')))

    class Meta:
        model = X509Certificate
        fields = ('name','cn','type',)

        widgets = {
            'name': TextInput(attrs={'class': 'form-control'}),
            'type': RadioSelect(choices=(('internal','Self-Signed Vulture Certificate'),('letsencrypt','Let\'s Encrypt Certificate'),('external','External certificate')), attrs={'class': 'form-control select2'}),
            'cn': TextInput(attrs={'class': 'form-control'})
        }


class X509ExternalCertificateForm(ModelForm):

    cn = CharField(required=False)
    type = ChoiceField(required=True,choices=(('internal','Self-Signed Vulture Certificate'),('letsencrypt','Let\'s Encrypt Certificate'),('external','External certificate')))

    class Meta:
        model = X509Certificate
        fields = ('name', 'type', 'cert', 'key', 'chain', 'crl', 'crl_uri')

        widgets = {
            'name': TextInput(attrs={'class': 'form-control'}),
            'type': RadioSelect(choices=(('internal','Self-Signed Vulture Certificate'),('letsencrypt','Let\'s Encrypt Certificate'),('external','External certificate')), attrs={'class': 'form-control select2'}),
            'cn': TextInput(attrs={'class': 'form-control'}),
            'cert': Textarea(attrs={'class': 'form-control'}),
            'key': Textarea(attrs={'class': 'form-control'}),
            'chain': Textarea(attrs={'class': 'form-control'}),
            'crl_uri': TextInput(attrs={'class': 'form-control'}),
            'crl': Textarea(attrs={'class': 'form-control'})
        }

    def clean_cert(self):
        """ Ensure cert is a valid PEM certificate
        """
        cert = self.cleaned_data.get('cert')

        if cert:
            try:
                x509.load_pem_x509_certificate(cert.encode())
            except Exception as e:
                logger.error(e)
                self.add_error('cert', "Invalid PEM X509 certificate")
        else:
            self.add_error('cert', "This field is required.")

        return cert


class TLSProfileForm(ModelForm):

    # This field has to be defined here, the .filter is not applied otherwise
    ca_cert = ModelChoiceField(
        queryset=X509Certificate.objects.filter(is_ca=True),
        required=False,
        widget=Select(attrs={'class': 'form-control select2'})
    )

    class Meta:
        model = TLSProfile
        fields = ('alpn', 'ca_cert', 'cipher_suite', 'compatibility', 'name', 'protocols', 'verify_client',
                  'x509_certificate')

        widgets = {
            'name': TextInput(attrs={'class': 'form-control'}),
            'x509_certificate': Select(choices=X509Certificate.objects.all(), attrs={'class': 'form-control select2'}),
            'compatibility': Select(choices=BROWSER_CHOICES, attrs={'class': 'form-control select2'}),
            'protocols': SelectMultiple(choices=PROTOCOL_CHOICES, attrs={'class': 'form-control select2'}),
            'cipher_suite': Textarea(attrs={'class': 'form-control'}),
            'alpn': SelectMultiple(choices=ALPN_CHOICES, attrs={'class': 'form-control select2'}),
            'verify_client': Select(choices=VERIFY_CHOICES, attrs={'class': 'form-control select2'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        for field_name in ['x509_certificate', 'compatibility', 'protocols', 'alpn', 'verify_client', 'ca_cert']:
            self.fields[field_name].empty_label = None

    def clean_protocols(self):
        """ Convert string value to list and validate the selected choices """
        field_value = self.cleaned_data.get('protocols')
        if not field_value:
            raise ValidationError("This field is required.")
        value = literal_eval(field_value)
        for v in value:
            if v not in [x[0] for x in PROTOCOL_CHOICES]:
                raise ValidationError("Choice {} not in available choices.".format(v))
        return value

    def clean_alpn(self):
        """ Convert string value to list and validate the selected choices """
        field_value = self.cleaned_data.get('alpn')
        if not field_value:
            raise ValidationError("This field is required.")
        value = literal_eval(field_value)
        for v in value:
            if v not in [x[0] for x in ALPN_CHOICES]:
                raise ValidationError("Choice {} not in available choices.".format(v))
        return value

    def clean_cipher_suite(self):
        """ Verify cipher suite format """
        value = self.cleaned_data['cipher_suite']
        """ Test cipher with ssl library """
        c = SSLContext(PROTOCOL_TLS)
        try:
            c.set_ciphers(value)
        except SSLError:
            self.add_error('cipher_suite', "Invalid cipher suite")
        return value

    def clean(self):
        """ Verify if ca_cert is filled-in if verify_client is not "none" """
        cleaned_data = super().clean()
        if cleaned_data.get('verify_client') != "none" and not cleaned_data.get('ca_cert'):
            # If the error is associated with a particular field, use add_error
            self.add_error('ca_cert', "This field is required if 'Verify client' is not 'No'")
        return cleaned_data
