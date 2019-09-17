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
__doc__ = 'KerberosRepository dedicated form class'

# Django system imports
from django.conf import settings
from django.core.files.uploadedfile import InMemoryUploadedFile
from django.forms import CheckboxInput, ModelForm, NumberInput, PasswordInput, Select, TextInput, FileInput

# Django project imports
from authentication.kerberos.models import KerberosRepository
from toolkit.auth.kerberos_client import test_keytab

# Extern modules imports
from base64 import b64encode, b64decode

# Required exceptions imports
from django.forms import ValidationError

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


class KerberosRepositoryForm(ModelForm):

    class Meta:
        model = KerberosRepository
        fields = ('name', 'realm', 'domain_realm', 'kdc', 'admin_server', 'krb5_service', 'keytab')
        widgets = {
            'name': TextInput(attrs={'class': 'form-control'}),
            'realm': TextInput(attrs={'class': 'form-control'}),
            'domain_realm': TextInput(attrs={'class': 'form-control'}),
            'kdc': TextInput(attrs={'class': 'form-control', 'data-role': "tagsinput"}),
            'admin_server': TextInput(attrs={'class': 'form-control'}),
            'krb5_service': TextInput(attrs={'class': 'form-control'}),
            'keytab': FileInput(attrs={'class': 'form-control'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def clean_keytab(self):
        """ Test keytab """
        keytab = self.cleaned_data.get('keytab')
        if not keytab:
            raise ValidationError("This field is required.")
        try:
            result = test_keytab(b64encode(keytab.read()))
        except Exception as e:
            raise ValidationError('keytab', "Error: {}".format(e))
        if not result.get('status'):
            raise ValidationError("Keytab error : {}".format(result.get('reason')))
        return keytab
