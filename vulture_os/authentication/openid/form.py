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
__doc__ = 'OpenIDRepository dedicated form class'

# Django system imports
from django.conf import settings
from django.core.validators import RegexValidator
from django.forms import CheckboxInput, Form, ModelForm, Select, TextInput, Textarea
from django.forms import URLField, BooleanField
# Django project imports
from authentication.openid.models import OpenIDRepository, PROVIDERS_TYPE, JWT_SIG_ALG_CHOICES
from authentication.user_scope.models import UserScope

# Extern modules imports
from cryptography import x509
from re import match as re_match
import json

# Required exceptions imports
from django.forms import ValidationError

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


class OpenIDRepositoryForm(ModelForm):

    class Meta:
        model = OpenIDRepository
        fields = ('name', 'provider', 'provider_url', 'client_id', 'client_secret', 'scopes', 'use_proxy',
                  'verify_certificate', 'user_scope', 'enable_jwt', 'jwt_signature_type', 'jwt_key',
                  'jwt_validate_audience')
        widgets = {
            'name': TextInput(attrs={'class': 'form-control'}),
            'provider': Select(choices=PROVIDERS_TYPE, attrs={'class': 'form-control select2'}),
            'provider_url': TextInput(attrs={'class': 'form-control'}),
            'client_id': TextInput(attrs={'class': 'form-control'}),
            'client_secret': TextInput(attrs={'class': 'form-control','autocomplete': 'off'}),
            'scopes': TextInput(attrs={'class': 'form-control', 'data-role': "tagsinput"}),
            'use_proxy': CheckboxInput(attrs={"class": " js-switch"}),
            'verify_certificate': CheckboxInput(attrs={"class": " js-switch"}),
            'user_scope': Select(attrs={'class': 'form-control select2'}),
            'enable_jwt': CheckboxInput(attrs={'class': 'form-control js-switch'}),
            'jwt_signature_type': Select(choices=JWT_SIG_ALG_CHOICES, attrs={'class': "form-control select2"}),
            'jwt_key': Textarea(attrs={'class': 'form-control'}),
            'jwt_validate_audience': CheckboxInput(attrs={'class': 'form-control js-switch'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['user_scope'].queryset = UserScope.objects.all()
        self.fields['user_scope'].empty_label = "Retrieve all claims"
        # Remove the blank input generated by django
        for field_name in ['provider', 'jwt_signature_type']:
            self.fields[field_name].empty_label = None
        # Set all fields as non required
        for field in ["user_scope"]:
            self.fields[field].required = False
        if not self.initial.get('name'):
            self.fields['name'].initial = "OpenID Repository"

        self.initial['scopes'] = ','.join(self.initial.get('scopes', []) or self.fields['scopes'].initial)

    def clean_name(self):
        """ Replace all spaces by underscores to prevent bugs later """
        return self.cleaned_data['name'].replace(' ', '_')

    def clean_scopes(self):
        scopes = self.cleaned_data.get('scopes') or []
        if scopes:
            try:
                scopes = json.loads(scopes.replace("'",'"'))
            except json.JSONDecodeError:
                scopes = [i.replace(" ", "") for i in scopes.split(',')]
        return scopes

    def clean(self):
        """ If jwt enabled, options required """
        cleaned_data = super().clean()

        if cleaned_data.get('enable_jwt'):
            if not cleaned_data.get('jwt_key'):
                self.add_error('jwt_key', "This field is required when jwt is enabled.")
            if OpenIDRepository.jwt_validate_with_certificate(cleaned_data.get('jwt_signature_type')):
                try:
                    x509.load_pem_x509_certificate(cleaned_data.get('jwt_key', '').encode())
                except (TypeError, ValueError) as e:
                    logger.error(e)
                    self.add_error('jwt_key', "Invalid PEM X509 certificate")

class OpenIDRepositoryTestForm(Form):
    provider_url = URLField()
    use_proxy = BooleanField(required=False)
    verify_certificate = BooleanField(required=False)
