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
__doc__ = 'UserAuthentication and UserSSO dedicated form class'

# Django system imports
from django.conf import settings
from django.core.validators import URLValidator
from django.forms import (CheckboxInput, ModelForm, ModelChoiceField, ModelMultipleChoiceField, NumberInput, Select,
                          SelectMultiple, TextInput, Textarea)
from django.utils.translation import ugettext_lazy as _

# Django project imports
from authentication.portal_template.models import PortalTemplate
from authentication.base_repository import BaseRepository
from authentication.ldap.models import LDAPRepository
from authentication.otp.models import OTPRepository
from authentication.openid.models import OpenIDRepository
from authentication.user_portal.models import (AUTH_TYPE_CHOICES, SSO_TYPE_CHOICES, SSO_BASIC_MODE_CHOICES,
                                               SSO_CONTENT_TYPE_CHOICES, UserAuthentication)
from authentication.user_scope.models import UserScope
from gui.forms.form_utils import NoValidationField
from system.pki.models import PROTOCOL_CHOICES as TLS_PROTOCOL_CHOICES, X509Certificate
from services.frontend.models import Frontend

# Extern modules imports

# Required exceptions imports

# Logger configuration imports
import logging

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


class UserAuthenticationForm(ModelForm):
    repositories = ModelMultipleChoiceField(
        label=_("Authentication repositories"),
        queryset=BaseRepository.objects.exclude(subtype="OTP").only(*BaseRepository.str_attrs()),
        widget=SelectMultiple(attrs={'class': 'form-control select2'}),
    )
    # Field used only by GUI, not saved
    not_openid_repositories = ModelMultipleChoiceField(
        label=_("Authentication repositories"),
        queryset=BaseRepository.objects.exclude(subtype__in=["OTP", "openid"]).only(*BaseRepository.str_attrs()),
        widget=SelectMultiple(attrs={'class': 'form-control select2'}),
        required=False
    )
    lookup_ldap_repo = ModelChoiceField(
        label=_("Lookup ldap repository"),
        queryset=LDAPRepository.objects.all().only(*LDAPRepository.str_attrs()),
        widget=Select(attrs={'class': 'form-control select2'}),
        required=False,
        empty_label=_("No lookup")
    )
    sso_forward_tls_cert = ModelChoiceField(
        label=_("Client certificate (optional)"),
        queryset=X509Certificate.objects.exclude(is_ca=True).only(*X509Certificate.str_attrs()),
        widget=Select(attrs={'class': 'form-control select2'}),
        required=False
    )
    # OAuth2 MUST uses httpS !
    external_listener = ModelChoiceField(
        label=_("Listen IDP on"),
        queryset=Frontend.objects.filter(enabled=True, mode="http", listener__tls_profiles__name__isnull=False).only(*Frontend.str_attrs()).distinct(),
        widget=Select(attrs={'class': 'form-control select2'}),
        required=False,
        empty_label=None
    )

    class Meta:
        model = UserAuthentication
        fields = ('name', 'enable_tracking', 'auth_type', 'portal_template', 'repositories', 'not_openid_repositories',
                  'lookup_ldap_repo', 'lookup_ldap_attr', 'lookup_claim_attr', 'user_scope',
                  'auth_timeout', 'enable_timeout_restart', 'enable_captcha', 'otp_repository', 'otp_max_retry',
                  'disconnect_url', 'enable_disconnect_message', 'enable_disconnect_portal', 'enable_registration',
                  'group_registration', 'update_group_registration', 'enable_external', 'external_fqdn',
                  'external_listener', 'enable_oauth', 'oauth_client_id', 'oauth_client_secret',
                  'oauth_redirect_uris', 'oauth_timeout',
                  'enable_sso_forward','sso_forward_type','sso_forward_direct_post','sso_forward_get_method',
                  'sso_forward_follow_redirect_before','sso_forward_follow_redirect','sso_forward_return_post',
                  'sso_forward_content_type','sso_forward_url','sso_forward_user_agent','sso_forward_content',
                  'sso_forward_enable_capture','sso_forward_capture_content','sso_forward_enable_replace',
                  'sso_forward_replace_pattern','sso_forward_replace_content','sso_forward_enable_additionnal',
                  'sso_forward_additional_url', 'sso_forward_tls_proto', 'sso_forward_tls_cert', 'sso_forward_tls_check')
        widgets = {
            'name': TextInput(attrs={'class': 'form-control'}),
            'enable_tracking': CheckboxInput(attrs={'class': 'form-control js-switch'}),
            'enable_external': CheckboxInput(attrs={'class': 'form-control js-switch'}),
            'external_fqdn': TextInput(attrs={'class': 'form-control'}),
            'auth_type': Select(choices=AUTH_TYPE_CHOICES, attrs={'class': 'form-control select2'}),
            'user_scope': Select(attrs={'class': 'form-control select2'}),
            'lookup_ldap_attr': TextInput(attrs={'class': 'form-control'}),
            'lookup_claim_attr': TextInput(attrs={'class': 'form-control'}),
            'portal_template': Select(choices=PortalTemplate.objects.all().only(*PortalTemplate.str_attrs()),
                                      attrs={'class': 'form-control select2'}),
            'auth_timeout': NumberInput(attrs={'class': 'form-control'}),
            'enable_timeout_restart': CheckboxInput(attrs={'class': 'form-control js-switch'}),
            'enable_captcha': CheckboxInput(attrs={'class': 'form-control js-switch'}),
            'otp_repository': Select(choices=OTPRepository.objects.all().only(*OTPRepository.str_attrs()),
                                     attrs={'class': 'form-control select2'}),
            'otp_max_retry': NumberInput(attrs={'class': 'form-control'}),
            'disconnect_url': TextInput(attrs={'class': 'form-control'}),
            'enable_disconnect_message': CheckboxInput(attrs={'class': 'form-control js-switch'}),
            'enable_disconnect_portal': CheckboxInput(attrs={'class': 'form-control js-switch'}),
            'enable_registration': CheckboxInput(attrs={'class': 'form-control js-switch'}),
            'group_registration': TextInput(attrs={'class': 'form-control'}),
            'update_group_registration': CheckboxInput(attrs={'class': 'form-control js-switch'}),
            'enable_oauth': CheckboxInput(attrs={'class': 'form-control'}),
            'oauth_client_id': TextInput(attrs={'readonly': ''}),
            'oauth_client_secret': TextInput(attrs={'readonly': ''}),
            'oauth_redirect_uris': Textarea(attrs={'class': 'form-control'}),
            'oauth_timeout': NumberInput(attrs={'class': 'form-control'}),
            'enable_sso_forward': CheckboxInput(attrs={'class': "form-control js-switch"}),
            'sso_forward_direct_post': CheckboxInput(attrs={'class': "form-control js-switch"}),
            'sso_forward_get_method': CheckboxInput(attrs={'class': "form-control js-switch"}),
            'sso_forward_follow_redirect_before': CheckboxInput(attrs={'class': "form-control js-switch"}),
            'sso_forward_follow_redirect': CheckboxInput(attrs={'class': "form-control js-switch"}),
            'sso_forward_return_post': CheckboxInput(attrs={'class': "form-control js-switch"}),
            'sso_forward_enable_capture': CheckboxInput(attrs={'class': "form-control js-switch"}),
            'sso_forward_enable_replace': CheckboxInput(attrs={'class': "form-control js-switch"}),
            'sso_forward_enable_additionnal': CheckboxInput(attrs={'class': "form-control js-switch"}),
            'sso_forward_type': Select(choices=SSO_TYPE_CHOICES, attrs={'class': "form-control select2"}),
            'sso_forward_content_type': Select(choices=SSO_CONTENT_TYPE_CHOICES, attrs={'class': "form-control select2"}),
            'sso_forward_tls_proto': Select(choices=TLS_PROTOCOL_CHOICES, attrs={'class': "form-control select2"}),
            'sso_forward_tls_check': CheckboxInput(attrs={'class': "form-control js-switch"}),
            'sso_forward_url': TextInput(attrs={'class': "form-control"}),
            'sso_forward_user_agent': TextInput(attrs={'class': "form-control"}),
            'sso_forward_content': Textarea(attrs={'class': "form-control", 'readonly':''}),
            'sso_forward_capture_content': Textarea(attrs={'class': "form-control"}),
            'sso_forward_replace_pattern': Textarea(attrs={'class': "form-control"}),
            'sso_forward_replace_content': Textarea(attrs={'class': "form-control"}),
            'sso_forward_additional_url': TextInput(attrs={'class': "form-control"}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Remove the blank input generated by django
        for field_name in ['portal_template', 'repositories', 'auth_type', 'sso_forward_type']:
            self.fields[field_name].empty_label = None
        self.fields['user_scope'].empty_label = "Retrieve all claims"
        self.fields['user_scope'].queryset = UserScope.objects.all()
        self.fields['otp_repository'].empty_label = "No double authentication"
        # Set fields as non required in POST data
        for field in ['portal_template', 'otp_repository', 'otp_max_retry', 'group_registration', "user_scope",
                      'update_group_registration', "sso_forward_direct_post", "sso_forward_get_method",
                      "sso_forward_follow_redirect_before", "sso_forward_follow_redirect", "sso_forward_return_post",
                      "sso_forward_enable_capture", "sso_forward_enable_replace", "sso_forward_enable_additionnal",
                      "sso_forward_type", "sso_forward_content_type", "sso_forward_tls_proto", "sso_forward_url",
                      "sso_forward_user_agent", "sso_forward_content", "sso_forward_capture_content",
                      "sso_forward_replace_pattern", "sso_forward_replace_content", "sso_forward_additional_url"]:
            self.fields[field].required = False
        # Format oauth_redirect_uris
        self.initial['oauth_redirect_uris'] = '\n'.join(self.initial.get('oauth_redirect_uris', []) or self.fields['oauth_redirect_uris'].initial)
        self.initial['not_openid_repositories'] = self.initial.get('repositories')

    def clean_name(self):
        """ Replace all spaces by underscores to prevent bugs later """
        return self.cleaned_data['name'].replace(' ', '_')

    def clean_oauth_redirect_uris(self):
        """ Split values with \n """
        res = []
        for url in self.cleaned_data.get('oauth_redirect_uris', "").split("\n"):
            url = url.rstrip()
            validate = URLValidator(schemes=("http", "https"))
            validate(url)
            res.append(url)
        return res

    def clean(self):
        """ Verify required field depending on other fields """

        cleaned_data = super().clean()

        """ If external enabled, external options required """
        if cleaned_data.get('enable_external'):
            if not cleaned_data.get('external_fqdn'):
                self.add_error('external_fqdn', "This field is required if external is enabled.")
            if not cleaned_data.get('external_listener'):
                self.add_error('external_listener', "This field is required if external is enabled.")

        """ Portal template is required if auth_type = HTTP """
        if cleaned_data.get('auth_type') == "http" and not cleaned_data.get('portal_template'):
            self.add_error('portal_template', "This field is required with HTTP auth type.")

        """ otp_max_retry required if otp_repository """
        if cleaned_data.get('otp_repository') and not cleaned_data.get('otp_max_retry'):
            self.add_error('otp_max_retry', "This field is required if an OTP repository has been chosen.")
        """ disconnect_url required if enable_disconnect_message or enable_disconnect_portal """
        if cleaned_data.get('enable_disconnect_message') or cleaned_data.get('enable_disconnect_portal'):
            if not cleaned_data.get('disconnect_url'):
                self.add_error('disconnect_url', "This field is required if 'Disconnect message' or 'Destroy portal "
                                                 "session' has been enabled.")

        """ group_registration required if enable_registration """
        repo = LDAPRepository.objects.filter(pk=cleaned_data.get('repository')).first()
        # If enable registration with LDAP Repo : group_registration required
        if cleaned_data.get('enable_registration') and repo and not cleaned_data.get('group_registration'):
            self.add_error('group_registration', "This field is required if registration enabled.")
        if cleaned_data.get('enable_registration') and (cleaned_data.get('group_registration') or
                                                            cleaned_data.get('update_group_registration')) \
                and not repo:
            self.add_error('group_registration', "To use this field, the mail repository must be LDAP.")
            self.add_error('update_group_registration', "To use this field, the mail repository must be LDAP.")

        if cleaned_data.get('lookup_ldap_repo'):
            if not cleaned_data.get('lookup_ldap_attr'):
                self.add_error('lookup_ldap_attr', "This field is required with 'LDAP Lookup repository'")
            if not cleaned_data.get('lookup_claim_attr'):
                self.add_error('lookup_claim_attr', "This field is required with 'LDAP Lookup repository'")

        return cleaned_data
