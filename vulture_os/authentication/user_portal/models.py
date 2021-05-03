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
__doc__ = 'LDAP Repository model'

# Django system imports
from django.conf import settings
from django.utils.translation import ugettext_lazy as _
from django.forms.models import model_to_dict
from djongo import models

# Django project imports
from authentication.portal_template.models import PortalTemplate
from authentication.base_repository import BaseRepository
from authentication.otp.models import OTPRepository
# Do NOT remove those unused imports !!! There are here to trigger internal django fonctionnality
from authentication.ldap.models import LDAPRepository
from authentication.kerberos.models import KerberosRepository
from authentication.openid.models import OpenIDRepository
from authentication.radius.models import RadiusRepository
from services.frontend.models import Frontend
from toolkit.http.utils import build_url
from toolkit.system.hashes import random_sha256
from system.pki.models import PROTOCOL_CHOICES as TLS_PROTOCOL_CHOICES, X509Certificate
from django.forms import (CheckboxInput, ModelForm, ModelChoiceField, ModelMultipleChoiceField, NumberInput, Select,
                          SelectMultiple, TextInput, Textarea)
from services.haproxy.haproxy import HAPROXY_OWNER, HAPROXY_PATH, HAPROXY_PERMS

# Extern modules imports
from bson import ObjectId
from jinja2 import Environment, FileSystemLoader

# Required exceptions imports
from jinja2.exceptions import (TemplateAssertionError, TemplateNotFound, TemplatesNotFound, TemplateRuntimeError,
                               TemplateSyntaxError, UndefinedError)
from services.exceptions import (ServiceJinjaError, ServiceStartError, ServiceTestConfigError, ServiceError)
from system.exceptions import VultureSystemConfigError

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')

JINJA_PATH = "/home/vlt-os/vulture_os/authentication/user_portal/config/"
JINJA_TEMPLATE = "haproxy_portal.conf"


AUTH_TYPE_CHOICES = (
    ('form', 'HTML Form'),
    ('basic', 'Basic Authentication'),
    ('kerberos', 'Kerberos Authentication')
)

SSO_TYPE_CHOICES = (
    ('form', 'HTML Form'),
    ('basic', 'Basic Authentication'),
    ('kerberos', 'Kerberos Authentication')
)
SSO_BASIC_MODE_CHOICES = (
    ('autologon', 'using AutoLogon'),
    ('learning', 'using SSO Learning'),
)
SSO_CONTENT_TYPE_CHOICES = (
    ('urlencoded', 'application/x-www-form-urlencoded'),
    ('multipart', 'multipart/form-data'),
    ('json', 'application/json')
)


#    enable_oauth2 = models.BooleanField(
#         default=False,
#         verbose_name=_("Enable OAuth2"),
#         help_text=_("If checked, OAuth2 authentication is allowed")
#     )
#     enable_stateless_oauth2 = models.BooleanField(
#         default=False,
#         verbose_name=_("Enable stateless OAuth2"),
#         help_text=_("If checked, Vulture will accept OAuth2 HTTP header as a login")
#     )

SOURCE_ATTRS_CHOICES = (
    ('constant', "Constant value"),
    ('claim', "Claim attribute"),
    ('repo', "Repository attribute"),
    ('merge', "Merge attribute as list"),
    ('claim_pref', "Use claim, or repo attr if not present"),
    ('repo_pref', "Use repo attr, or claim if not present")
)

REPO_ATTR_SOURCE_CHOICES = (
    ('claim', "Claim attribute"),
    ('repo', "Repository attribute"),
    ('constant', "Constant"),
)

REPO_ATTR_CRITERION_CHOICES = (
    ('equals', "equals to"),
    ('exists', "exists"),
    ('not exists', "does not exists"),
    ('contains', "contains"),
    ('not contains', "does not contains"),
    ('startswith', "starts with"),
    ('endswith', "ends with"),
)




class RepoAttributes(models.Model):
    # Needed to patch Djongo ArrayField error
    _id = models.ObjectIdField(default=ObjectId)
    condition_var_kind = models.TextField(
        default=REPO_ATTR_SOURCE_CHOICES[0][0],
        choices=REPO_ATTR_SOURCE_CHOICES,
    )
    condition_var_name = models.TextField(
        default="email"
    )
    condition_criterion = models.TextField(
        default=REPO_ATTR_CRITERION_CHOICES[0][0],
        choices=REPO_ATTR_CRITERION_CHOICES,
    )
    condition_match = models.TextField(
        default="test@abcd.fr"
    )
    action_var_name = models.TextField(
        default="admin"
    )
    action_var_kind = models.TextField(
        default=SOURCE_ATTRS_CHOICES[0][0],
        choices=SOURCE_ATTRS_CHOICES,
    )
    action_var = models.TextField(
        default="true"
    )

    def __str__(self):
        return "IF {} {} {} THEN SET {} = {}({})".format(self.condition_var_kind, self.condition_var_name,
                                                        self.condition_criterion, self.condition_match,
                                                        self.action_var_name, self.action_var_kind, self.action_var)

    def get_condition_var(self, claims, repo_attrs):
        if self.condition_var_kind == "repo":
            return repo_attrs.get(self.condition_var_name, "")
        elif self.condition_var_kind == "claim":
            return claims.get(self.condition_var_name, "")
        elif self.condition_var_kind == "constant":
            return self.condition_var_name
        else:
            raise NotImplementedError(f"{self.condition_var_kind} is not implemented yet.")

    def get_action_var_value(self, claims, repo_attrs):
        if self.action_var_kind == "claim":
            return claims.get(self.action_var, "")
        elif self.action_var_kind == "repo":
            return repo_attrs.get(self.action_var, "")
        elif self.action_var_kind == "merge":
            claim = claims.get(self.action_var, [])
            if not isinstance(claim, list):
                claim = [claim]
            repo = repo_attrs.get(self.action_var, [])
            if not isinstance(repo, list):
                repo = [repo]
            return claim+repo
        elif self.action_var_kind == "claim_pref":
            return claims.get(self.action_var) or repo_attrs.get(self.action_var, "")
        elif self.action_var_kind == "repo_pref":
            return repo_attrs.get(self.action_var) or claims.get(self.action_var, "")
        elif self.action_var_kind == "constant":
            return self.action_var
        else:
            raise NotImplementedError(f"{self.action_var_kind} is not implemented yet.")

    def validate_condition(self, value):
        if self.condition_criterion == "equals":
            return value == self.condition_match
        elif self.condition_criterion == "exists":
            return (len(value) != 0) if hasattr(value, "__len__") else bool(value)
        elif self.condition_criterion == "not exists":
            return (len(value) == 0) if hasattr(value, "__len__") else not bool(value)
        elif self.condition_criterion == "contains":
            return (self.condition_match in value) if hasattr(value, "__contains__") else False
        elif self.condition_criterion == "not contains":
            return (self.condition_match not in value) if hasattr(value, "__contains__") else False
        elif self.condition_criterion == "startswith":
            return (value.startswith(self.condition_match)) if hasattr(value, "startswith") else False
        elif self.condition_criterion == "endswith":
            return (value.endswith(self.condition_match)) if hasattr(value, "endswith") else False
        else:
            raise NotImplementedError(f"{self.condition_criterion} is not implemented yet.")

    def get_scope(self, scope, claims, repo_attrs):
        if self.validate_condition(self.get_condition_var(claims, repo_attrs)):
            scope[self.action_var_name] = self.get_action_var_value(claims, repo_attrs)
        return scope

    def __getitem__(self, item):
        """ PATCH FOR DJONGO ERROR (RepoAttributes is not subscriptable) """
        return getattr(self, item)



class RepoAttributesForm(ModelForm):

    class Meta:
        model = RepoAttributes
        fields = ('condition_var_kind', 'condition_var_name', 'condition_criterion', 'condition_match',
                  'action_var_name', 'action_var_kind', 'action_var')
        widgets = {
            'condition_var_kind': Select(choices=REPO_ATTR_SOURCE_CHOICES, attrs={'class': 'form-control select2'}),
            'condition_var_name': TextInput(attrs={'class': 'form-control'}),
            'condition_criterion': Select(choices=REPO_ATTR_CRITERION_CHOICES, attrs={'class': 'form-control select2'}),
            'condition_match': TextInput(attrs={'class': 'form-control'}),
            'action_var_name': TextInput(attrs={'class': 'form-control'}),
            'action_var_kind': Select(choices=SOURCE_ATTRS_CHOICES, attrs={'class': 'form-control select2'}),
            'action_var': TextInput(attrs={'class': 'form-control select2'})
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Remove the blank input generated by django
        for field_name in ['condition_var_kind', 'condition_criterion', 'action_var_kind']:
            self.fields[field_name].empty_label = None
        self.fields['condition_match'].required = False

    def clean(self):
        """ Verify required field depending on other fields """
        cleaned_data = super().clean()

        if cleaned_data.get('condition_criterion') not in ["exists", "not exists"] and not cleaned_data.get('condition_match'):
            self.add_error('condition_match', "This field is required, except for (not)exists criterion.")

        return cleaned_data


class UserAuthentication(models.Model):
    """ Class used to represent a Portal instance used for authentication

    """
    """ Mandatory principal attributes """
    name = models.TextField(
        default="Users authentication",
        unique=True,
        verbose_name=_("Name"),
        help_text=_("Custom object name")
    )
    enable_external = models.BooleanField(
        default=False,
        verbose_name=_("Enable Identity Provider"),
        help_text=_("Listen portal on dedicated host - required for ")
    )
    external_listener = models.ForeignKey(
        to=Frontend,
        null=True,
        verbose_name=_('Listen on'),
        help_text=_("Listener used for external portal"),
        on_delete=models.SET_NULL
    )
    external_fqdn = models.CharField(
        max_length=40,
        default="auth.testing.tr",
        verbose_name=_("FQDN"),
        help_text=_("Listening FQDN for external portal")
    )
    enable_tracking = models.BooleanField(
        default=True,
        verbose_name=_("Track anonymous connections"),
        help_text=_("If disable, Vulture won\'t give a cookie to anonymous users")
    )
    repositories = models.ArrayReferenceField(
        BaseRepository,
        default=[],
        verbose_name=_('Authentication repositories'),
        help_text=_("Repositories to use to authenticate users (tested in order)"),
        on_delete=models.PROTECT,
    )
    auth_type = models.TextField(
        default=AUTH_TYPE_CHOICES[0][0],
        choices=AUTH_TYPE_CHOICES,
        verbose_name=_("Authentication type"),
        help_text=_("Type of authentication to ask from client")
    )
    portal_template = models.ForeignKey(
        PortalTemplate,
        null=True,
        on_delete=models.PROTECT,
        verbose_name=_("Portal template"),
        help_text=_('Select the template to use for user authentication portal')
    )
    lookup_ldap_repo = models.ForeignKey(
        LDAPRepository,
        default=None,
        null=True,
        verbose_name=_('Lookup ldap repository'),
        help_text=_("Used for federation to retrieve user attributes from LDAP repository"),
        on_delete=models.PROTECT,
        related_name="lookup_ldap_repo_set"
    )
    lookup_ldap_attr = models.TextField(
        default="cn",
        verbose_name=_('Lookup ldap attribute'),
        help_text=_("Attribute name in ldap to map user claim")
    )
    lookup_claim_attr = models.TextField(
        default="username",
        verbose_name=_('Lookup claim key name'),
        help_text=_("Claim name used to map user to ldap attribute")
    )
    repo_attributes = models.ArrayField(
        model_container=RepoAttributes,
        model_form_class=RepoAttributesForm,
        verbose_name=_('Create user scope'),
        null=True,
        default=None,
        help_text=_("Repo attributes whitelist, for re-use in SSO and ACLs")
    )
    auth_timeout = models.PositiveIntegerField(
        default=900,
        verbose_name=_("Disconnection timeout"),
        help_text=_("Expiration timeout of portal cookie")
    )
    enable_timeout_restart = models.BooleanField(
        default=True,
        verbose_name=_("Reset timeout after a request"),
        help_text=_("Restart timeout after a request")
    )
    enable_captcha = models.BooleanField(
        default=False,
        verbose_name=_("Enable captcha"),
        help_text=_("Ask a captcha validation")
    )
    otp_repository = models.ForeignKey(
        to=OTPRepository,
        null=True,
        on_delete=models.SET_NULL,
        verbose_name=_("OTP Repository"),
        help_text=_("Double authentication repository to use"),
        related_name="user_authentication_otp_set"
    )
    otp_max_retry = models.PositiveIntegerField(
        default=3,
        verbose_name=_("Retries numbers"),
        help_text=_("Maximum number of OTP retries until deauthentication")
    )
    disconnect_url = models.TextField(
        default="^{{workflow.public_dir}}/logout\?userid=[^&]+",
        verbose_name=_("Disconnect regex"),
        help_text=_("Regex for the application disconnect page (ex: 'logout\?sessid=.*'")
    )
    enable_disconnect_message = models.BooleanField(
        default=False,
        verbose_name=_("Display the disconnect message from template"),
        help_text=_("Display the disconnect template message instead of redirecting user.")
    )
    enable_disconnect_portal = models.BooleanField(
        default=False,
        verbose_name=_("Destroy portal session on disconnect"),
        help_text=_("Also disconnect the user from the portal.")
    )
    enable_registration = models.BooleanField(
        default=False,
        verbose_name=_("Enable users registration by mail"),
        help_text=_("Enable users registration")
    )
    group_registration = models.TextField(
        default="",
        verbose_name=_("Add users in group (ldap)"),
        help_text=_("Group of ldap registered users")
    )
    update_group_registration = models.BooleanField(
        default=False,
        verbose_name=_("Update group members (ldap)"),
        help_text=_("Update group members")
    )
    enable_oauth = models.BooleanField(
        default=False,
        verbose_name=_("Enable OAuth2 provider"),
        help_text=_("Set portal as OAuth2 provider")
    )
    oauth_client_id = models.CharField(
        max_length=64,
        default=random_sha256,
        verbose_name=_("Application ID (client_id)"),
        help_text=_("Client_id used to contact OAuth2 provider urls")
    )
    oauth_client_secret = models.CharField(
        max_length=64,
        default=random_sha256,
        verbose_name=_("Secret (client_secret)"),
        help_text=_("Client_secret used to contact OAuth2 provider urls")
    )
    oauth_redirect_uris = models.JSONField(
        models.CharField(
            null=False
        ),
        default=["https://myapp.com/oauth2/callback"],
        help_text=_("Use one line per allowed URI")
    )
    oauth_timeout = models.PositiveIntegerField(
        default=600,
        verbose_name=_("OAuth2 tokens timeout"),
        help_text=_("Time in seconds after which oauth2 tokens will expire")
    )
    enable_sso_forward = models.BooleanField(
        default=False,
        help_text=_('Forward credentials to backend')
    )
    sso_forward_type = models.TextField(
        choices=SSO_TYPE_CHOICES,
        default="form",
        help_text=_('Select the way to propagate authentication')
    )
    sso_forward_tls_proto = models.TextField(
        choices=TLS_PROTOCOL_CHOICES,
        default=TLS_PROTOCOL_CHOICES[-1],
        help_text=_('Minimal TLS protocol used to connect to SSO url')
    )
    sso_forward_tls_check = models.BooleanField(
        default=True,
        help_text=_('Enable certificate verification (date, subject, CA), disable if self-signed certificate')
    )
    sso_forward_tls_cert = models.ForeignKey(
        to=X509Certificate,
        on_delete=models.PROTECT,
        null=True,
        blank=False,
        help_text=_("Client certificate used to connect to SSO url.")
    )
    sso_forward_direct_post = models.BooleanField(
        default=False,
        help_text=_('Enable direct POST')
    )
    sso_forward_get_method = models.BooleanField(
        default=False,
        help_text=_('Make a GET instead of a POST')
    )
    sso_forward_follow_redirect_before = models.BooleanField(
        default=False,
        help_text=_('Before posting the login form, follow metaredirect')
    )
    sso_forward_follow_redirect = models.BooleanField(
        default=False,
        help_text=_('After posting the login form, follow the redirection')
    )
    sso_forward_return_post = models.BooleanField(
        default=False,
        help_text=_('Return the application\'s response immediately after the SSO Forward Request')
    )
    sso_forward_content_type = models.TextField(
        choices=SSO_CONTENT_TYPE_CHOICES,
        default='urlencoded',
        help_text=_('Content-Type of the SSO Forward request')
    )
    sso_forward_url = models.TextField(
        default='http://your_internal_app/action.do?what=login',
        help_text=_('URL of the login form')
    )
    sso_forward_user_agent = models.TextField(
        default="Vulture/4 (BSD; Vulture OS)",
        verbose_name=_("Override User-Agent (set empty if not)"),
        help_text=_('Override \'User-Agent\' header for SSO forward requests')
    )
    sso_forward_content = models.TextField(
        default="",
        help_text=_('')
    )
    sso_forward_enable_capture = models.BooleanField(
        default=False,
        help_text=_('Capture content in SSO response')
    )
    sso_forward_capture_content = models.TextField(
        default="^REGEX to capture (content.*) in SSO Forward Response$",
        help_text=_('')
    )
    sso_forward_enable_replace = models.BooleanField(
        default=False,
        help_text=_('Enable content rewrite of SSO response')
    )
    sso_forward_replace_pattern = models.TextField(
        default="^To Be Replaced$",
        help_text=_('Replace pattern in SSO response')
    )
    sso_forward_replace_content = models.TextField(
        default="By previously captured '$1'/",
        help_text=_('Replace content in SSO response')
    )
    sso_forward_enable_additionnal = models.BooleanField(
        default=False,
        help_text=_('Make an additionnal request after SSO')
    )
    sso_forward_additional_url = models.TextField(
        default="http://My_Responsive_App.com/Default.aspx",
        help_text=_('URL of additionnal request')
    )

    objects = models.DjongoManager()

    def __str__(self):
        return "{} ({})".format(self.name, [str(r) for r in self.repositories.all()])

    @staticmethod
    def str_attrs():
        """ List of attributes required by __str__ method """
        return ['name', 'repositories']

    def str_auth_type(self):
        auth_type = "UNKNOWN"
        for auth in AUTH_TYPE_CHOICES:
            if auth[0] == self.auth_type:
                auth_type = auth[1]
        return auth_type

    def to_template(self):
        """  returns the attributes of the class """
        data = model_to_dict(self)
        data['openid_repos'] = self.openid_repos
        return data

    def to_template_external(self):
        return {
            'id': self.id,
            'name': self.name,
            'external_fqdn': self.external_fqdn,
            'portal_template': self.portal_template.to_dict()
        }

    def get_repo_attributes(self):
        if not self.repo_attributes:
            return []
        else:
            return [RepoAttributes(**r) for r in self.repo_attributes]

    def to_dict(self):
        data = model_to_dict(self)
        data['id'] = str(self.pk)
        data['repositories'] = [r.to_dict() for r in self.repositories.all()]
        data['portal_template'] = self.portal_template.to_dict()
        data['portal_template_id'] = self.portal_template.pk
        data['repo_attributes'] = []
        for repo_attr in self.repo_attributes:
            repo_attr.pop('_id', None)
            data['repo_attributes'].append(repo_attr)
        if self.external_listener:
            data['external_listener'] = self.external_listener.to_dict()
            data['external_listener_id'] = self.external_listener.pk

        return data

    @property
    def openid_repos(self):
        return [repo.get_daughter() for repo in self.repositories.filter(subtype="openid")]

    def to_html_template(self):
        """ Returns needed attributes for html rendering """
        result = {
            'id': str(self.id),
            'name': self.name,
            'enable_external': self.enable_external,
            'repositories': [str(repo) for repo in self.repositories.all()],
            'enable_captcha': self.enable_captcha,
            'otp_repository': str(self.otp_repository) if self.otp_repository else "",
            'enable_registration': self.enable_registration,
            'auth_type': self.str_auth_type()
        }
        return result

    def get_openid_callback_url(self, req_scheme, workflow_host, workflow_path, repo_id):
        if self.enable_external:
            base_url = build_url("https" if self.external_listener.tls_profiles.count()>0 else "http", self.external_fqdn, self.external_listener.port)
        else:
            base_url = req_scheme + "://" + workflow_host + workflow_path
        base_url += '/' if base_url[-1] != '/' else ''
        return base_url+"oauth2/callback/{}".format(repo_id)

    def write_login_template(self):
        """ Write templates as static, to serve them without rendering """
        return self.portal_template.write_template("html_login", openid_repos=self.openid_repos, portal_id=self.id)

    def render_template(self, tpl_name, **kwargs):
        return self.portal_template.render_template(tpl_name, **{**kwargs, **self.to_template()})

    def get_user_scope(self, claims, repo_attrs):
        user_scope = {}
        for u in self.get_repo_attributes():
            user_scope = u.get_scope(user_scope, claims, repo_attrs)
        return user_scope


    def generate_conf(self):
        """ Render the conf with Jinja template and self.to_template() method
        :return     The generated configuration as string, or raise
        """
        # The following var is only used by error, do not forget to adapt if needed
        template_name = JINJA_PATH + JINJA_TEMPLATE
        try:
            jinja2_env = Environment(loader=FileSystemLoader(JINJA_PATH))
            template = jinja2_env.get_template(JINJA_TEMPLATE)
            return template.render({'conf': self.to_template_external()})
        # In ALL exceptions, associate an error message
        # The exception instantiation MUST be IN except statement, to retrieve traceback in __init__
        except TemplateNotFound:
            exception = ServiceJinjaError("The following file cannot be found : '{}'".format(template_name), "haproxy")
        except TemplatesNotFound:
            exception = ServiceJinjaError("The following files cannot be found : '{}'".format(template_name), "haproxy")
        except (TemplateAssertionError, TemplateRuntimeError):
            exception = ServiceJinjaError("Unknown error in template generation: {}".format(template_name), "haproxy")
        except UndefinedError:
            exception = ServiceJinjaError("A variable is undefined while trying to render the following template: "
                                          "{}".format(template_name), "haproxy")
        except TemplateSyntaxError:
            exception = ServiceJinjaError("Syntax error in the template: '{}'".format(template_name), "haproxy")
        # If there was an exception, raise a more general exception with the message and the traceback
        raise exception

    def get_base_filename(self):
        """ Return the workflow filename, without directory """
        return "portal_{}.cfg".format(self.id)

    def get_filename(self):
        """  """
        return "{}/{}".format(HAPROXY_PATH, self.get_base_filename())

    def save_conf(self):
        """
        :return   A message of what has been done
        """
        if not self.enable_external:
            return "No standalone portal, no need to write conf."

        params = [self.get_filename(), self.generate_conf(), HAPROXY_OWNER, HAPROXY_PERMS]
        for node in self.external_listener.get_nodes():
            try:
                api_res = node.api_request("system.config.models.write_conf", config=params)
                if not api_res.get('status'):
                    raise VultureSystemConfigError(". API request failure ", traceback=api_res.get('message'))
            except Exception:
                raise VultureSystemConfigError("API request failure.")

        return "Workflow configuration written."

    def generate_openid_config(self, issuer):
        return {
            "issuer": issuer,
            "authorization_endpoint": f"{issuer}/oauth2/authorize",
            "token_endpoint": f"{issuer}/oauth2/token",
            "userinfo_endpoint": f"{issuer}/oauth2/userinfo",
            "revocation_endpoint": f"{issuer}/oauth2/revoke",
            "scopes_supported": [
                "openid"
            ],
            "response_types_supported": [
                "code"
            ]
        }
