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
__doc__ = 'Frontends & Listeners dedicated form classes'

# Django system imports
from django.conf import settings
from django.forms import (CharField, CheckboxInput, ChoiceField, ModelChoiceField, ModelMultipleChoiceField, Form,
                          ModelForm, NumberInput, Select, SelectMultiple, TextInput, Textarea, URLField, PasswordInput)
from django.utils.translation import ugettext_lazy as _

# Django project imports
from applications.logfwd.models import LogOM
from applications.reputation_ctx.models import ReputationContext
from darwin.policy.models import DarwinPolicy
from gui.forms.form_utils import NoValidationField
from services.frontend.models import (COMPRESSION_ALGO_CHOICES, Frontend, FrontendReputationContext, Listener,
                                      LISTENING_MODE_CHOICES, LOG_LEVEL_CHOICES, MODE_CHOICES, IMPCAP_FILTER_CHOICES,
                                      DARWIN_MODE_CHOICES)
from services.rsyslogd.rsyslog import JINJA_PATH as JINJA_RSYSLOG_PATH
from system.cluster.models import NetworkInterfaceCard, NetworkAddress
from system.error_templates.models import ErrorTemplate
from toolkit.api_parser.utils import get_available_api_parser
from system.pki.models import TLSProfile
from system.cluster.models import Node

# Required exceptions imports
from django.core.exceptions import ObjectDoesNotExist
from django.forms import ValidationError

# Extern modules imports
from ast import literal_eval as ast_literal_eval
from ipaddress import ip_address
from json import loads as json_loads
from mimetypes import guess_extension as mime_guess_ext
from os import scandir
from os.path import exists as path_exists
from re import search as re_search, match as re_match

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


class FrontendReputationContextForm(ModelForm):
    """ Form class for intermediary model between Frontend & ReputationContext """
    class Meta:
        model = FrontendReputationContext
        fields = ("enabled", "reputation_ctx", "arg_field")

        widgets = {
            'enabled': CheckboxInput(attrs={'class': "form-control js-switch"}),
            'reputation_ctx': Select(attrs={'class': "form-control select2"}),
            'arg_field': TextInput(attrs={'class': "form-control", 'placeholder': "src_ip"})
        }

    def __init__(self, *args, **kwargs):
        """ Initialisation of fields method """
        # Do not set id of html fields, that causes issues in JS/JQuery
        kwargs['auto_id'] = False
        super().__init__(*args, **kwargs)
        self.fields['reputation_ctx'].empty_label = None

    def as_table_headers(self):
        """ Format field names as table head """
        result = "<tr>\n"
        for field in self:
            result += "<th>{}</th>\n".format(field.label)
        result += "<th>Delete</th></tr>\n"
        return result

    def as_table_td(self):
        """ Format fields as a table with <td></td> """
        result = "<tr>"
        for field in self:
            result += "<td>{}</td>\n".format(field)
        result += "<td style='text-align:center'><a class='btnDelete'><i style='color:grey' " \
                  "class='fas fa-trash-alt'></i></a></td></tr>\n"
        return result


class FrontendForm(ModelForm):
    listeners = NoValidationField()
    headers = NoValidationField()
    reputation_ctx = NoValidationField()
    keep_source_fields = NoValidationField()

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        AVAILABLE_API_PARSER = [("", "--------")]
        AVAILABLE_API_PARSER.extend([(parser, parser.upper().replace('_', ' '))
                                     for parser in get_available_api_parser()])

        """ Darwin policy """
        self.fields['darwin_policy'] = ModelChoiceField(
            label=_("Darwin policy"),
            queryset=DarwinPolicy.objects.all(),
            widget=Select(attrs={'class': 'form-control select2'}),
            required=False
        )
        """ Log forwarders """
        self.fields['log_forwarders'] = ModelMultipleChoiceField(
            label=_("Log forwarders"),
            queryset=LogOM.objects.all().only(*LogOM.str_attrs()),
            widget=SelectMultiple(attrs={'class': 'form-control select2'}),
            required=False
        )
        """ Log forwarders """
        self.fields['log_forwarders_parse_failure'] = ModelMultipleChoiceField(
            label=_("Log forwarders - parse failure"),
            queryset=LogOM.objects.all().only(*LogOM.str_attrs()),
            widget=SelectMultiple(attrs={'class': 'form-control select2'}),
            required=False
        )
        """ MMDP Reputation database IPv4 """
        # Defined here AND in model, to use queryset
        self.fields['logging_reputation_database_v4'] = ModelChoiceField(
            label=_("Rsyslog IPv4 reputation database"),
            # queryset=[(f.get('id'), str(f)) for f in Feed.objects.mongo_find({"filename": {"$regex": r"\.mmdb$"},  # MMDB database
            #                                   "label": {"$regex": r"^((?![iI][Pp][Vv]6).)*$"}},  # Excude IPv6
            #                                  {"filename": 1, "label": 1})],  # .only( label, filename )
            # queryset=Feed.objects.filter(filename__iregex="^((?![iI][Pp][Vv]6).)*\.mmdb$"),
            # queryset=Feed.objects.exclude(filename__iregex="^((?![iI][Pp][Vv]6).)*$").filter(filename__endswith=".mmdb"),
            queryset=ReputationContext.objects.filter(db_type="ipv4", filename__endswith=".mmdb")
                                      .only(*(ReputationContext.str_attrs() + ['filename', 'db_type'])),
            widget=Select(attrs={'class': 'form-control select2'}),
            empty_label="No IPv4",
            required=False
        )
        """ MMDP Reputation database IPv6 """
        # Defined here AND in model, to use queryset
        self.fields['logging_reputation_database_v6'] = ModelChoiceField(
            label=_("Rsyslog IPv6 reputation database"),
            queryset=ReputationContext.objects.filter(db_type="ipv6",
                                                      filename__endswith=".mmdb")  # MMDP database & IPv6
            .only(*(ReputationContext.str_attrs() + ['filename', 'db_type'])),
            widget=Select(attrs={'class': 'form-control select2'}),
            empty_label="No IPv6",
            required=False
        )
        self.fields['logging_geoip_database'] = ModelChoiceField(
            label=_("Rsyslog GeoIP database"),
            queryset=ReputationContext.objects.filter(db_type="GeoIP")
                                      .only(*(ReputationContext.str_attrs() + ['filename', 'db_type'])),
            widget=Select(attrs={'class': 'form-control select2'}),
            empty_label="No GeoIP",
            required=False
        )

        self.fields['node'] = ModelChoiceField(
            label=_('Node'),
            queryset=Node.objects.all(),
            widget=Select(attrs={'class': 'form-control select2'})
        )

        self.fields['forcepoint_host'] = URLField(
            label=_('Forcepoint URL'),
            widget=TextInput(attrs={'class': 'form-control'})
        )

        self.fields['api_parser_type'] = ChoiceField(
            label=_('API Parser'),
            choices=AVAILABLE_API_PARSER,
            widget=Select(attrs={'class': 'form-control select2'})
        )

        # Remove the blank input generated by django
        for field_name in ['mode', 'ruleset', 'log_level', 'listening_mode', 'compression_algos', 'log_forwarders',
                           'impcap_intf']:
            self.fields[field_name].empty_label = None
        self.fields['error_template'].empty_label = "No template"
        # Set required in POST data to False
        for field_name in ['log_condition', 'ruleset', 'log_level', 'listening_mode', 'headers', 'custom_haproxy_conf',
                           'cache_total_max_size', 'cache_max_age', 'compression_algos', 'compression_mime_types',
                           'error_template', 'enable_logging_reputation', 'impcap_filter', 'impcap_filter_type',
                           'impcap_intf', 'tags', 'timeout_client', 'timeout_connect', 'timeout_keep_alive',
                           'parser_tag', 'file_path', 'node', 'api_parser_type', 'api_parser_use_proxy',
                           'elasticsearch_host', 'elasticsearch_auth', 'elasticsearch_verify_ssl',
                           'elasticsearch_username', 'elasticsearch_password', 'elasticsearch_index', 'forcepoint_host',
                           'forcepoint_username', 'forcepoint_password', "symantec_username", "symantec_password",
                           "aws_access_key_id", "aws_secret_access_key", "aws_bucket_name", "akamai_host",
                           "akamai_client_secret", "akamai_access_token", "akamai_client_token", 'akamai_config_id',
                           'office365_tenant_id', 'office365_client_id', 'office365_client_secret',
                           'keep_source_fields', 'imperva_base_url', 'imperva_api_key', 'imperva_api_id',
                           'imperva_private_key', 'darwin_mode']:

            self.fields[field_name].required = False

        """ Build choices of "ruleset" field with rsyslog jinja templates names """
        # read the entries
        try:
            with scandir(JINJA_RSYSLOG_PATH) as listOfEntries:
                for entry in listOfEntries:
                    if entry.is_dir():
                        m = re_search("rsyslog_ruleset_([\w-]+)", entry.name)
                        if m:
                            # Do NOT process haproxy - it's an internal log type
                            if m.group(1) in ("haproxy", "haproxy_tcp"):
                                continue

                            self.fields['ruleset'].widget.choices.append((m.group(1), m.group(1)))
        except Exception as e:
            logger.error("Cannot build 'ruleset' choices. Seems that path '{}' is not found: ".format(
                JINJA_RSYSLOG_PATH
            ))
            logger.exception(e)

        # Set initial value of compression_algos field,
        #  convert space separated string into list
        if self.initial.get('compression_algos'):
            self.initial['compression_algos'] = self.initial.get('compression_algos').split(' ')
        self.initial['tags'] = ','.join(self.initial.get('tags', []) or self.fields['tags'].initial)

        if not self.fields['keep_source_fields'].initial:
            self.fields['keep_source_fields'].initial = dict(self.initial.get('keep_source_fields') or {}) or "{}"

    class Meta:
        model = Frontend
        fields = ('enabled', 'tags', 'name', 'mode', 'enable_logging', 'log_level', 'log_condition', 'ruleset',
                  'listening_mode', 'custom_haproxy_conf', 'enable_cache', 'cache_total_max_size', 'cache_max_age',
                  'enable_compression', 'compression_algos', 'compression_mime_types', 'error_template',
                  'log_forwarders', 'enable_logging_reputation', 'logging_reputation_database_v4',
                  'logging_reputation_database_v6', 'logging_geoip_database', 'timeout_client', 'timeout_connect',
                  'timeout_keep_alive', 'impcap_intf', 'impcap_filter', 'impcap_filter_type',
                  'disable_octet_counting_framing', 'https_redirect', 'log_forwarders_parse_failure', 'parser_tag',
                  'file_path', 'node', 'darwin_policy', 'api_parser_type', 'api_parser_use_proxy', 'elasticsearch_host',
                  'elasticsearch_verify_ssl', 'elasticsearch_auth', 'elasticsearch_username', 'elasticsearch_password',
                  'elasticsearch_index', 'forcepoint_host', 'forcepoint_username', 'forcepoint_password',
                  "symantec_username", "symantec_password", "aws_access_key_id", "aws_secret_access_key",
                  "aws_bucket_name", "akamai_host", "akamai_client_secret", "akamai_access_token",
                  "akamai_client_token", 'akamai_config_id', 'office365_tenant_id', 'office365_client_id',
                  'keep_source_fields', 'office365_client_secret', 'imperva_base_url', 'imperva_api_key',
                  'imperva_api_id', 'imperva_private_key', 'darwin_mode')

        widgets = {
            'enabled': CheckboxInput(attrs={'class': "js-switch"}),
            'name': TextInput(attrs={'class': 'form-control'}),
            'tags': TextInput(attrs={'class': 'form-control', 'data-role': "tagsinput"}),
            'mode': Select(choices=MODE_CHOICES, attrs={'class': 'form-control select2'}),
            'enable_logging': CheckboxInput({'class': 'js-switch'}),  # do not set js-switch
            'impcap_filter_type': Select(choices=IMPCAP_FILTER_CHOICES, attrs={'class': "form-control select2"}),
            'impcap_filter': TextInput(attrs={'class': "form-control"}),
            'impcap_intf': Select(choices=NetworkInterfaceCard.objects.all(), attrs={'class': "form-control select2"}),
            'enable_logging_reputation': CheckboxInput(attrs={'class': "js-switch"}),
            'log_level': Select(choices=LOG_LEVEL_CHOICES, attrs={'class': 'form-control select2'}),
            'darwin_mode': Select(choices=DARWIN_MODE_CHOICES, attrs={'class': 'form-control select2'}),
            'log_condition': Textarea(attrs={'class': 'form-control'}),
            'ruleset': Select(attrs={'class': 'form-control select2'}),
            'listening_mode': Select(choices=LISTENING_MODE_CHOICES, attrs={'class': 'form-control select2'}),
            'disable_octet_counting_framing': CheckboxInput(attrs={'class': " js-switch"}),
            'custom_haproxy_conf': Textarea(attrs={'class': 'form-control'}),
            'enable_cache': CheckboxInput(attrs={'class': " js-switch"}),
            'cache_total_max_size': NumberInput(attrs={'class': 'form-control'}),
            'cache_max_age': NumberInput(attrs={'class': 'form-control'}),
            'enable_compression': CheckboxInput(attrs={'class': " js-switch"}),
            'compression_algos': SelectMultiple(choices=COMPRESSION_ALGO_CHOICES,
                                                attrs={'class': "form-control select2"}),
            'compression_mime_types': TextInput(attrs={'class': 'form-control', 'data-role': "tagsinput"}),
            'error_template': Select(choices=ErrorTemplate.objects.all(), attrs={'class': 'form-control select2'}),
            'timeout_client': NumberInput(attrs={'class': 'form-control'}),
            'timeout_connect': NumberInput(attrs={'class': 'form-control'}),
            'timeout_keep_alive': NumberInput(attrs={'class': 'form-control'}),
            'https_redirect': CheckboxInput(attrs={'class': 'js-switch'}),
            'parser_tag': TextInput(attrs={'class': 'form-control'}),
            'file_path': TextInput(attrs={'class': 'form-control'}),
            'api_parser_use_proxy': CheckboxInput(attrs={'class': 'js-switch'}),
            'elasticsearch_host': TextInput(attrs={
                'class': 'form-control',
                'placeholder': "http://192.168.1.1:9200,http://192.168.1.2:9200"
            }),
            'elasticsearch_verify_ssl': CheckboxInput(attrs={'class': 'js-switch'}),
            'elasticsearch_auth': CheckboxInput(attrs={'class': 'js-switch'}),
            'elasticsearch_username': TextInput(attrs={'class': 'form-control'}),
            'elasticsearch_password': PasswordInput(attrs={'class': 'form-control'}),
            'elasticsearch_index': TextInput(attrs={'class': 'form-control'}),
            'forcepoint_username': TextInput(attrs={'class': 'form-control'}),
            'forcepoint_password': PasswordInput(attrs={'class': 'form-control'}),
            'symantec_username': TextInput(attrs={'class': 'form-control'}),
            'symantec_password': PasswordInput(attrs={'class': 'form-control'}),
            'aws_access_key_id': TextInput(attrs={'class': 'form-control'}),
            'aws_secret_access_key': TextInput(attrs={'class': 'form-control'}),
            'aws_bucket_name': Select(attrs={'class': 'form-control select2'}),
            'akamai_host': TextInput(attrs={'class': 'form-control'}),
            'akamai_client_secret': TextInput(attrs={'class': 'form-control'}),
            'akamai_access_token': TextInput(attrs={'class': 'form-control'}),
            'akamai_client_token': TextInput(attrs={'class': 'form-control'}),
            'akamai_config_id': TextInput(attrs={'class': 'form-control'}),
            'office365_tenant_id': TextInput(attrs={'class': 'form-control'}),
            'office365_client_id': TextInput(attrs={'class': 'form-control'}),
            'office365_client_secret': TextInput(attrs={'class': 'form-control'}),
            'imperva_base_url': TextInput(attrs={'class': 'form-control'}),
            'imperva_api_key': TextInput(attrs={'class': 'form-control'}),
            'imperva_api_id': TextInput(attrs={'class': 'form-control'}),
            'imperva_private_key': Textarea(attrs={'class': 'form-control'})
        }

    def clean_name(self):
        """ HAProxy does not support space in frontend/listen name directive, replace them by _ """
        return self.cleaned_data['name'].replace(' ', '_')

    def clean_tags(self):
        tags = self.cleaned_data.get('tags')
        if tags:
            return [i.replace(" ", "") for i in self.cleaned_data['tags'].split(',')]
        return []

    def clean_log_condition(self):
        """ Verify if log_condition contains valids LogOM name into {{}} """
        regex = "{{([^}]+)}}"
        log_condition = self.cleaned_data.get('log_condition', "").replace("\r\n", "\n")
        for line in log_condition.split('\n'):
            if line.count('{') > 2:
                raise ValidationError("There cannot be 2 actions on one line.")
            match = re_search(regex, line)
            if match:
                try:
                    LogOM().select_log_om_by_name(match.group(1))
                except ObjectDoesNotExist:
                    raise ValidationError("Log Forwarder named '{}' not found.".format(match.group(1)))
        return log_condition

    def clean_ruleset(self):
        """ Check if the file associate to the ruleset exists """
        ruleset = self.cleaned_data.get('ruleset')
        if not ruleset:
            return ruleset

        ruleset_filename = "{}rsyslog_ruleset_{}".format(JINJA_RSYSLOG_PATH, ruleset)
        if not path_exists(ruleset_filename):
            raise ValidationError("Invalid ruleset chosen, corresponding configuration directory '{}' does not exists."
                                  .format(ruleset_filename))
        return ruleset

    def clean_compression_algos(self):
        """ Convert SelectMultiple selected choices
        into a TextField with space separator """
        compression_algos = self.cleaned_data.get('compression_algos')
        if not compression_algos:
            return ""
        try:
            """ Transform text formatted list into list"""
            algos_list = ast_literal_eval(compression_algos)
        except Exception:
            raise ValidationError("Invalid field.")
        else:
            """ And return select choices with space separator """
            return ' '.join(algos_list)

    def clean_compression_mime_types(self):
        """ Validate chosen MIME types with MIME library """
        mime_types = self.cleaned_data.get('compression_mime_types')
        if not mime_types:
            return mime_types
        for mime_type in mime_types.split(','):
            if not mime_guess_ext(mime_type):
                raise ValidationError("This MIME type is unknown : {}".format(mime_type))
        return mime_types

    def clean_impcap_filter(self):
        """  """
        # TODO : check
        return self.cleaned_data.get('impcap_filter')

    def clean_keep_source_fields(self):
        try:
            if self.cleaned_data.get('keep_source_fields'):
                field_val = json_loads(self.cleaned_data.get('keep_source_fields'))
            else:
                return {}
        except Exception:
            raise ValidationError("This field seems to be corrupted")
        else:
            invalid_fields = []
            for key, val in field_val.items():
                if not re_match("^[a-zA-Z0-9\-\._\!]+$", key):
                    invalid_fields.append(key)
                if not re_match("^[a-zA-Z0-9\-\._\!]+$", val.get('field_name')):
                    invalid_fields.append(val.get('field_name'))
            if invalid_fields:
                raise ValidationError("Field '{}' is not valid")
            return field_val

    def clean(self):
        """ Verify needed fields - depending on mode chosen """
        cleaned_data = super().clean()
        """ If mode != log or enable_logging => log_level required """
        mode = cleaned_data.get('mode')

        if cleaned_data.get('enable_logging'):
            if not cleaned_data.get('log_condition'):
                raise ValidationError(
                    "Logging is enabled. Please check \"Archive logs on system\" or configure a log forwarder.")
            if mode == "http":
                if not cleaned_data.get('log_level'):
                    """ Log_level is required if mode is not log and logging enabled """
                    # If the error is associated with a particular field, use add_error
                    self.add_error('log_level', "This field is required if logging is enabled.")
        if mode == "log":
            # if cleaned_data.get('listening_mode') == "api":
            #     cleaned_data['ruleset'] = "generic_json"
            if not cleaned_data.get('ruleset'):
                self.add_error('ruleset', "This field is required.")
            if not cleaned_data.get('listening_mode'):
                self.add_error('listening_mode', "This field is required.")
        if mode == "impcap":
            if not cleaned_data.get('impcap_intf'):
                self.add_error('impcap_intf', "This field is required.")
            if not cleaned_data.get('impcap_filter'):
                self.add_error('impcap_filter', "This field is required.")
        if mode == "http":
            if not cleaned_data.get('timeout_keep_alive'):
                self.add_error('timeout_keep_alive', "This field is required.")

        # If HAProxy conf
        if (mode == "log" and "tcp" in cleaned_data.get('listening_mode')) or mode in ("tcp", "http"):
            if not cleaned_data.get('timeout_connect'):
                self.add_error('timeout_connect', "This field is required.")
            if not cleaned_data.get('timeout_client'):
                self.add_error('timeout_client', "This field is required.")

        if mode == "log" and cleaned_data.get('listening_mode') == "file":
            if not cleaned_data.get('node'):
                self.add_error('node', "This field is required.")
            if not cleaned_data.get('tags'):
                self.add_error('tags', "This field is required.")

        """ If cache is enabled, cache_total_max_size and cache_max_age required """
        if cleaned_data.get('enable_cache'):
            if not cleaned_data.get('cache_total_max_size'):
                self.add_error('cache_total_max_size', "This field is required.")
            if not cleaned_data.get('cache_max_age'):
                self.add_error('cache_max_age', "This field is required.")

        """ If cache is enabled, cache_total_max_size and cache_max_age required """
        if cleaned_data.get('enable_compression'):
            if not cleaned_data.get('compression_algos'):
                self.add_error('compression_algos', "This field is required.")
            if not cleaned_data.get('compression_mime_types'):
                self.add_error('compression_mime_types', "This field is required.")

        """ If enable_logging_reputation is enabled, logging_reputation_database v4 or v6 or both required """
        if cleaned_data.get('enable_logging_reputation'):
            if not cleaned_data.get('logging_reputation_database_v4') and \
                    not cleaned_data.get('logging_reputation_database_v6'):
                self.add_error('logging_reputation_database_v4', "One of those fields is required.")
                self.add_error('logging_reputation_database_v6', "One of those fields is required.")

        """ If Darwin policy is enabled, darwon_mode is required """
        if cleaned_data.get('darwin_policy'):
            if not cleaned_data.get("darwin_mode"):
                self.add_error("darwin_mode", "This field is required when a darwin policy is set")

        return cleaned_data


class ListenerForm(ModelForm):
    class Meta:
        model = Listener
        fields = ('network_address', 'port', 'tls_profiles', 'whitelist_ips', 'max_src', 'max_rate',)

        widgets = {
            'network_address': Select(choices=NetworkAddress.objects.all(), attrs={'class': 'form-control select2'}),
            'port': NumberInput(attrs={'class': 'form-control'}),
            'tls_profiles': SelectMultiple(choices=TLSProfile.objects.all(), attrs={'class': 'form-control select2'}),
            'whitelist_ips': TextInput(attrs={'class': 'form-control', 'data-role': "tagsinput"}),
            'max_src': NumberInput(attrs={'class': 'form-control'}),
            'max_rate': NumberInput(attrs={'class': 'form-control'})
        }

    def __init__(self, *args, **kwargs):
        """ Initialisation of fields method """
        # Do not set id of html fields, that causes issues in JS/JQuery
        kwargs['auto_id'] = False
        super().__init__(*args, **kwargs)
        # Remove the blank input generated by django
        self.fields['network_address'].empty_label = None
        self.fields['tls_profiles'].empty_label = "Plain text"
        self.fields['tls_profiles'].required = False

    def clean_whitelist_ips(self):
        """ Verify 'whitelist_ips' field """
        value = self.cleaned_data.get('whitelist_ips')
        any_field = False
        for v in value.split(','):
            if v == 'any':
                any_field = True
            elif any_field:
                raise ValidationError("Can't set field to 'any' if ip addresses are provided.")
            else:
                try:
                    v_splitted = v.split('/')
                    if len(v_splitted) > 2:
                        raise ValidationError("'{}' is not a valid ip address or cidr.".format(v))
                    elif len(v_splitted) == 2:
                        netmask = int(v_splitted[1])  # raise ValueError if failure
                        if netmask > 32 or netmask < 1:
                            raise ValidationError("'{}' is not a valid ip address or cidr.".format(v))
                    assert ip_address(v_splitted[0])
                except (ValueError, AssertionError) as e:
                    logger.exception(e)
                    raise ValidationError("'{}' is not a valid ip address or cidr.".format(v))
        return value

    def as_table_headers(self):
        """ Format field names as table head """
        result = "<tr><th style=\"visibility:hidden;\">{}</th>\n"
        for field in self:
            result += "<th>{}</th>\n".format(field.label)
        result += "<th>Delete</th></tr>\n"
        return result

    def as_table_td(self):
        """ Format fields as a table with <td></td> """
        result = "<tr><td style=\"visibility:hidden;\">{}</td>".format(self.instance.id or "")
        for field in self:
            result += "<td>{}</td>".format(field)
        result += "<td style='text-align:center'><a class='btnDelete'><i style='color:grey' " \
                  "class='fas fa-trash-alt'></i></a></td></tr>\n"
        return result


CONDITION_CHOICES = (
    ('if', 'If'),
    ('if not', 'If not')
)

FIELD_CHOICES = (
    ('$msg', 'Message'),
    ('$rawmsg', 'Raw message'),
    ('$hostname', 'Hostname'),
    ('$fromhost', 'Hostname msg from'),
    ('$fromhost-ip', 'IP msg from'),
    ('$syslogtag', 'Tag'),
    ('$programname', 'Program name'),
    ('$pri', 'PRI msg part'),
    ('$pri-text', 'PRI as text'),
    ('$iut', 'InfoUnitType'),
    ('$syslogfacility', 'Facility - as num'),
    ('$syslogfacility-text', 'Facility - as text'),
    ('$syslogseverity', 'Severity - as num'),
    ('$syslogseverity-text', 'Severity - as text'),
    ('$timegenerated', 'Received time'),
    ('$timestamp', 'Msg timestamp'),
    ('$inputname', 'Input module name')
)

OPERATOR_CHOICES = (
    ('contains', 'Contains'),
    ('startswith', 'Starts with'),
    ('regex', 'Matches regex'),
    ('==', 'Is equal to'),
    ('!=', 'Is different than'),
    ('<', 'Is less than'),
    ('>', 'Is upper than'),
    ('<=', 'Is less or equal to'),
    ('>=', 'Is upper or equal to'),
)


class LogOMTableForm(Form):
    """ Form used to generate table for log_forwarders """
    """ First condition word """
    condition = ChoiceField(
        label=_("Condition"),
        choices=CONDITION_CHOICES,
        widget=Select(attrs={'class': 'form-control select2'})
    )
    """ Comparison field name """
    field_name = ChoiceField(
        label=_("Field"),
        choices=FIELD_CHOICES,
        widget=Select(attrs={'class': 'form-control select2'})
    )
    """ Comparison operator """
    operator = ChoiceField(
        label=_("Operator"),
        choices=OPERATOR_CHOICES,
        widget=Select(attrs={'class': 'form-control select2'})
    )
    """ Comparison value """
    value = CharField(
        label=_("Value"),
        initial='"plop"',
        widget=TextInput(attrs={'class': 'form-control'})
    )
    """ Action - log forwarder """
    action = ModelMultipleChoiceField(
        label=_("Action"),
        queryset=LogOM.objects.all().only(*LogOM.str_attrs()),
        widget=SelectMultiple(attrs={'class': 'form-control select2'})
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.fields['action'].empty_label = None

    def as_table_headers(self):
        """ Format field names as table head """
        result = "<tr>\n"
        for field in self:
            result += "<th>{}</th>\n".format(field.label)
        result += "<th>Delete</th></tr>\n"
        return result

    def as_table_td(self):
        """ Format fields as a table with <td></td> """
        result = "<tr>"
        for field in self:
            result += "<td>{}</td>".format(field)
        result += "<td style='text-align:center'><a class='btnDelete'><i style='color:grey' " \
                  "class='fas fa-trash-alt'></i></a></td></tr>\n"
        return result
