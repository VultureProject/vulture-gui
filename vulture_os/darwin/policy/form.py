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
__doc__ = 'DarwinPolicy dedicated form class'

# Django system imports
from django.conf import settings
from django.core.exceptions import ValidationError
from django.forms import (CharField, CheckboxInput, ModelChoiceField, ModelForm, NumberInput, Select, SelectMultiple,
                          TextInput, FilePathField, Form, IntegerField, ChoiceField, HiddenInput)

# Django project imports
from applications.reputation_ctx.models import DATABASES_PATH, ReputationContext
from darwin.policy.models import FilterPolicy, DarwinFilter, DarwinPolicy, DARWIN_LOGLEVEL_CHOICES, CONF_PATH

# Extern modules imports
import os.path

# Required exceptions imports

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


class DarwinPolicyForm(ModelForm):
    class Meta:
        model = DarwinPolicy
        fields = ('name', 'description')
        widgets = {
            'name': TextInput(attrs={'class': 'form-control'}),
            'description': TextInput(attrs={'class': 'form-control'}),
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # Set all fields as non required
        for field in self.fields:
            self.fields[field].required = False

    def clean_name(self):
        """ Replace all spaces by underscores to prevent bugs later """
        return self.cleaned_data['name'].replace(' ', '_')


class FilterPolicyForm(ModelForm):
    """ Form used to validate and show filters in policy form """
    """ Name of the filter, not editable """

    filter_description = "No description available"
    common_fields = ['filter_name', 'enabled', 'threshold', 'log_level',  'nb_thread', 'cache_size']
    custom_fields = []

    filter_name = CharField(
        disabled=True
    )

    class Meta:
        model = FilterPolicy
        # The order of the fields in html table is defined here
        fields = ('filter_name', 'enabled', 'nb_thread', 'log_level', 'cache_size', 'threshold',
                  'mmdarwin_enabled', 'mmdarwin_parameters')

        widgets = {
            'enabled': CheckboxInput(attrs={"class": "js-switch"}),
            'nb_thread': NumberInput(attrs={'class': 'form-control'}),
            'threshold': NumberInput(attrs={'class': 'form-control'}),
            'log_level': Select(choices=DARWIN_LOGLEVEL_CHOICES, attrs={'class': 'form-control select2'}),
            'cache_size': NumberInput(attrs={'class': 'form-control'}),
            'mmdarwin_enabled': CheckboxInput(attrs={"class": "js-switch mmdarwin-enabled-btn"}),
            'mmdarwin_parameters': TextInput(attrs={"class": "form-control tags-input mmdarwin-parameters"})
        }

        labels = {
            'mmdarwin_enabled': 'Enable custom Rsyslog calls',
            'mmdarwin_parameters': 'Rsyslog parameters:'
        }

    def __init__(self, *args, **kwargs):
        """ Initialize custom fields """
        super().__init__(*args, **kwargs)
        instance = kwargs.get('instance')

        """ Set the filter name with the instance passed in kwargs """
        filter = instance.filter
        self.initial['filter_name'] = filter.name
        self.filter_description = filter.description

        try:
            initial_mmdarwin_parameters = self.initial['mmdarwin_parameters']
        except KeyError:
            initial_mmdarwin_parameters = instance.mmdarwin_parameters

        if isinstance(initial_mmdarwin_parameters, list):
            self.initial['mmdarwin_parameters'] = ",".join(initial_mmdarwin_parameters)

        self.fields['mmdarwin_parameters'].required = False

        self['mmdarwin_enabled'].field.widget.attrs['id'] = '{filter_name}_mmdarwin_enabled'.format(
            filter_name=filter.name
        )

    def clean_enabled(self):
        if self.instance.filter.is_internal:
            return True

        return self.cleaned_data['enabled']

    def clean_mmdarwin_parameters(self):
        mmdarwin_parameters = self.cleaned_data['mmdarwin_parameters']

        if not mmdarwin_parameters:
            formatted_mmdarwin_parameters = []
        else:
            formatted_mmdarwin_parameters = mmdarwin_parameters.split(",")

        return formatted_mmdarwin_parameters

    def is_modal(self):
        for field in self.custom_fields:
            if not isinstance(self.fields[field].widget, HiddenInput):
                return True

        return False

    def is_custom_fields(self):
        return isinstance(self.custom_fields, list) and len(self.custom_fields) > 0

    def to_config(self):
        return {}

    def clean(self):
        self.fields.config = self.to_config()

        try:
            if not self.cleaned_data['mmdarwin_enabled']:
                self.cleaned_data['mmdarwin_parameters'] = []
        except KeyError:
            pass

        return self.cleaned_data

    def as_table_headers(self):
        """ Format field names as table head """
        result = "<tr>\n"

        for field_str in self.common_fields:
            field = self[field_str]

            if field.field.widget.input_type in ("number", "checkbox"):
                result += "<th style=\"width:2%\">{}</th>\n".format(field.label)
            else:
                result += "<th style=\"width:3%\">{}</th>\n".format(field.label)

            if field.name == "filter_name":
                result += "<th style=\"width:1%\">Hint</th>\n"

        result += "<th style=\"width:10%\">Configure</th>\n"
        result += "</tr>\n"

        return result

    def as_table_td(self):
        """ Format fields as a table with <td></td> """
        result = "<tr>\n"
        for field_str in self.common_fields:
            field = self[field_str]

            if field.name == "filter_name":
                result += "<td class=\"filter-name\">{}</td>\n".format(self.initial['filter_name'].replace('_', ' '))

                result += '<td class=""><a class="btn btn-flat btn-xs btn-primary" ' \
                          'data-toggle="tooltip" data-placement="top" ' \
                          'title="{description}"><span>' \
                          '<i class="fas fa-question"></i></span></a></td>'.format(
                            description=self.filter_description
                          )

            else:
                result += "<td>{}</td>\n".format(field).replace('name="', 'name="{}_'.format(self.initial['filter_name'])).replace('id="id_', 'id="{}_'.format(self.initial['filter_name']))  # Prevent duplicate id for select2

        if self.is_modal():
            result += '<td class=""><a data-toggle="modal" href="#" data-target="#{filter_name}_modal"' \
                      ' class="btn btn-flat btn-xs btn-primary" data-toggle="tooltip" data-placement="top" ' \
                      'title="Configure {filter_name} filter"><span>' \
                      '<i class="fas fa-wrench"></i></span></a></td>'.format(
                            filter_name=self.initial['filter_name']
                        )
        else:
            result += "<td></td>"

        return result + "</tr>\n"

    def as_custom_fields(self):
        """ Format fields as a table with <td></td> """
        result = ""

        for field in self:  # Replace name for POST data treatment in view
            if field.name not in self.custom_fields:
                continue

            if field.name == "mmdarwin_parameters":
                result += "<div id=\"{}_mmdarwin_parameters\">".format(self.initial['filter_name'])

            if not isinstance(field.field.widget, HiddenInput):
                result += "<div class=\"filter-label\">{}</div>\n".format(field.label_tag())

            result += "{}\n".format(field).replace('name="', 'name="{}_'.format(self.initial['filter_name']))\
                .replace('id="id_', 'id="{}_'.format(self.initial['filter_name']))

            if field.name == "mmdarwin_parameters":
                result += "</div>"

        return result


class FilterPolicyReputationForm(FilterPolicyForm):
    custom_fields = ['mmdb_database', 'mmdarwin_enabled', 'mmdarwin_parameters']
    """ Form used to validate and show Reputation filter in policy form """
    """ Conf of the DarwinFilter, only used for reputation database (for the moment) """

    def clean_mmdb_database(self):
        mmdb_database_obj = self.cleaned_data['mmdb_database']

        return "{}/{}".format(DATABASES_PATH, mmdb_database_obj.filename)

    def clean(self):
        cleaned_data = super().clean()

        try:
            mmdb_database = cleaned_data['mmdb_database']
        except KeyError:
            mmdb_database = self.instance.config.get('mmdb_database', None)

        # Cannot add this check, because os.path.exists is false
        # (currently, /var/db/darwin is not mounted on the Apache jail)
        # if cleaned_data.get("enabled", False) and (not mmdb_database or not os.path.exists(mmdb_database)):
        #     raise ValidationError("Cannot enable this filter, as there is no configuration path given")

        return cleaned_data

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields['mmdb_database'] = ModelChoiceField(
            label="Reputation file:",
            queryset=ReputationContext.objects.filter(filename__endswith=".mmdb",
                                                        db_type__in=["ipv4", "ipv6"])
                                        .order_by('filename')
                                        .only(*(ReputationContext.str_attrs() + ['filename'])),
            required=False,
            widget=Select(attrs={'class': 'form-control select2'}),
            empty_label=None
        )

        try:
            mmdb_database = self.initial['mmdb_database']
        except KeyError:
            mmdb_database = self.instance.config.get('mmdb_database', None)

        if mmdb_database is not None:
            try:
                self.initial['mmdb_database'] = ReputationContext.objects.get(filename__endswith=mmdb_database.split('/')[-1]).id
            except ReputationContext.DoesNotExist:
                del self.initial['mmdb_database']

        # <= 1, because there is the "empty" choice to consider
        if not self['mmdb_database'].field.choices or len(self['mmdb_database'].field.choices) <= 1:
            self.fields['enabled'].disabled = True

    def to_config(self):
        to_return = {}

        try:
            to_return["mmdb_database"] = self.cleaned_data["mmdb_database"]
        except KeyError:
            pass

        return to_return


class FilterPolicyHostlookupForm(FilterPolicyForm):
    custom_fields = ['database', 'mmdarwin_enabled', 'mmdarwin_parameters']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields['database'] = FilePathField(
            path="{}f{}/".format(CONF_PATH, "hostlookup"),
            required=False,
            widget=Select(attrs={'class': 'form-control select2'}),
            match=".*\.db$"
        )

        try:
            if not os.path.exists(self.initial['database']):
                del self.initial['database']

            if self.initial.get('database', None) is None:
                self.initial['enabled'] = False

        except KeyError:
            pass

        # <= 1, because there is the "empty" choice to consider
        if not self['database'].field.choices or len(self['database'].field.choices) <= 1:
            self.fields['enabled'].disabled = True

    def clean(self):
        cleaned_data = super().clean()

        try:
            database = cleaned_data['database']
        except KeyError:
            database = self.instance.config.get('database', None)

        is_enabled = cleaned_data['enabled']

        if is_enabled and (not database or not os.path.exists(database)):
            raise ValidationError('Database file "{}" does not exist, so this filter cannot be enabled'.format(
                database
            ))

    def to_config(self):
        to_return = {}

        try:
            to_return["database"] = self.cleaned_data["database"]
        except KeyError:
            pass

        return to_return


class FilterPolicyConnectionForm(FilterPolicyForm):
    custom_fields = ['redis_socket_path', 'init_data_file', 'redis_expire']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # not shown in GUI
        self.fields['redis_socket_path'] = CharField(
            required=False,
            initial="/var/sockets/redis/redis.sock",
            widget=HiddenInput()
        )

        self.fields['init_data_file'] = CharField(
            required=False,
            initial="/home/darwin/conf/fconnection/init_data_file",
            widget=HiddenInput()
        )

        self.fields['redis_expire'] = IntegerField(
            required=False,
            initial=300,
            widget=NumberInput(attrs={"class": "form-control"})
        )

    def to_config(self):
        to_return = {}

        try:
            to_return["redis_socket_path"] = self.cleaned_data["redis_socket_path"]
        except KeyError:
            pass

        try:
            to_return["init_data_file"] = self.cleaned_data["init_data_file"]
        except KeyError:
            pass

        try:
            to_return["redis_expire"] = self.cleaned_data["redis_expire"]
        except KeyError:
            pass

        return to_return


class FilterPolicyContentInspectionForm(FilterPolicyForm):
    custom_fields = ['maxConnections', 'yaraScanType', 'yaraScanMaxSize', 'maxMemoryUsage', 'yaraRuleFile',
                     'mmdarwin_enabled', 'mmdarwin_parameters']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields['maxConnections'] = IntegerField(
            label='Max connections:',
            required=False,
            initial=64000,
            min_value=1,
            widget=NumberInput(attrs={"class": "form-control"})
        )

        self.fields['yaraScanType'] = ChoiceField(
            label='Yara scan type:',
            required=False,
            initial="packet",
            choices=[
                ("packet", "Packet"),
                ("stream", "Stream")
            ],
            widget=Select(attrs={"class": "form-control"})
        )

        self.fields['yaraScanMaxSize'] = IntegerField(
            label='Yara scan max size:',
            required=False,
            initial=16384,
            min_value=1,
            widget=NumberInput(attrs={"class": "form-control"})
        )

        self.fields['maxMemoryUsage'] = IntegerField(
            label='Max memory usage:',
            required=False,
            initial=200,
            min_value=1,
            widget=NumberInput(attrs={"class": "form-control"})
        )

        self.fields['yaraRuleFile'] = FilePathField(
            label='Yara rule file:',
            path="{}f{}/".format(CONF_PATH, "content_inspection"),
            required=True,
            widget=Select(attrs={'class': 'form-control select2'}),
            match=".*\.yar$"
        )

        self.fields["mmdarwin_enabled"].disabled = True
        if not self.fields["yaraRuleFile"].widget.choices:
            self.fields["yaraRuleFile"].disabled = True

    # stream_store_folder can be used to debug the filter. But for the moment, the field is useless
    # stream_store_folder = CharField()  # not shown in GUI

    def to_config(self):
        to_return = {}

        try:
            to_return["maxConnections"] = self.cleaned_data["maxConnections"]
        except KeyError:
            pass

        try:
            to_return["yaraScanType"] = self.cleaned_data["yaraScanType"]
        except KeyError:
            pass

        try:
            to_return["yaraRuleFile"] = self.cleaned_data["yaraRuleFile"]
        except KeyError:
            pass

        try:
            to_return["yaraScanMaxSize"] = self.cleaned_data["yaraScanMaxSize"]
        except KeyError:
            pass

        try:
            to_return["maxMemoryUsage"] = self.cleaned_data["maxMemoryUsage"]
        except KeyError:
            pass

        return to_return


class FilterPolicyUserAgentForm(FilterPolicyForm):
    custom_fields = ['token_map_path', 'model_path', 'max_tokens', 'mmdarwin_enabled', 'mmdarwin_parameters']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # not shown in GUI
        self.fields['token_map_path'] = CharField(
            required=False,
            initial="/home/darwin/conf/fuser_agent/fuser_agent.pb",
            widget=HiddenInput()
        )

        # not shown in GUI
        self.fields['max_tokens'] = IntegerField(
            required=False,
            initial=75,
            min_value=1,
            widget=HiddenInput()
        )

        self.fields['model_path'] = FilePathField(
            label="Model:",
            path="{}f{}/".format(CONF_PATH, "user_agent"),
            required=False,
            widget=Select(attrs={'class': 'form-control select2'}),
            match=".*\.pb$"
        )

        try:
            if not os.path.exists(self.initial['model_path']):
                del self.initial['model_path']

            if self.initial.get('model_path', None) is None:
                self.initial['enabled'] = False

        except KeyError:
            pass

        # <= 1, because there is the "empty" choice to consider
        if not self['model_path'].field.choices or len(self['model_path'].field.choices) <= 1:
            self.fields['enabled'].disabled = True

    def clean(self):
        cleaned_data = super().clean()

        try:
            model_path = cleaned_data['model_path']
        except KeyError:
            model_path = self.instance.config.get('model_path', None)

        is_enabled = cleaned_data['enabled']

        if is_enabled and (not model_path or not os.path.exists(model_path)):
            raise ValidationError('Model path "{}" does not exist, so this filter cannot be enabled'.format(model_path))

    def to_config(self):
        to_return = {}

        try:
            to_return["token_map_path"] = self.cleaned_data["token_map_path"]
        except KeyError:
            pass

        try:
            to_return["model_path"] = self.cleaned_data["model_path"]
        except KeyError:
            pass

        try:
            to_return["max_tokens"] = self.cleaned_data["max_tokens"]
        except KeyError:
            pass

        return to_return


class FilterPolicyDGAForm(FilterPolicyForm):
    custom_fields = ['token_map_path', 'model_path', 'max_tokens', 'mmdarwin_enabled', 'mmdarwin_parameters']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # not shown in GUI
        self.fields['token_map_path'] = CharField(
            required=False,
            initial="/home/darwin/conf/fdga/fdga_tokens.csv",
            widget=HiddenInput()
        )

        # not shown in GUI
        self.fields['max_tokens'] = IntegerField(
            required=False,
            initial=75,
            min_value=1,
            widget=HiddenInput()
        )

        self.fields['model_path'] = FilePathField(
            label="Model:",
            path="{}f{}/".format(CONF_PATH, "dga"),
            required=False,
            widget=Select(attrs={'class': 'form-control select2'}),
            match=".*\.pb$"
        )

        try:
            if not os.path.exists(self.initial['model_path']):
                del self.initial['model_path']

            if self.initial.get('model_path', None) is None:
                self.initial['enabled'] = False

        except KeyError:
            pass

        # <= 1, because there is the "empty" choice to consider
        if not self['model_path'].field.choices or len(self['model_path'].field.choices) <= 1:
            self.fields['enabled'].disabled = True

    def clean(self):
        cleaned_data = super().clean()

        try:
            model_path = cleaned_data['model_path']
        except KeyError:
            model_path = self.instance.config.get('model_path', None)

        is_enabled = cleaned_data['enabled']

        if is_enabled and (not model_path or not os.path.exists(model_path)):
            raise ValidationError('Model path "{}" does not exist, so this filter cannot be enabled'.format(model_path))

    def to_config(self):
        to_return = {}

        try:
            to_return["token_map_path"] = self.cleaned_data["token_map_path"]
        except KeyError:
            pass

        try:
            to_return["model_path"] = self.cleaned_data["model_path"]
        except KeyError:
            pass

        try:
            to_return["max_tokens"] = self.cleaned_data["max_tokens"]
        except KeyError:
            pass

        return to_return


class FilterPolicyTAnomalyForm(FilterPolicyForm):
    custom_fields = ['redis_socket_path', 'redis_list_name', 'log_file_path', 'mmdarwin_enabled', 'mmdarwin_parameters']

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        # not shown in GUI
        self.fields['redis_socket_path'] = CharField(
            required=False,
            initial="/var/sockets/redis/redis.sock",
            widget=HiddenInput()
        )

        # not shown in GUI
        self.fields['redis_list_name'] = CharField(
            required=False,
            initial="anomalyFilterData",
            widget=HiddenInput()
        )

        # not shown in GUI
        self.fields['log_file_path'] = CharField(
            required=False,
            initial="/var/log/darwin/anomaly.log",
            widget=HiddenInput()
        )

    def to_config(self):
        to_return = {}

        try:
            to_return["redis_socket_path"] = self.cleaned_data["redis_socket_path"]
        except KeyError:
            pass

        try:
            to_return["redis_list_name"] = self.cleaned_data["redis_list_name"]
        except KeyError:
            pass

        try:
            to_return["log_file_path"] = self.cleaned_data["log_file_path"]
        except KeyError:
            pass

        return to_return
