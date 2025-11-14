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
from django.utils.translation import gettext_lazy as _
from django.forms.models import model_to_dict
from django.db import models

# Django project imports
from django.forms import (ModelForm, Select,
                          TextInput)


# Required exceptions imports

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')



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
    ('always', "Always"),
)

REPO_ATTR_CRITERION_CHOICES = (
    ('equals', "equals to"),
    ('not equals', "does not equal to"),
    ('exists', "exists"),
    ('not exists', "does not exist"),
    ('contains', "contains"),
    ('not contains', "does not contain"),
    ('startswith', "starts with"),
    ('endswith', "ends with"),
)

REPO_ATTR_ASSIGNATOR_CHOICES = (
    ('=', "set"),
    ('+=', "append"),
)


class RepoAttribute(models.Model):
    # Needed to patch Djongo ArrayField error
    _id = models.IntegerField(default=0)
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
    assignator = models.TextField(
        default=REPO_ATTR_ASSIGNATOR_CHOICES[0][0],
        choices=REPO_ATTR_ASSIGNATOR_CHOICES
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
        return "IF {} {} {} {} THEN SET {} {} {}({})".format(self.condition_var_kind, self.condition_var_name,
                                                        self.condition_criterion, self.condition_match,
                                                        self.action_var_name, self.assignator,
                                                        self.action_var_kind, self.action_var)

    def get_condition_var(self, claims, repo_attrs):
        if self.condition_var_kind == "repo":
            return repo_attrs.get(self.condition_var_name, None)
        elif self.condition_var_kind == "claim":
            return claims.get(self.condition_var_name, None)
        elif self.condition_var_kind == "constant":
            return self.condition_var_name
        elif self.condition_var_kind == "always":
            return "1"
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
        if self.condition_var_kind == "always":
            return True
        if self.condition_criterion == "equals":
            return value == self.condition_match
        if self.condition_criterion == "not equals":
            return value != self.condition_match
        elif self.condition_criterion == "exists":
            return value is not None
        elif self.condition_criterion == "not exists":
            return value is None
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

    def convert_to_list(self, value):
        if not isinstance(value, list):
            if value is None:
                return []
            else:
                return [value]
        else:
            return value

    def assign(self, scope, value):
        if self.assignator == "=":
            scope[self.action_var_name] = value
        elif self.assignator == "+=":
            scope[self.action_var_name] = self.convert_to_list(scope.get(self.action_var_name)) + self.convert_to_list(value)
        return scope

    def get_scope(self, scope, claims, repo_attrs):
        if self.validate_condition(self.get_condition_var(claims, repo_attrs)):
            scope = self.assign(scope, self.get_action_var_value(claims, repo_attrs))
        return scope

    def __getitem__(self, item):
        """ PATCH FOR DJONGO ERROR (RepoAttribute is not subscriptable) """
        return getattr(self, item)



class RepoAttributeForm(ModelForm):

    class Meta:
        model = RepoAttribute
        fields = ('condition_var_kind', 'condition_var_name', 'condition_criterion', 'condition_match',
                  'assignator', 'action_var_name', 'action_var_kind', 'action_var')
        widgets = {
            'condition_var_kind': Select(choices=REPO_ATTR_SOURCE_CHOICES, attrs={'class': 'form-control condition-var-kind select2'}),
            'condition_var_name': TextInput(attrs={'class': 'form-control'}),
            'condition_criterion': Select(choices=REPO_ATTR_CRITERION_CHOICES, attrs={'class': 'form-control select2'}),
            'condition_match': TextInput(attrs={'class': 'form-control'}),
            'action_var_name': TextInput(attrs={'class': 'form-control'}),
            'assignator': Select(choices=REPO_ATTR_ASSIGNATOR_CHOICES, attrs={'class': 'form-control select2'}),
            'action_var_kind': Select(choices=SOURCE_ATTRS_CHOICES, attrs={'class': 'form-control select2'}),
            'action_var': TextInput(attrs={'class': 'form-control select2'})
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # Remove the blank input generated by django
        for field_name in ['condition_var_kind', 'condition_criterion', 'action_var_kind', 'assignator']:
            self.fields[field_name].empty_label = None
        self.fields['condition_match'].required = False

    def clean(self):
        """ Verify required field depending on other fields """
        cleaned_data = super().clean()

        if cleaned_data.get('condition_criterion') not in ["exists", "not exists"] and not cleaned_data.get('condition_match'):
            self.add_error('condition_match', "This field is required, except for (not)exists criterion.")

        return cleaned_data


class UserScope(models.Model):
    """ Class used to represent a Portal instance used for authentication

    """
    """ Mandatory principal attributes """
    name = models.TextField(
        default="User scope",
        unique=True,
        verbose_name=_("Name"),
        help_text=_("Custom object name")
    )
    repo_attributes = models.JSONField(
        # model_container=RepoAttribute,
        # model_form_class=RepoAttributeForm,
        verbose_name=_('Create user scope'),
        null=True,
        default=[],
        help_text=_("Repo attributes whitelist, for re-use in SSO and ACLs")
    )

    # objects = models.DjongoManager()

    def __str__(self):
        return "{} ({})".format(str(self.name), [r['action_var_name'] for r in self.repo_attributes])

    @staticmethod
    def str_attrs():
        """ List of attributes required by __str__ method """
        return ["name", "repo_attributes"]

    def to_template(self):
        """  returns the attributes of the class """
        data = model_to_dict(self)
        return data

    def get_repo_attributes(self):
        if not self.repo_attributes:
            return []
        else:
            return [RepoAttribute(**r) for r in self.repo_attributes]

    def to_dict(self, fields=None):
        data = model_to_dict(self, fields=fields)
        if not fields or "id" in fields:
            data['id'] = str(self.pk)
        if not fields or "repo_attributes" in fields:
            data['repo_attributes'] = []
            for repo_attr in self.repo_attributes:
                repo_attr.pop('_id', None)
                data['repo_attributes'].append(repo_attr)
        return data

    def to_html_template(self):
        """ Returns needed attributes for html rendering """
        result = {
            'id': str(self.id),
            'name': self.name,
            'scope_keys': [r['action_var_name'] for r in self.repo_attributes]
        }
        return result

    def get_user_scope(self, claims, repo_attrs):
        user_scope = {}
        for u in self.get_repo_attributes():
            user_scope = u.get_scope(user_scope, claims, repo_attrs)
        return user_scope
