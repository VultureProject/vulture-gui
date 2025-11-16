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

__author__ = "Olivier de Régis"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = ""
__doc__ = 'User Form for Installation View'

from django.contrib.auth.forms import UserCreationForm, UserChangeForm
from django.utils.translation import gettext as _
from django.contrib.auth.models import Group
from django import forms

from gui.forms.form_utils import NoValidationField
from system.users.models import User


class UserForm(UserCreationForm):
    username = forms.CharField(
        help_text=_("Letter, digits and @/./+/-/_ only"),
        max_length=150,
        widget=forms.TextInput(attrs={
            'class': 'form-control'
        })
    )

    password1 = forms.CharField(
        help_text=_("""Your password must contain at least
            8 characters and can't be entirely numeric."""),
        label=_("Password"),
        required=False,
        widget=forms.PasswordInput(attrs={
            'class': 'form-control'
        }),
        max_length=150,
    )

    password2 = forms.CharField(
        help_text=_("Enter the same password as above, for verification."),
        label=_("Password confirmation"),
        required=False,
        widget=forms.PasswordInput(attrs={
            'class': 'form-control'
        }),
        max_length=150,
    )

    groups = forms.ModelMultipleChoiceField(
        queryset=Group.objects.all(),
        required=False,
        widget=forms.SelectMultiple(attrs={
            'class': 'select2'
        })
    )

    is_superuser = forms.BooleanField(
        required=False,
        label=_("Superuser"),
        widget=forms.CheckboxInput(attrs={
            'class': 'js-switch'
        })
    )

    is_active = forms.BooleanField(
        required=False,
        label=_("Active"),
        widget=forms.CheckboxInput(attrs={
            'class': 'js-switch'
        })
    )

    def clean(self):
        cleaned_data = super().clean()

        pwd = cleaned_data.get('password1')
        pwd_confirm = cleaned_data.get('password2')

        # If password, we got a password reset
        if pwd:
            if pwd != pwd_confirm:
                error = _("Passwords mismatch")
                self._errors['password2'] = error
        else:
            self.cleaned_data['password1'] = None

        return cleaned_data

    class Meta:
        model = User
        fields = ('username', 'password1', 'password2',
                  'groups', 'is_superuser', 'is_active')


class ChangeUserForm(UserChangeForm):
    username = forms.CharField(
        help_text=_("Letter, digits and @/./+/-/_ only"),
        max_length=150,
        widget=forms.TextInput(attrs={
            'class': 'form-control'
        })
    )

    password1 = forms.CharField(
        help_text=_("""Your password must contain at least
            8 characters and can't be entirely numeric."""),
        label=_("Password"),
        required=False,
        widget=forms.PasswordInput(attrs={
            'class': 'form-control'
        }),
        max_length=150,
    )

    password2 = forms.CharField(
        help_text=_("Enter the same password as above, for verification."),
        label=_("Password confirmation"),
        required=False,
        widget=forms.PasswordInput(attrs={
            'class': 'form-control'
        }),
        max_length=150,
    )

    groups = forms.ModelMultipleChoiceField(
        queryset=Group.objects.all(),
        required=False,
        widget=forms.SelectMultiple(attrs={
            'class': 'select2'
        })
    )

    is_superuser = forms.BooleanField(
        required=False,
        label=_("Superuser"),
        widget=forms.CheckboxInput(attrs={
            'class': 'js-switch'
        })
    )

    is_active = forms.BooleanField(
        required=False,
        label=_("Active"),
        widget=forms.CheckboxInput(attrs={
            'class': 'js-switch'
        })
    )

    def clean(self):
        cleaned_data = super().clean()

        pwd = cleaned_data.get('password1')
        pwd_confirm = cleaned_data.get('password2')

        # If password, we got a password reset
        if pwd:
            if pwd != pwd_confirm:
                error = _("Passwords mismatch")
                self._errors['password2'] = error
        else:
            self.cleaned_data['password1'] = None

        return cleaned_data

    class Meta:
        model = User
        fields = ('username', 'password1', 'password2',
                  'groups', 'is_superuser', 'is_active')


class UserLDAPForm(UserCreationForm):
    username = forms.CharField(
        help_text=_("Letter, digits and @/./+/-/_ only"),
        max_length=150,
        widget=forms.TextInput(attrs={
            'class': 'form-control'
        })
    )

    groups = forms.ModelMultipleChoiceField(
        queryset=Group.objects.all(),
        required=False,
        widget=forms.SelectMultiple(attrs={
            'class': 'select2'
        })
    )

    is_superuser = forms.BooleanField(
        required=False,
        label=_("Superuser"),
        widget=forms.CheckboxInput(attrs={
            'class': 'js-switch'
        })
    )

    is_active = forms.BooleanField(
        required=False,
        label=_("Active"),
        widget=forms.CheckboxInput(attrs={
            'class': 'js-switch'
        })
    )

    """ This field must not be displayed """
    is_ldapuser = forms.BooleanField(
        required=False
    )

    password1 = NoValidationField()
    password2 = NoValidationField()

    class Meta:
        model = User
        fields = ['username', 'groups', 'is_superuser', 'is_active']
        exclude = ['password1', 'password2']


class ChangeUserLDAPForm(UserChangeForm):
    username = forms.CharField(
        help_text=_("Letter, digits and @/./+/-/_ only"),
        max_length=150,
        widget=forms.TextInput(attrs={
            'class': 'form-control'
        })
    )

    groups = forms.ModelMultipleChoiceField(
        queryset=Group.objects.all(),
        required=False,
        widget=forms.SelectMultiple(attrs={
            'class': 'select2'
        })
    )

    is_superuser = forms.BooleanField(
        required=False,
        label=_("Superuser"),
        widget=forms.CheckboxInput(attrs={
            'class': 'js-switch'
        })
    )

    is_active = forms.BooleanField(
        required=False,
        label=_("Active"),
        widget=forms.CheckboxInput(attrs={
            'class': 'js-switch'
        })
    )

    """ This field must not be displayed """
    is_ldapuser = forms.BooleanField(
        required=False
    )

    password1 = NoValidationField()
    password2 = NoValidationField()

    class Meta:
        model = User
        fields = ['username', 'groups', 'is_superuser', 'is_active']
        exclude = ['password1', 'password2']
