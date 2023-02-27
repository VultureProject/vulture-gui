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

from django.contrib.auth.forms import UserCreationForm
from django.utils.translation import gettext as _
from django import forms

from system.users.models import User


class UserForm(UserCreationForm):
    username = forms.CharField(
        help_text=_("Letter, digits and @/./+/-/_ only"),
        max_length=150,
        required=False,
        widget=forms.TextInput(attrs={
            'class': 'form-control'
        })
    )

    password1 = forms.CharField(
        help_text=_("""Your password must contain at least
            8 characters and can't be entirely numeric."""),
        widget=forms.PasswordInput(attrs={
            'class': 'form-control'
        }),
        max_length=150,
        required=False,
    )

    password2 = forms.CharField(
        help_text=_("Enter the same password as above, for verification."),
        widget=forms.PasswordInput(attrs={
            'class': 'form-control'
        }),
        max_length=150,
        required=False,
    )

    class Meta:
        model = User
        fields = ('username', 'password1', 'password2')
