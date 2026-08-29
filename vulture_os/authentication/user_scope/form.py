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
__doc__ = 'UserScope dedicated form class'

# Django system imports
from django.conf import settings
from django.forms import (ModelForm, TextInput)
from django.utils.translation import gettext_lazy as _

# Django project imports
from authentication.user_scope.models import UserScope
from gui.forms.form_utils import NoValidationField, bootstrap_tooltips

# Extern modules imports

# Required exceptions imports

# Logger configuration imports
import logging

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


class UserScopeForm(ModelForm):
    repo_attributes = NoValidationField(
        label=_("User scope")
    )

    class Meta:
        model = UserScope
        fields = ('name',)
        widgets = {
            'name': TextInput(attrs={'class': 'form-control'})
        }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self = bootstrap_tooltips(self)
