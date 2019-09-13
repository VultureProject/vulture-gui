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

__author__ = "Théo BERTIN"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Packet inspection rules form class'

# Django system imports
from django.conf import settings
from django.forms import ModelForm, TextInput, Select, Textarea, SelectMultiple, HiddenInput, ModelMultipleChoiceField
from django.utils.translation import ugettext_lazy as _

# Django project imports
from darwin.inspection.models import InspectionPolicy, InspectionRule, PACKET_INSPECTION_TECHNO

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


class InspectionPolicyForm(ModelForm):
    class Meta:
        model = InspectionPolicy
        fields = ("name", "techno", "description", "rules", "compilable", "compile_status")
        widgets = {
            "name": TextInput(attrs={"class": "form-control"}),
            "techno": Select(choices=PACKET_INSPECTION_TECHNO, attrs={"class": "form-control select2"}),
            "description": TextInput(attrs={"class": "form-control"}),
            "compilable": HiddenInput(),
            "rules": SelectMultiple(
                attrs={'class': 'form-control select2'},
                choices=InspectionRule.objects.all()
            ),
            "compile_status": Textarea(attrs={"class": "form-control"})
        }


    def __init__(self, *args, **kwargs):
        super(InspectionPolicyForm, self).__init__(*args, **kwargs)
        self.fields['description'].required = False
        self.fields['compilable'].required = False
        self.fields['compile_status'].required = False

        self.fields['compilable'].disabled = True
        self.fields['compile_status'].disabled = True
    def clean(self):
        """ Verify required field depending on other fields """
        cleaned_data = super().clean()

        if self.cleaned_data.get("name"):
            cleaned_data["name"] = cleaned_data["name"].replace(" ", "_")

        return cleaned_data


class InspectionRuleForm(ModelForm):
    class Meta:
        model = InspectionRule
        fields = ("name", "category", "techno", "source", "content")

        widgets = {
            "name": TextInput(attrs={"class": "form-control"}),
            "techno": Select(choices=PACKET_INSPECTION_TECHNO, attrs={"class": "form-control select2"}),
            "category": TextInput(attrs={"class": "form-control"}),
            "source": HiddenInput(),
            "content": Textarea(attrs={"class": "form-control"})
        }

    def __init__(self, *args, **kwargs):
        super(InspectionRuleForm, self).__init__(*args, **kwargs)
        self.fields['source'].disabled = True

    def clean(self):
        """ Verify required field depending on other fields """
        cleaned_data = super().clean()

        if self.cleaned_data.get("name"):
            cleaned_data["name"] = cleaned_data["name"].replace(" ", "_")

        return cleaned_data
