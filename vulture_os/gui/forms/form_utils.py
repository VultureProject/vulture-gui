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
__doc__ = 'Form utils file'


# Django system imports
from django.conf import settings
from django.forms import CharField
from django.forms.utils import ErrorList

# Django project imports

# Required exceptions imports

# Extern modules imports

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


def bootstrap_tooltips(form, excluded_fields=[]):
    """ Add bootstrap properties used to display help tooltips based on
            help_text field

    :param form: The form object to update
    :param excluded_fields: list of field which doesnt need tooltip
    :return: The updated form
    """
    for field in form.fields:
        help_text = form.fields[field].help_text
        form.fields[field].help_text = None
        if help_text != '' and field not in excluded_fields:
            try:
                class_attr = form.fields[field].widget.attrs["class"]
            except:
                class_attr = 'form-control'

            form.fields[field].widget.attrs.update({
                'class': class_attr,
                'data-toggle': 'tooltip',
                'title': help_text,
                'data-placement': 'right'})
    return form


class DivErrorList(ErrorList):
    """ Dedicated class to print forms errors in red """

    def __str__(self):
        return self.as_ul()

    def as_ul(self):
        if not self:
            return ''
        if self.error_class and "nonfield" in self.error_class:
            return '<div class="custom_nonfield_error">{}</div>'.format(super(DivErrorList, self).as_ul())
        # Need custom_error class in css
        return '<div class="custom_error">{}</div>'.format(super(DivErrorList, self).as_ul())


class NoValidationField(CharField):
    """ Field with no implicit validation of the value """
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

    def clean(self, value):
        return value

    def validate(self, value):
        pass
