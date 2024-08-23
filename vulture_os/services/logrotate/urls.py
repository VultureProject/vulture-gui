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
__doc__ = 'LogRotate dedicated urls entries'

# Django system imports
from django.urls import re_path

# Django project imports
from services.logrotate import views

# Required exceptions imports

# Extern modules imports

# Logger configuration imports


urlpatterns = [
    # There is only one HAProxy global settings, no deletable, neither duplicable
    re_path('^services/logrotate/edit/(?P<object_id>[A-Fa-f0-9]{24})?$', views.logrotate_edit,
            name="services.logrotate.edit"),
]
