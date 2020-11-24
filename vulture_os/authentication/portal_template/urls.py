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
__doc__ = 'Listeners URLS'

# Django system imports
from django.urls import path, re_path

# Django project imports
from authentication.portal_template import views, api
from authentication.generic_list import ListPortalTemplate
from authentication.generic_delete import DeletePortalTemplate


urlpatterns = [
    path('portal/template/', ListPortalTemplate.as_view(), name="portal.template.list"),
    re_path('portal/template/edit/(?P<object_id>[A-Fa-f0-9]+)?', views.template_edit, name="portal.template.edit"),
    path('api/v1/portal/template/clone/', api.portal_template_clone, name="portal.template.clone"),
    path('api/v1/portal/template/', api.PortalTemplateAPIv1.as_view(), name="api.portal.template"),
    re_path('^api/v1/portal/template/(?P<object_id>[A-Fa-f0-9]+)?$', api.PortalTemplateAPIv1.as_view(), name="api.portal.template"),
    re_path('^portal/template/delete/(?P<object_id>[A-Fa-f0-9]+)?$', DeletePortalTemplate.as_view(), name="portal.template.delete"),
]
