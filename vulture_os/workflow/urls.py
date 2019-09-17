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
from workflow.generic_list import ListWorkflow
from django.urls import path, re_path

# Django project imports
from workflow import views, api


urlpatterns = [
    re_path('^workflow/delete/(?P<object_id>[A-Fa-f0-9]+)$',
            views.workflow_delete,
            name="workflow.delete"),

    re_path('^workflow/edit/$',
            views.workflow_edit,
            name="workflow.edit"),

    re_path('^workflow/edit/(?P<object_id>[A-Fa-f0-9]+)$',
            views.workflow_edit,
            name="workflow.edit"),

    re_path('^workflow/$',
            ListWorkflow.as_view(),
            name="workflow.list"),

    path('api/v1/workflow/', api.WorkflowAPIv1.as_view(), name='workflow.api'),
    path('api/v1/workflow/<int:object_id>/', api.WorkflowAPIv1.as_view(), name='workflow.api')

]
