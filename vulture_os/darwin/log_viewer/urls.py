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
__email__ = "contact@vultureproject.org"
__doc__ = 'Darwin URLS'

# Django system imports
from darwin.log_viewer import views
from django.urls import path

urlpatterns = [
    path('darwin/logviewer/', views.log_viewer, name="darwin.log_viewer"),
    path('darwin/logviewer/logs', views.get_logs, name="darwin.get_logs"),
    path('darwin/logviewer/graph', views.get_graph, name="darwin.get_graph"),
    path('darwin/predator', views.predator_info, name="darwin.predator"),
    path('darwin/predator/submit', views.predator_submit, name="darwin.predator_submit"),

    path('darwin/defender/get/<str:job_id>', views.get_defender_wl, name="darwin.get_defender_wl"),
    path('darwin/defender/request', views.request_defender_wl, name="darwin.request_defender_wl"),
    path('darwin/defender/save', views.submit_defender_wl, name="darwin.submit_defender_wl"),
    path('darwin/defender/get-rulesets', views.get_defender_rulesets, name="darwin.get_defender_rulesets"),
]
