#!/home/vlt-os/env/bin/python
"""This file is part of Vulture 3.

Vulture 3 is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

Vulture 3 is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with Vulture 3.  If not, see http://www.gnu.org/licenses/.
"""

__author__ = "Olivier de Régis"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = ""
__doc__ = 'GUI URLs'

from django.urls import path, re_path

from gui.views.main import process_queue_state, rss, collapse
from gui.views.api_wrapper import ApiWrapperGet
from gui.views.auth import authent, log_out
from gui.views import api as api_view
from gui.views import dashboard

urlpatterns = [
    path('login/', authent, name="gui.login"),
    path('logout/', log_out, name="gui.logout"),

    path('collapse', collapse, name="gui.collapse_menu"),

    re_path(r'^$', dashboard.dashboard_services, name="gui.dashboard.services"),

    path('rss/', rss, name='gui.rss'),
    path('process_queue/', process_queue_state, name='gui.process_queue'),

    # This is the entry point for Continous Integration
    #    This API is a wrapper arround all views in the project: yet very powerful, but very dangerous also
    #    Access to port 8000 should be restricted has much as possible.
    #    You have been warned
    re_path('^api/ci/get/(?P<objclass>[A-Za-z0-9\._]+)/(?P<object_id>[A-Fa-f0-9]+)?$',
            ApiWrapperGet.as_view(), name='gui.views.api_wrapper_get'),

    re_path('^api/v1/services/monitor/$', api_view.services_monitor, name="api.services_monitor"),

]
