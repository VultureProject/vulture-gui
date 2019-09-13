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
__doc__ = 'Reputation CTX URLS'

# Django system imports
from django.urls import path, re_path

# Django project imports
from applications.reputation_ctx import views, api
from applications.generic_list import ListReputationContext


urlpatterns = [
    path('apps/reputation_ctx/', ListReputationContext.as_view(), name="applications.reputation_ctx.list"),

    re_path('^apps/reputation_ctx/delete/(?P<object_id>[A-Fa-f0-9]+)$',
            views.reputation_ctx_delete,
            name="applications.reputation_ctx.delete"),

    re_path('^apps/reputation_ctx/edit/(?P<object_id>[A-Fa-f0-9]+)?$',
            views.reputation_ctx_edit,
            name="applications.reputation_ctx.edit"),

    re_path('^apps/reputation_ctx/clone/(?P<object_id>[A-Fa-f0-9]+)$',
            views.reputation_ctx_clone,
            name="applications.reputation_ctx.clone"),

    path('apps/reputation_ctx/download_test/',
         api.reputation_ctx_download_test,
         name="applications.reputation_ctx.test_conf"),

    path('api/v1/apps/reputation_ctx/',
         api.ReputationContextAPIv1.as_view(),
         name="applications.reputation_ctx.api"),

    path('api/v1/apps/reputation_ctx/<int:object_id>/',
         api.ReputationContextAPIv1.as_view(),
         name="applications.reputation_ctx.api"),

    path('api/v1/apps/reputation_ctx/<int:object_id>/<str:action>/',
         api.ReputationContextAPIv1.as_view(),
         name="applications.reputation_ctx.api"),
]
