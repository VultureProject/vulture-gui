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
__author__ = "Jérémie JOURDIN"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Cluster URLS'


from django.urls import path, re_path
from system.cluster import views, api
from system.generic_delete import DeleteNode
from system.generic_list import ListNode

urlpatterns = [
    re_path('^system/cluster/delete/(?P<object_id>[A-Fa-f0-9]+)$',
            DeleteNode.as_view(),
            name="system.cluster.delete"),

    re_path('^system/cluster/edit/(?P<object_id>[A-Fa-f0-9]+)$',
            views.cluster_edit,
            name="system.cluster.edit"),

    re_path('^system/cluster/stepdown/(?P<object_id>[A-Fa-f0-9]+)?$',
            views.cluster_stepdown,
            name="system.cluster.stepdown"),

    re_path('^system/cluster/remove/(?P<object_id>[A-Fa-f0-9]+)$',
            views.cluster_remove,
            name="system.cluster.remove"),

    re_path('^system/cluster/join/(?P<object_id>[A-Fa-f0-9]+)$',
            views.cluster_join,
            name="system.cluster.join"),

    path('api/system/cluster/add/',
         api.cluster_add,
         name="system.cluster.add"),

    path('api/v1/system/cluster/info/',
         api.cluster_info,
         name="system.cluster.info"),

    path('api/v1/system/cluster/key/',
         api.secret_key,
         name="system.cluster.key"),

    path('api/v1/system/cluster/tasks/',
         api.get_message_queues,
         name="system.cluster.tasks"),

    path('api/v1/system/cluster/status/',
         api.get_cluster_status,
         name="system.cluster.status"),

    path('api/v1/system/node/', api.NodeAPIv1.as_view(), name="system.node.api"),

    path('api/v1/system/node/<int:object_id>/', api.NodeAPIv1.as_view(), name="system.node.api"),

    path('api/v1/system/node/<int:object_id>/<str:action>/',
         api.NodeAPIv1.as_view(),
         name="system.node.api"),

    path('system/cluster/', ListNode.as_view(), name="system.cluster.list"),
]
