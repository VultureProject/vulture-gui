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

__author__ = "Jérémie"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'ZFS URLs'


from system.zfs import views, api
from django.urls import path, re_path
from system.generic_list import ListZFS


urlpatterns = [

    path('system/zfs/', ListZFS.as_view(), name="system.zfs.list"),
    path('system/zfs/refresh', views.zfs_refresh, name="system.zfs.refresh"),
    re_path('^system/zfs/delete/(?P<object_id>[A-Fa-f0-9]+)$', views.zfs_delete, name="system.zfs.delete"),
    re_path('^system/zfs/snapshot/(?P<object_id>[A-Fa-f0-9]+)$', views.zfs_snapshot, name="system.zfs.snapshot"),
    re_path('^system/zfs/restore/(?P<object_id>[A-Fa-f0-9]+)$', views.zfs_restore, name="system.zfs.restore"),


    path('api/v1/system/zfs/', api.ZFSAPIv1.as_view(), name="system.zfs.api"),
    path('api/v1/system/zfs/<int:object_id>', api.ZFSAPIv1.as_view(), name="system.zfs.api"),
    path('api/v1/system/zfs/<int:object_id>/<str:action>/', api.ZFSAPIv1.as_view(), name="system.zfs.api"),

]
