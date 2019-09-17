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
__doc__ = 'VM URLs'


from system.vm import views, api
from django.urls import path, re_path
from system.generic_list import ListVM


urlpatterns = [

    path('system/vm/', ListVM.as_view(), name="system.vm.list"),
    re_path('^system/vm/delete/(?P<object_id>[A-Fa-f0-9]+)$', views.vm_delete, name="system.vm.delete"),
    re_path('^system/vm/start/(?P<object_id>[A-Fa-f0-9]+)$', views.vm_start, name="system.vm.start"),
    re_path('^system/vm/stop/(?P<object_id>[A-Fa-f0-9]+)$', views.vm_stop, name="system.vm.stop"),

    path('api/v1/system/vm/', api.VMAPIv1.as_view(), name="system.vm.api"),
    path('api/v1/system/vm/<int:object_id>', api.VMAPIv1.as_view(), name="system.vm.api"),
    path('api/v1/system/vm/<int:object_id>/<str:action>/', api.VMAPIv1.as_view(), name="system.vm.api"),

]
