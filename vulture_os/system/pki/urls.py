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
__doc__ = 'PKI URLS'


from django.urls import path, re_path
from system.pki import views, api
from system.generic_delete import DeleteTLSProfile
from system.generic_list import ListTLSProfile, ListX509Certificate

urlpatterns = [
    re_path('^system/pki/delete/(?P<object_id>[A-Fa-f0-9]+)$',
            views.pki_delete,
            name="system.pki.delete"),

    re_path('^system/pki/getcert/(?P<object_id>[A-Fa-f0-9]+)?$',
            views.pki_getcert,
            name="system.pki.getcert"),

    re_path('^system/pki/getbundle/(?P<object_id>[A-Fa-f0-9]+)?$',
            views.pki_getbundle,
            name="system.pki.getbundle"),

    re_path('^system/pki/getcrl/(?P<object_id>[A-Fa-f0-9]+)?$',
            views.pki_getcrl,
            name="system.pki.getcrl"),

    re_path('^system/pki/gencrl/(?P<object_id>[A-Fa-f0-9]+)?$',
            views.pki_gencrl,
            name="system.pki.gencrl"),

    re_path('^system/pki/revoke/(?P<object_id>[A-Fa-f0-9]+)?$',
            views.pki_revoke,
            name="system.pki.revoke"),

    re_path('^system/pki/edit/(?P<object_id>[A-Fa-f0-9]+)?$',
            views.pki_edit,
            name="system.pki.edit"),

    path('system/pki/', ListX509Certificate.as_view(), name="system.pki.list"),

    path('api/system/pki/get_ca', api.pki_get_ca, name="system.pki_get_ca"),

    path('api/system/pki/get_cert/', api.pki_issue_cert, name="system.pki.pki_issue_cert"),


    re_path('^system/tls_profile/edit/(?P<object_id>[A-Fa-f0-9]+)?$',
            views.tls_profile_edit,
            name="system.tls_profile.edit"),

    re_path('^system/tls_profile/clone/(?P<object_id>[A-Fa-f0-9]+)$',  # object_id is required
            views.tls_profile_clone,
            name="system.tls_profile.clone"),

    re_path('^system/tls_profile/delete/(?P<object_id>[A-Fa-f0-9]+)$',  # object_id is required
            DeleteTLSProfile.as_view(),
            name="system.tls_profile.delete"),

    path('system/tls_profile/', ListTLSProfile.as_view(), name="system.tls_profile.list"),
]
