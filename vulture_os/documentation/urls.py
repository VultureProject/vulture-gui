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
__doc__ = 'Documentation URLs'

from documentation import views as doc_view
from django.conf.urls.static import static
from django.conf import settings
from django.urls import path
from os.path import join


urlpatterns = [
	path('documentation', doc_view.documentation, name="documentation")
]

urlpatterns += static("documentation/", document_root=join(settings.BASE_DIR, 'documentation', 'static'))