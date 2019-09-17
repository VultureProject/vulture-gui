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
__doc__ = 'Documentation Views'

from django.template.loader import render_to_string
from os.path import join as path_join
from django.http import JsonResponse
from django.conf import settings
from bson import ObjectId


def documentation(request):
    path = request.POST.get('path')

    if not path:
        path = "/"

    path = path.replace(".", "")
    path_splitted = path.split('/')

    if ObjectId.is_valid(path_splitted[-1]):
        del path_splitted[-1]

    to_del = []
    for i, path in enumerate(path_splitted):
        try:
            int(path_splitted[i])
            to_del.append(i)
        except ValueError:
            pass

    for i in to_del:
        del path_splitted[i]

    new_path = path_join("/", *settings.DOCUMENTATION_PATH.split('/'),
                         'vulture-doc-master', *path_splitted, "README.md")

    try:
        with open(new_path, 'r') as f:
            readme = f.read()
    except FileNotFoundError:
        return JsonResponse({
            'status': True,
            'html': render_to_string('documentation/doc_not_found.html', {
                'path': path_join(*path_splitted, "README.md")
            })
        })

    return JsonResponse({
        'status': True,
        'html': render_to_string("documentation/doc.html"),
        'readme': readme
    })
