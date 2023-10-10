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
__doc__ = 'Classes used to delete objects'

# Django system imports
from django.db.models import Q
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseBadRequest, JsonResponse
from django.shortcuts import render
from django.utils.decorators import method_decorator
from django.views.generic import View

# Django project imports
from workflow.models import Workflow

# Extern modules imports
from json import loads as json_loads

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


class ListView(View):
    """ Generic list view """
    template_name = ""
    obj = None

    @method_decorator(login_required)
    def dispatch(self, *args, **kwargs):
        return super().dispatch(*args, **kwargs)

    def get(self, request, **kwargs):
        if not request.headers.get('x-requested-with') == 'XMLHttpRequest':
            return render(request, self.template_name)
        return HttpResponseBadRequest()

    def post(self, request, **kwargs):
        if not request.headers.get('x-requested-with') == 'XMLHttpRequest':
            return HttpResponseBadRequest()

        order = {
            "asc": "",
            "desc": "-"
        }

        start = int(request.POST['iDisplayStart'])
        length = int(request.POST['iDisplayLength']) + start

        search = request.POST['sSearch']
        columns = json_loads(request.POST['columns'])
        col_sort = columns[int(request.POST["iSortingCols"])]

        col_order = "{}{}".format(order[request.POST['sSortDir_0']], col_sort)

        s = Q()
        if search:
            s = Q(name__icontains=search)

        objs = []
        max_objs = self.obj.objects.filter(s).count()

        for obj in self.obj.objects.filter(s).order_by(col_order)[start:length]:
            objs.append(obj.to_template())

        return JsonResponse({
            "status": True,
            "iTotalRecords": max_objs,
            "iTotalDisplayRecords": max_objs,
            "aaData": objs
        })


class ListWorkflow(ListView):
    """ Class dedicated to list all Backend objects """
    template_name = "main/workflow.html"
    obj = Workflow

    def get(self, request, **kwargs):
        if not request.headers.get('x-requested-with') == 'XMLHttpRequest':
            return render(request, self.template_name)
        return HttpResponseBadRequest()

    def post(self, request, **kwargs):
        if not request.headers.get('x-requested-with') == 'XMLHttpRequest':
            return HttpResponseBadRequest()

        order = {
            "asc": "",
            "desc": "-"
        }

        start = int(request.POST['iDisplayStart'])
        length = int(request.POST['iDisplayLength']) + start

        search = request.POST['sSearch']
        columns = json_loads(request.POST['columns'])
        col_sort = columns[int(request.POST["iSortingCols"])]

        col_order = "{}{}".format(order[request.POST['sSortDir_0']], col_sort)

        s = Q()
        if search:
            s = Q(name__icontains=search) | Q(fqdn__icontains=search)

        objs = []
        max_objs = self.obj.objects.filter(s).count()

        for obj in self.obj.objects.filter(s).order_by(col_order)[start:length]:
            # use to_html_template instead of to_html
            objs.append(obj.to_html_template())

        return JsonResponse({
            "status": True,
            "iTotalRecords": max_objs,
            "iTotalDisplayRecords": max_objs,
            "aaData": objs
        })
