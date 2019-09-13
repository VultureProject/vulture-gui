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
__doc__ = 'Classes used to view objects'

# Django system imports
from django.db.models import Q
from django.conf import settings
from django.contrib.auth.decorators import login_required
from django.http import HttpResponseBadRequest, JsonResponse
from django.shortcuts import render
from django.utils.decorators import method_decorator
from django.views.generic import View

# Django project imports
from darwin.defender_policy.models import DefenderPolicy
from darwin.inspection.models import InspectionPolicy, InspectionRule
from authentication.generic_list import ListLDAPRepository
from darwin.policy.models import DarwinFilter, DarwinPolicy
from services.frontend.models import BlacklistWhitelist
from darwin.access_control.models import AccessControl
from darwin.defender_policy.models import DefenderPolicy
from darwin.log_viewer.models import DefenderRuleset
from services.frontend.models import BlacklistWhitelist

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
        if not request.is_ajax():
            return render(request, self.template_name)
        return HttpResponseBadRequest()

    def post(self, request, **kwargs):
        if not request.is_ajax():
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


class ListDarwinPolicy(ListView):
    """ Class dedicated to list all Frontend objects """
    template_name = "policy.html"
    obj = DarwinPolicy

    def get(self, request, **kwargs):
        if not request.is_ajax():
            return render(request, self.template_name)
        return HttpResponseBadRequest()

    def post(self, request, **kwargs):
        if not request.is_ajax():
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
            # use to_html_template instead of to_html
            objs.append(obj.to_html_template())

        return JsonResponse({
            "status": True,
            "iTotalRecords": max_objs,
            "iTotalDisplayRecords": max_objs,
            "aaData": objs
        })


class ListBlacklistWhitelists(ListView):
    template_name = "waf_rules.html"
    obj = BlacklistWhitelist

    def get(self, request, **kwargs):
        if not request.is_ajax():
            return render(request, self.template_name)
        return HttpResponseBadRequest()

    def post(self, request, **kwargs):
        if not request.is_ajax():
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
            s = Q(rule__icontains=search)

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


class ListInspectionPolicy(ListView):
    template_name = "inspection.html"
    obj = InspectionPolicy

    def get(self, request, **kwargs):
        if not request.is_ajax():
            return render(request, self.template_name)
        return HttpResponseBadRequest()

    def post(self, request, **kwargs):
        if not request.is_ajax():
            return HttpResponseBadRequest()

        order = {
            "asc": "",
            "desc": "-"
        }

        start = int(request.POST.get('iDisplayStart', "0"))
        stop = int(request.POST.get('iDisplayLength', "10")) + start

        search = request.POST.get('sSearch', "")
        columns = json_loads(request.POST.get('columns', '["id", "name"]'))
        col_sort = columns[int(request.POST.get("iSortingCols", "1"))]

        col_order = "{}{}".format(order[request.POST.get('sSortDir_0', "asc")], col_sort)

        s = Q()
        if search:
            s = Q(name__icontains=search)

        objs = []
        max_objs = self.obj.objects.filter(s).count()

        for obj in self.obj.objects.filter(s).only("last_update",
                                                   "name",
                                                   "compilable",
                                                   "techno",
                                                   "description").order_by(col_order)[start:stop]:
            # use to_html_template instead of to_html
            objs.append(obj.to_html_template())

        return JsonResponse({
            "status": True,
            "iTotalRecords": max_objs,
            "iTotalDisplayRecords": max_objs,
            "aaData": objs
        })

class ListInspectionRule(ListView):
    template_name = "inspection.html"
    obj = InspectionRule

    def get(self, request, **kwargs):
        if not request.is_ajax():
            return render(request, self.template_name)
        return HttpResponseBadRequest()

    def post(self, request, **kwargs):
        if not request.is_ajax():
            return HttpResponseBadRequest()

        order = {
            "asc": "",
            "desc": "-"
        }

        start = int(request.POST.get('iDisplayStart', "0"))
        stop = int(request.POST.get('iDisplayLength', "10")) + start

        logger.info("rule query start {} and end {}".format(start, stop))

        search = request.POST['sSearch']
        columns = json_loads(request.POST.get('columns', '["name"]'))
        col_sort = columns[int(request.POST.get("iSortingCols", "0"))]

        col_order = "{}{}".format(order[request.POST.get('sSortDir_0', "asc")], col_sort)

        s = Q()
        if search:
            s = Q(name__icontains=search)

        objs = []
        max_objs = self.obj.objects.filter(s).count()

        for obj in self.obj.objects.filter(s).order_by(col_order)[start:stop]:
            # use to_html_template instead of to_html
            objs.append(obj.to_html_template())

        return JsonResponse({
            "status": True,
            "iTotalRecords": max_objs,
            "iTotalDisplayRecords": max_objs,
            "aaData": objs
        })


class ListDefenderPolicy(ListView):
    """ Class dedicated to list all Frontend objects """
    template_name = "defender_policy.html"
    obj = DefenderPolicy

    def get(self, request, **kwargs):
        if not request.is_ajax():
            return render(request, self.template_name)
        return HttpResponseBadRequest()

    def post(self, request, **kwargs):
        if not request.is_ajax():
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
            # use to_html_template instead of to_html
            objs.append(obj.to_html_template())

        return JsonResponse({
            "status": True,
            "iTotalRecords": max_objs,
            "iTotalDisplayRecords": max_objs,
            "aaData": objs
        })


class ListDefenderRuleset(ListView):
    """ Class dedicated to list all Frontend objects """
    template_name = "defender_ruleset.html"
    obj = DefenderRuleset

    def get(self, request, **kwargs):
        if not request.is_ajax():
            return render(request, self.template_name)
        return HttpResponseBadRequest()

    def post(self, request, **kwargs):
        if not request.is_ajax():
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
            # use to_html_template instead of to_html
            objs.append(obj.to_html_template())

        return JsonResponse({
            "status": True,
            "iTotalRecords": max_objs,
            "iTotalDisplayRecords": max_objs,
            "aaData": objs
        })


class ListAccessControl(ListLDAPRepository):
    """ Class dedicated to list all AccessControl objects """
    template_name = "access_control.html",
    obj = AccessControl

    # Get and POST inherited from ListLDAPRepository
