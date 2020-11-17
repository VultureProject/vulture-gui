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
from authentication.kerberos.models import KerberosRepository
from authentication.ldap.models import LDAPRepository
from authentication.learning_profiles.models import LearningProfile
from authentication.openid.models import OpenIDRepository
from authentication.otp.models import OTPRepository
from authentication.radius.models import RadiusRepository
from authentication.user_portal.models import UserAuthentication

# Extern modules imports
from json import loads as json_loads

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


class ListView(View):
    """ Generic list view - use to_template() to render an object """
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


class ListLDAPRepository(ListView):
    """ Custom class - use to_html_template() to render an object """
    template_name = "authentication/ldap.html"
    obj = LDAPRepository

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


class ListOTPRepository(ListLDAPRepository):
    template_name = "authentication/otp.html",
    obj = OTPRepository

    # Get and POST inherited from ListLDAPRepository


class ListKerberosRepository(ListLDAPRepository):
    template_name = "authentication/kerberos.html",
    obj = KerberosRepository

    # Get and POST inherited from ListLDAPRepository


class ListRadiusRepository(ListLDAPRepository):
    template_name = "authentication/radius.html",
    obj = RadiusRepository

    # Get and POST inherited from ListLDAPRepository


class ListUserAuthentication(ListLDAPRepository):
    template_name = "authentication/user_authentication.html",
    obj = UserAuthentication

    # Get and POST inherited from ListLDAPRepository


class ListLearningProfile(ListView):
    """ Custom class - use as_table() to render an objects """
    template_name = "authentication/learning_profiles.html"
    obj = LearningProfile

    # Get and POST inherited from ListView


class ListOpenIDRepository(ListLDAPRepository):
    """ Custom class - use as_table() to render an objects """
    template_name = "authentication/openid.html"
    obj = OpenIDRepository

    # Get and POST inherited from ListLDAPRepository
