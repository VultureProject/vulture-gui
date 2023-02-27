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
__doc__ = 'Portal templates View'

import base64

# Django system imports
from django.conf import settings
from django.shortcuts import render
from django.utils.translation import gettext_lazy as _
from django.views.decorators.http import require_http_methods
from django.http import HttpResponseNotFound, HttpResponseRedirect

# Django project imports
from authentication.portal_template.models import PortalTemplate, TemplateImage
from authentication.portal_template.form import PortalTemplateForm, TemplateImageForm


# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


@require_http_methods(["GET"])
def template_edit(request, object_id=None):
    portal_template = None

    if object_id:
        try:
            portal_template = PortalTemplate.objects.get(pk=object_id)
        except PortalTemplate.DoesNotExist:
            return HttpResponseNotFound()
    
    form = PortalTemplateForm(None, instance=portal_template)
    return render(request, "authentication/portal_template/edit.html", {
        "object_id": object_id,
        "form": form
    })


def image_edit(request, object_id: str = None):
    image = TemplateImage()

    if object_id:
        try:
            image = TemplateImage.objects.get(pk=object_id)
        except TemplateImage.DoesNotExist:
            return HttpResponseNotFound()
    
    form = TemplateImageForm(request.POST or None, request.FILES or None, initial=image.to_dict())
    if request.method == "POST" and form.is_valid():

        with request.FILES["content"].open("rb") as f:
            image.content = base64.b64encode(f.read()).decode("utf-8")

        image.name = form.cleaned_data.get('name') 
        image.image_type = request.FILES["content"].content_type
        image.save()

        return HttpResponseRedirect('/portal/template/')

    return render(request, "authentication/portal_template/image_edit.html", {
        "object_id": object_id,
        "form": form
    })