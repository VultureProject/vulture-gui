#!/usr/bin/python
#-*- coding: utf-8 -*-
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
__author__ = "Hugo Soszynski"
__credits__ = []
__license__ = "GPLv3"
__version__ = "3.0.0"
__maintainer__ =\
    "Vulture Project"
__email__ = "contact@vultureproject.org"
__doc__ = 'Django views used to return the template images in database'

# Django system imports
from django.conf import settings
from django.http import HttpResponse, HttpResponseNotFound
import magic

# Django project imports
from applications.portal_template.models import TemplateImage

# REQUIRED ?
import sys
sys.path.append("/home/vlt-gui/vulture/portal")

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('portal_authentication')


def template_image(request, image_id=None):
    """
    Get the image using image_id and return it to be rendered in a portal template.
    :param request: Django request object.
    :param image_id: The object id of the searched image.
    :return: And HTTP response containing the image or Not Found.
    """

    if not image_id:
        return HttpResponseNotFound('')

    try:
        image = TemplateImage.objects.get(uid=image_id)
    except Exception as e:
        logger.error("Unable to find image: {}".format(e))
        return HttpResponseNotFound('')

    try:

        content = image.content.read()
        mime = magic.Magic(mime=True)
        mime_type = mime.from_buffer (content)
        return HttpResponse(content,content_type=mime_type)
    except Exception as e:
        logger.error("Unable to retrieve image content: {}".format(e))
        return HttpResponseNotFound('')

