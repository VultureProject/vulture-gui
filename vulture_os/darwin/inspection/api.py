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
__author__ = "Théo BERTIN"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'packet inspection API'


# Django system imports
from django.conf import settings
from django.http import JsonResponse
from django.utils.translation import ugettext_lazy as _
from django.views import View

# Darwin imports
from darwin.inspection.models import InspectionPolicy

# Django project imports
from gui.decorators.apicall import api_need_key
from django.views.decorators.csrf import csrf_exempt
from django.utils.decorators import method_decorator

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api')


@method_decorator(csrf_exempt, name='dispatch')
class InspectionPolicyAPIv1(View):
    @api_need_key('cluster_api_key')
    def get(self, request, object_id=None):
        try:
            if object_id:
                try:
                    obj = InspectionPolicy.objects.get(pk=object_id).to_dict()
                except InspectionPolicy.DoesNotExist:
                    return JsonResponse({
                        'error': _('Object does not exist')
                    }, status=404)

            else:
                obj = [s.to_dict() for s in InspectionPolicy.objects.all()]

            return JsonResponse({
                'data': obj
            })

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'error': error
            }, status=500)
