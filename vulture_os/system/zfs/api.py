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
__doc__ = 'ZFS API'

from django.utils.translation import ugettext_lazy as _
from django.views.decorators.csrf import csrf_exempt
from gui.decorators.apicall import api_need_key
from system.zfs import views as zfs_views
from subprocess import Popen, PIPE
from django.http import JsonResponse
from django.conf import settings
from django.views import View
import logging

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api')


class ZFSAPIv1(View):
    @csrf_exempt
    @api_need_key('cluster_api_key')
    def get(self, request, object_id=None):

        try:
            proc = Popen(['/sbin/zfs', 'list'], stdout=PIPE)
            proc2 = Popen(['/usr/bin/grep', '/zroot'], stdin=proc.stdout, stdout=PIPE, stderr=PIPE)
            proc.stdout.close()
            success, error = proc2.communicate()
            obj = list()
            if not error:
                for s in success.decode('utf-8').split('\n'):
                    tmp = " ".join(s.split()).split(" ")

                    obj.append({
                        'name': tmp[0],
                        'used': tmp[1],
                        'avail': tmp[2],
                        'refer': tmp[3],
                        'mount': tmp[4]
                    })

                return JsonResponse({
                    'status': True,
                    'data': obj
                })
            else:
                logger.error(error, exc_info=1)

        except Exception as e:
            if settings.DEV_MODE:
                raise

            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'status': False,
                'error': error
            }, status=500)

    @csrf_exempt
    @api_need_key('cluster_api_key')
    def post(self, request, object_id=None, action=None):
        try:

            if not action:
                return JsonResponse({
                    'error': _('You must specify an action')
                }, status=401)

            if action and not object_id:
                return JsonResponse({
                    'error': _('You must specify an ID')
                }, status=401)

            command_available = {
                'snapshot': zfs_views.zfs_snapshot,
                'restore': zfs_views.zfs_restore,
                'refresh': zfs_views.zfs_refresh
            }

            if action not in list(command_available.keys()):
                return JsonResponse({
                    'error': _('Action not allowed')
                }, status=403)

            return command_available[action](request, object_id, api=True)

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

        return JsonResponse({
            'error': error
        }, status=500)
