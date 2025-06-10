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
__doc__ = ''

from system.cluster.models import MessageQueue
from django.http import JsonResponse
from django.conf import settings
from gui.models.rss import RSS
import logging.config
import json

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


def process_queue_state(request):
    """
        Fetch 10 last messages in queue
    """
    order = {
        "asc": "",
        "desc": "-"
    }

    try:
        columns = json.loads(request.POST.get('columns'))
        col_sort = columns[int(request.POST.get("iSortCol_0"))]
        col_order = "{}{}".format(order[request.POST.get('sSortDir_0')], col_sort)
    except (json.JSONDecodeError, ValueError, KeyError):
        col_order = "-date_add"

    objs = []

    max_objs = 50
    # Do NOT send internal MessageQueues
    for message in MessageQueue.objects.filter(internal=False).order_by("-run_at", col_order)[:max_objs]:
        objs.append(message.to_template())

    return JsonResponse({
        "status": True,
        "iTotalRecords": max_objs,
        "iTotalDisplayRecords": max_objs,
        "aaData": objs
    })


def rss(request):
    """
        Fetch all not acknowledged RSS informations
        ordered by date
    """
    if request.method == "GET":
        rss = [r.to_template() for r in
               RSS.objects.filter(ack=False).order_by('-date')]

        return JsonResponse({
            'status': True,
            'rss': rss
        })

    # If POST, acknowledge the RSS
    rss_id = request.POST['rss']

    try:
        rss = RSS.objects.get(pk=rss_id)
        rss.ack = True
        rss.save()
    except RSS.DoesNotExist as e:
        logger.error ("Main::rss: {}".format(e))
        return JsonResponse({
            'status': False
        })

    except Exception as e:
        logger.error ("Main::rss: {}".format(e))
        return JsonResponse({
            'status': False
        })

    return JsonResponse({
        'status': True
    })


def collapse(request):
    request.session['collapse'] = request.GET['collapse'] == "true"

    return JsonResponse({
        'status': True
    })
