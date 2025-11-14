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
__doc__ = 'Cluster API'


# Django system imports
from django.views.decorators.http import require_http_methods
from django.utils.decorators import method_decorator
from django.utils.translation import gettext_lazy as _
from django.views.decorators.csrf import csrf_exempt
from django.http import JsonResponse
from django.conf import settings
from django.views import View

# Django project imports
from applications.backend.models import Backend
from applications.logfwd.models import LogOMMongoDB
from authentication.user_portal.models import UserAuthentication
from gui.decorators.apicall import api_need_key
from system.cluster.models import Node, MessageQueue, APISyncResultTimeOutException
from system.cluster.views import COMMAND_LIST, cluster_edit
from system.cluster.models import Cluster
from system.pki.models import X509Certificate
from toolkit.network.network import is_valid_ip, is_valid_hostname
from toolkit.mongodb.postgres_base import PostgresBase
from services.frontend.models import Frontend
from workflow.models import Workflow

# Required exceptions imports

# Extern modules imports
import time

import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('system')


@csrf_exempt
@api_need_key('cluster_api_key')
@require_http_methods(["POST"])
def cluster_add(request):

    new_node_ip = request.POST.get('ip')
    new_node_name = request.POST.get('name')

    current_node = Cluster.get_current_node()

    if not new_node_name or not is_valid_hostname(new_node_name):
        return JsonResponse({
            'status': False,
            'message': 'Invalid hostname'
        })
    elif not new_node_ip or not is_valid_ip(new_node_ip):
        return JsonResponse({
            'status': False,
            'message': 'Invalid IP'
        })

    """ Make the new_node_name resolvable on all Cluster nodes """
    new_node_is_resolvable = current_node.api_request("toolkit.network.network.make_hostname_resolvable", (new_node_name, new_node_ip))
    if not new_node_is_resolvable.get('status', False) or 'instances' not in new_node_is_resolvable:
        logger.error(f"Error while creating new 'network.make_hostname_resolvable' task: {new_node_is_resolvable.get('message')}")
        return JsonResponse({
            'status': False,
            'message': 'Error during repl_add. Check logs'
        })
    new_node_is_resolvable = new_node_is_resolvable.get('instances', [None])[0]

    """ Now the new node should be in the cluster: Add its management IP """
    new_node = Node()
    new_node.name = new_node_name
    new_node.management_ip = new_node_ip
    new_node.internet_ip = new_node_ip
    new_node.backends_outgoing_ip = new_node_ip
    new_node.logom_outgoing_ip = new_node_ip
    new_node.save()

    """ Ask cluster to reload PF Conf and wait for it """
    logger.info("Call cluster-wide services.pf.pf.gen_config()...")
    pf_conf_generated = current_node.api_request("services.pf.pf.gen_config")
    pf_restarted = current_node.api_request("services.pf.pf.reload_service")
    if not pf_conf_generated.get('status', False) or 'instances' not in pf_conf_generated:
        logger.error(f"Error while creating new 'pf.gen_config' task: {pf_conf_generated.get('message')}")
        return JsonResponse({
            'status': False,
            'message': 'Error during repl_add. Check logs'
        })
    pf_conf_generated = pf_conf_generated.get('instances', [None])[0]
    pf_restarted = pf_restarted.get('instances', [None])[0]

    try:
        action_result, message = new_node_is_resolvable.await_result()
        if not action_result:
            logger.error(f"Could not make new node resolvable : {message}")
            return JsonResponse({
                'status': False,
                'message': 'Error during repl_add. Check logs'
            })
        action_result, message = pf_conf_generated.await_result()
        if not action_result:
            logger.error(f"Could not regenerate pf configuration : {message}")
            return JsonResponse({
                'status': False,
                'message': 'Error during repl_add. Check logs'
            })
        action_result, message = pf_restarted.await_result()
        if not action_result:
            logger.error(f"Could not restart pf: {message}")
            return JsonResponse({
                'status': False,
                'message': 'Error during repl_add. Check logs'
            })
    except APISyncResultTimeOutException as e:
        logger.error("Did not get a result for the action in time")
        logger.exception(e)
        return JsonResponse({
            'status': False,
            'message': 'Error during repl_add. Check logs'
        })

    """ Add NEW MongoDB node into the REPLICASET, as a pending member """
    postgres = PostgresBase()
    status, message = None, None
    if postgres.connect_with_retries(retries=10, timeout=2):
        cpt = 0
        while not message:
            try:
                logger.debug("Adding {} to replicaset".format(new_node_name))
                status, message = postgres.repl_add(new_node_name + ':9091')
            except Exception as e:
                logger.error("Cannot connect to replica for the moment : {}".format(e))
                cpt += 1
                if cpt > 10:
                    logger.error("Failed to connect to the replica 10 times, aborting.")
                    return JsonResponse({
                        'status': False,
                        'message': 'Error during repl_add. Check logs'
                    })
            logger.info("Waiting for next connection to replica...")
            time.sleep(1)
    else:
        logger.error("Could not connect to the MongoDB replicaset")

    if status:
        Cluster.api_request("toolkit.network.network.make_hostname_resolvable", (new_node_name, new_node_ip))
        Cluster.api_request("services.pf.pf.gen_config")
        Cluster.api_request("services.pf.pf.reload_service")
        new_node.api_request('toolkit.network.network.refresh_nic')
        for other_node in Node.objects.exclude(id=new_node.id):
            new_node.api_request("toolkit.network.network.make_hostname_resolvable", (other_node.name, other_node.management_ip))

        """ Update uri of internal Log Forwarder """
        logfwd = LogOMMongoDB.objects.get()
        logfwd.uristr = postgres.get_replicaset_uri()
        logfwd.save()

        """ Save certificates on new node """
        for cert in X509Certificate.objects.all():
            cert.save_conf()

        """ Synchronize Redis Node with cluster """
        # Replication is configured BEFORE password, as replication state must be defined for the sentinel to set a password
        for node in Node.objects.exclude(id=new_node.pk):
            if node.is_master_redis:
                new_node.api_request("toolkit.redis.redis_base.set_replica_of", (node.management_ip, ""))
                break
        cluster_redis_password = Cluster.get_global_config().redis_password
        new_node.api_request("toolkit.redis.redis_base.set_password", (cluster_redis_password, ""), internal=True)

        """ Download reputation databases before crontab """
        new_node.api_request("gui.crontab.feed.security_update")

        logger.debug("API call to configure HAProxy")
        # Reload/Build backend configurations
        for backend in Backend.objects.all():
            backend.save_conf()
        # Reload/Build backend configurations
        for workflow in Workflow.objects.all():
            new_node.api_request("workflow.workflow.build_conf", workflow.pk)
        # Reload/Build IDP configurations
        for idp in UserAuthentication.objects.filter(enable_external = True):
            new_node.api_request("authentication.user_portal.api.write_templates", idp.id)
            idp.save_conf()
        # Reload/Build global haproxy configurations and reload service for all nodes
        Cluster.api_request("services.haproxy.haproxy.configure_node")
        Cluster.api_request("services.haproxy.haproxy.reload_service")

        logger.debug("API call to reload whole darwin configuration")
        new_node.api_request("services.darwin.darwin.reload_all")

        """ The method configure restart rsyslog if needed """
        logger.debug("API calls to configure rsyslog")
        new_node.api_request("services.rsyslogd.rsyslog.build_conf")
        new_node.api_request("gui.crontab.generate_tzdbs.generate_timezone_dbs")
        new_node.api_request("gui.crontab.feed.update_reputation_ctx_now")
        # API call to whole Cluster - to refresh mongodb uri in pf logs
        Cluster.api_request("services.rsyslogd.rsyslog.configure_node")
        Cluster.api_request("services.rsyslogd.rsyslog.restart_service")

        logger.debug("API call to configure logrotate")
        new_node.api_request("services.logrotate.logrotate.reload_conf")

        logger.debug("API call to update PF")
        Cluster.api_request("services.pf.pf.gen_config")
        Cluster.api_request("services.pf.pf.reload_service")

        return JsonResponse({
            'status': True,
            'message': 'ok'
        })
    else:
        return JsonResponse({
            'status': False,
            'message': 'Error during repl_add. Check logs'
        })


@csrf_exempt
@api_need_key('cluster_api_key')
@require_http_methods(['GET'])
def cluster_info(request):
    try:
        nodes = {}
        for node in Node.objects.all():
            nodes[node.name] = node.to_dict()

        return JsonResponse({
            'status': True,
            'data': nodes
        })

    except Exception as e:
        logger.critical(e, exc_info=1)
        if settings.DEV_MODE:
            raise

        return JsonResponse({
            'status': False,
            'data': _('An error has occurred')
        }, 500)


@csrf_exempt
@api_need_key('cluster_api_key')
@require_http_methods(['GET'])
def secret_key(request):
    try:

        assert settings.SECRET_KEY

        return JsonResponse({
            'status': True,
            'data': settings.SECRET_KEY
        })

    except AssertionError:
        logger.error("Cannot get secret key: no key in settings")
        return JsonResponse({
            'status': False,
            'data': _("No secret key to provide")
        }, 404)

    except Exception as e:
        logger.critical(e, exc_info=1)
        if settings.DEV_MODE:
            raise

        return JsonResponse({
            'status': False,
            'data': _('An error has occurred')
        }, 500)


@api_need_key('cluster_api_key')
@require_http_methods(['GET'])
def get_message_queues(request):
    try:
        params = {}
        status = request.GET.get('status')
        if status:
            if status not in ("new", "running", "done", "failure"):
                return JsonResponse({
                    'status': False,
                    'data': _("Invalid value for parameter 'status'")
                }, status=400)
            params['status'] = status
        node = request.GET.get('node')
        if node:
            params['node__name'] = node

        limit = request.GET.get('limit', "100")
        try:
            limit = int(limit)
        except (TypeError, ValueError):
            return JsonResponse({
                'status': False,
                'data': _("Invalid value for parameter 'limit'")
            }, status=400)

        tasks = MessageQueue.objects.filter(**params).order_by('modified')[:limit]

        res = [m.to_template() for m in tasks]

        return JsonResponse({
            'status': True,
            'data': res
        })

    except Exception as e:
        logger.critical(e, exc_info=1)
        if settings.DEV_MODE:
            raise

        return JsonResponse({
            'status': False,
            'data': _('An error has occurred')
        }, 500)


@api_need_key('cluster_api_key')
@require_http_methods(['GET'])
def get_cluster_status(request):
    try:
        params = {}
        node_name = request.GET.get('node')
        node = None
        if node_name:
            try:
                node = Node.objects.get(name=node_name)
                params['node'] = node
            except Node.DoesNotExist:
                return JsonResponse({
                    'status': False,
                    'data': _(f"node with name {node_name} does not exist")},
                    status=404
                )

        pending_tasks = MessageQueue.objects.filter(**params, status__in=["new", "running"]).count()
        failed_tasks = MessageQueue.objects.filter(**params, status="failure").count()

        result = True
        frontends_status = []
        for f in Frontend.objects.filter(enabled=True):
            if node:
                if node not in f.get_nodes():
                    continue
                f_status = f.status.get(node.name, "UNKNOWN")
                if f_status != "OPEN":
                    result = False
            else:
                # No need to set status=False if it already is
                if result:
                    # Check on each node is status is UP
                    for f_node, f_stat in f.status.items():
                        if f_stat != "OPEN":
                            result = False
                f_status = f.status

            frontends_status.append({f.name: f_status})

        if result and (pending_tasks > 0 or failed_tasks > 0):
            result = False

        return JsonResponse({
            'status': result,
            'data': {
                'tasks': {
                    'pending': pending_tasks,
                    'failed': failed_tasks
                },
                'frontends': frontends_status
            }
        })

    except Exception as e:
        logger.critical(e, exc_info=1)
        if settings.DEV_MODE:
            raise

        return JsonResponse({
            'status': False,
            'data': _('An error has occurred')
        }, 500)


@method_decorator(csrf_exempt, name="dispatch")
class NodeAPIv1(View):
    @api_need_key('cluster_api_key')
    def get(self, request, object_id=None):
        try:
            name = request.GET.get("name")
            fields = request.GET.getlist('fields') or None
            if object_id:
                obj = Node.objects.get(pk=object_id).to_dict(fields=fields)
            elif name:
                obj = Node.objects.get(name=name).to_dict(fields=fields)
            else:
                obj = [s.to_dict(fields=fields) for s in Node.objects.all()]

            return JsonResponse({
                'data': obj
            })

        except Node.DoesNotExist:
            return JsonResponse({
                'error': _('Object does not exist')
            }, status=404)
        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'error': error
            }, status=500)

    @api_need_key('cluster_api_key')
    def post(self, request, object_id, action=None):
        try:
            if not action:
                return cluster_edit(request, object_id, api=True)

            if action and not object_id:
                return JsonResponse({
                    'error': _('You must specify an ID')
                }, status=401)

            if action not in list(COMMAND_LIST.keys()):
                return JsonResponse({
                    'error': _('Action not allowed')
                }, status=403)

            return COMMAND_LIST[action](request, object_id, api=True)

        except Exception as e:
            logger.critical(e, exc_info=1)
            if settings.DEV_MODE:
                error = str(e)
            else:
                error = _("An error has occurred")

        return JsonResponse({
            'error': error
        }, status=500)

    @api_need_key('cluster_api_key')
    def put(self, request, object_id):
        try:
            return cluster_edit(request, object_id, api=True)

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'error': error
            }, status=500)

    @api_need_key('cluster_api_key')
    def patch(self, request, object_id):
        allowed_fields = ('management_ip', 'internet_ip', 'backends_outgoing_ip', 'logom_outgoing_ip',
                          'gateway', 'gateway_ipv6', 'static_routes', 'pf_limit_states', 'pf_limit_frags', 'pf_limit_src',
                          'pf_custom_param_config', 'pf_custom_nat_config', 'pf_custom_rdr_config', 'pf_custom_config',
                          'pstats_forwarders')

        try:
            for key in request.JSON.keys():
                if key not in allowed_fields:
                    return JsonResponse({'error': _("Attribute not allowed : '{}'."
                                                    "Allowed attributes are {}".format(key, allowed_fields))}, status=400)
            return cluster_edit(request, object_id, api=True, update=True)

        except Exception as e:
            logger.critical(e, exc_info=1)
            error = _("An error has occurred")

            if settings.DEV_MODE:
                error = str(e)

            return JsonResponse({
                'error': error
            }, status=500)

    # It is not possible (yet?) to delete a node
