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
__email__ = "contact@vultureproject.org"
__doc__ = 'Log Viewer view'

from copy import deepcopy

from django.conf import settings
from darwin.defender_policy.models import DefenderPolicy
from darwin.log_viewer import const
from darwin.log_viewer.models import (LogViewerConfiguration, LogViewerSearches, DefenderRuleset, DefenderRule,
                                      DEFENDER_PATH, DefenderProcessRuleJob, DefenderProcessRule)
from darwin.log_viewer.toolkit import LogViewerMongo, ModDefenderRulesFetcher, Predator
from django.http import JsonResponse, HttpResponseBadRequest, HttpResponseNotAllowed
from django.template.loader import render_to_string
from django.utils.translation import ugettext as _
from applications.logfwd.models import LogOM
from system.cluster.models import Cluster
from django.shortcuts import render
import json
import logging
import uuid
import threading

from services.frontend.models import Frontend
from system.cluster.models import Node

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


def log_viewer(request):
    try:
        if not request.is_ajax():
            return render(request, 'log_viewer.html')

        action = request.POST.get('action')

        data = {
            'status': False,
            'error': _("No defined action")
        }

        if action == "get_available_logs":
            available_logs = deepcopy(const.AVAILABLE_LOGS)
            """ If no impcap frontend, delete impcap available logs option """
            if Frontend.objects.filter(mode="impcap").count() == 0:
                del available_logs['impcap']

            access = False
            for frontend in Frontend.objects.exclude(mode="impcap", enable_logging=True).filter():
                lf_amount = frontend.log_forwarders.filter(internal=True).count()
                if lf_amount > 0:
                    access = True
                    break

            if not access:
                del available_logs['access']

            nodes = {}
            for n in Node.objects.all():
                nodes[n.id] = n.name

            data = {
                'status': True,
                'logs': available_logs,
                'nodes': nodes
            }

        elif action == "get_available_apps":
            type_logs = request.POST.get('type_logs')
            apps = {}

            if type_logs == "impcap":
                for frontend in Frontend.objects.filter(mode="impcap", enable_logging=True):
                    try:
                        frontend.log_forwarders.get(internal=True)
                        apps[frontend.name] = frontend.name
                    except LogOM.DoesNotExist:
                        continue
            else:
                for frontend in Frontend.objects.exclude(mode="impcap", enable_logging=True):
                    lf_amount = frontend.log_forwarders.filter(internal=True).count()
                    if lf_amount > 0:
                        apps[frontend.name] = frontend.name

            data = {
                'status': True,
                'applications': apps
            }

        elif action == "get_mapping":
            type_logs = request.POST.get('type_logs')

            try:
                configuration = LogViewerConfiguration.objects.get(
                    type_logs=type_logs,
                    user=request.user
                )
            except LogViewerConfiguration.DoesNotExist:
                configuration = LogViewerConfiguration(
                    type_logs=type_logs,
                    user=request.user.user,
                    displayed_columns=const.DEFAULT_COLUMNS[type_logs]
                )

                configuration.save()

            searches = [l.to_template() for l in LogViewerSearches.objects.filter(
                user=request.user.user,
                type_logs=type_logs
            )]

            data = {
                'status': True,
                'mapping': const.MAPPING[type_logs],
                'config': configuration.to_template(),
                'searches': searches,
                'predator_columns': const.PREDATOR_COLUMNS
            }

            if type_logs == "pf":
                data['nodes'] = [n.name for n in Node.objects.all()]

        elif action == "save_search":
            type_logs = request.POST['type_logs']
            update = request.POST.get('update')
            search_name = request.POST['search_name']
            rules = json.loads(request.POST['rules'])

            if update:
                search = LogViewerSearches.objects.get(pk=update)
                search.name = search_name
                search.search = rules

                search.save()

            else:
                search = LogViewerSearches.objects.create(
                    name=search_name,
                    type_logs=type_logs,
                    search=rules,
                    user=request.user.user
                )

            data = {
                "status": True,
                "searches": [l.to_template() for l in LogViewerSearches.objects.filter(
                    user=request.user.user,
                    type_logs=type_logs
                )]
            }

        elif action == "save_config":
            type_logs = request.POST['type_logs']
            size = int(request.POST.get('size', 10))
            length = int(request.POST.get('length', 10))
            table_config = json.loads(request.POST.get('table_config'))

            if length > 200:
                length = 200

            try:
                config = LogViewerConfiguration.objects.get(user=request.user.user, type_logs=type_logs)
                config.font_size = size
                config.nb_lines = length
                config.displayed_columns = table_config

                config.save()

            except LogViewerConfiguration.DoesNotExist:
                config = LogViewerConfiguration.objects.create(
                    user=request.user.user,
                    type_logs=type_logs,
                    nb_lines=length,
                    font_size=size,
                    displayed_columns=table_config
                )

            data = {'status': True}

        elif action == "delete_search":
            pk = request.POST['pk']
            LogViewerSearches.objects.get(pk=pk).delete()

            data = {'status': True}

        return JsonResponse(data)

    except Exception as e:
        if settings.DEV_MODE:
            raise

        logger.error(e, exc_info=1)
        return JsonResponse({
            'status': False,
            'error': _('An error has occured')
        })


def get_logs(request):
    params = {
        'startDate': request.POST['startDate'],
        'endDate': request.POST['endDate'],
        'type_logs': request.POST['type_logs'],
        'columns': json.loads(request.POST['columns']),
        'rules': json.loads(request.POST['rules']),
        'start': int(request.POST['iDisplayStart']),
        'length': int(request.POST['iDisplayLength']),
        'sorting': int(request.POST['iSortCol_0']),
        'type_sorting': request.POST['sSortDir_0'],
        'frontend_name': request.POST.get('frontend_name')
    }

    if params['type_logs'] in ('access',):
        params['frontend'] = Frontend.objects.get(name=request.POST.get('frontend_name'))

    log_viewer_mongo = LogViewerMongo(params)
    nb_res, results = log_viewer_mongo.search()
    graph_data = log_viewer_mongo.timeline()

    return JsonResponse({
        'status': True,
        "iTotalRecords": nb_res,
        "iTotalDisplayRecords": nb_res,
        "aaData": results,
        'graph_data': graph_data
    })


def get_graph(request):
    params = {
        'startDate': request.POST['startDate'],
        'endDate': request.POST['endDate'],
        'type_logs': request.POST['type_logs'],
        'rules': json.loads(request.POST['rules']),
        'frontend_name': request.POST.get('frontend_name')
    }

    log_viewer_mongo = LogViewerMongo(params)
    data = log_viewer_mongo.graph()

    return JsonResponse({
        'status': True,
        'data': data
    })


def predator_info(request):
    try:

        column = request.POST['column']
        info = request.POST['info']

        old_column = request.POST.get('old_column')
        old_info = request.POST.get('old_info')

        predator = Predator(column, info)
        data = predator.fetch_info()

        if not data['status']:
            return JsonResponse({
                'status': False,
                'error': data['error']
            })

        data['tag_info'] = info
        data['column'] = column

        data['old_info'] = old_info
        data['old_column'] = old_column

        return JsonResponse({
            'status': True,
            'info': info,
            'column': column,
            'data': render_to_string("predator.html", data)
        })

    except Exception as e:
        if settings.DEV_MODE:
            raise

        logger.critical(e, exc_info=1)
        return JsonResponse({
            'status': False,
            'error': _('An error has occurred')
        })


def predator_submit(request):
    try:
        ip = request.POST.get('ip')

        predator = Predator(None, ip)
        status, data = predator.submit_ip()

        if status:
            return JsonResponse({
                'status': True,
                'message': _("IP has been reported")
            })
        else:
            return JsonResponse({
                'status': False,
                'message': data
            })

    except Exception as e:
        if settings.DEV_MODE:
            raise

        logger.critical(e, exc_info=1)
        return JsonResponse({
            'status': False,
            'error': _('An error has occurred')
        })


def defender_perform(http_method, http_path, params, cookies, content_type, body, threshold):
    if http_path == '<BADREQ>':
        return []

    fetcher = ModDefenderRulesFetcher(
        conf_file_path=DEFENDER_PATH + "/core.rules",
        threshold=threshold
    )

    if http_method == '-':
        http_method = ''

    if http_path == '-':
        http_path = ''

    if params == '-':
        params = ''

    if cookies == '-':
        cookies = ''

    if content_type == '-':
        content_type = ''

    if body == '-':
        body = ''

    headers = ''

    if content_type:
        headers += 'Content-Type: {}\r\n'.format(content_type)

    if cookies:
        headers += 'Cookie: {}\r\n'.format(cookies)

    http_path += params

    request_dict = {
        'URL': http_path,
        'HEADERS': headers,
        'BODY': body,
        'METHOD': http_method
    }

    return fetcher.get_results(request_dict)


def get_defender_wl(request, job_id):
    try:
        try:
            job = DefenderProcessRuleJob.objects.get(job_id=job_id)
        except DefenderProcessRuleJob.DoesNotExist:
            return JsonResponse({
                'status': True,
                'message': {'is_done': None}
            }, status=200)

        if not job.is_done:
            return JsonResponse({
                'status': True,
                'message': {'is_done': False}
            }, status=200)

        rules = DefenderProcessRule.objects.filter(job_id=job_id)
        formatted_rules = {}

        for rule in rules:
            formatted_rules[rule.rule_key] = {
                **rule.data, **{'id': [rule.rule_id]}
            }

        return JsonResponse({
            'status': True,
            'message': {
                'rules': list(formatted_rules.values()),
                'is_done': True
            }
        }, status=200)

    except Exception as error:
        logger.exception(error)

        return JsonResponse({
            'status': False,
            'error': str(error)
        }, status=500)


def process_rules(job_id, results, rule_threshold):
    try:
        rule_job = DefenderProcessRuleJob.objects.get(job_id=job_id)

        for request_descr in results:
            try:
                matched_rules = defender_perform(
                    request_descr['http_method'],
                    request_descr.get('http_path', ''),
                    request_descr.get('http_get_params', ''),
                    request_descr.get('http_request_cookies', ''),
                    request_descr.get('http_request_content_type', ''),
                    request_descr.get('http_request_body', ''),
                    rule_threshold
                )

                for rule in matched_rules:
                    if rule.get('score') >= rule_threshold:
                        for rule_id in rule.get('ids'):

                            rule_key = '{},{},{},{}'.format(
                                rule.get('zone'), rule_id, rule.get('key'), rule.get('value')
                            )

                            process_rule = DefenderProcessRule(
                                job_id=job_id,
                                rule_id=rule_id,
                                rule_key=rule_key,
                                data={
                                    **rule, **{'id': [rule_id]}
                                }
                            )

                            process_rule.save()

            except FileNotFoundError:
                raise

            except Exception as error:
                logger.exception('process_rules function: rule exception with job ID {}! Error is {}'.format(
                    job_id, error
                ))

                continue

        rule_job.is_done = True
        rule_job.save()

    except Exception as error:
        logger.exception('process_rules function: unexpected error with job ID {}! Error is {}'.format(job_id, error))
        raise


def request_defender_wl(request):
    try:
        params = {
            'startDate': request.POST['startDate'],
            'endDate': request.POST['endDate'],
            'type_logs': "access",
            'rules': json.loads(request.POST['rules']),
            'frontend_name': request.POST.get('frontend_name'),
            'length': 0,
            'start': 0,
            'columns': [],
        }

        log_viewer_mongo = LogViewerMongo(params)
        nb_res, results = log_viewer_mongo.search()

        if nb_res > 0:
            logger.info('request_defender_wl function: about to process {} results'.format(nb_res))
            rule_threshold = request.POST.get('rule_threshold', 8)
            job_id = str(uuid.uuid4())

            rule_job = DefenderProcessRuleJob(job_id=job_id)
            rule_job.save()

            process_rules_thread = threading.Thread(
                target=process_rules,
                args=(str(job_id), results, rule_threshold),
                kwargs={}
            )

            process_rules_thread.setDaemon(True)
            process_rules_thread.start()

            return JsonResponse({'status': True,
                                 'message': job_id}, status=200)

        else:
            logger.debug("No rules has matched")

            return JsonResponse({'status': True,
                                 'message': None}, status=200)

    except Exception as error:
        logger.exception(error)

        return JsonResponse({
            'status': False,
            'error': str(error)
        }, status=500)


def get_defender_rulesets(request):
    try:
        if request.method != 'GET':
            return HttpResponseNotAllowed()

        search = request.GET.get('search')
        page = int(request.GET.get('page', 0))
        size = int(request.GET.get('size', 10))
        offset = page * size

        if search:
            objects = DefenderRuleset.objects.filter(name__contains=search)
        else:
            objects = DefenderRuleset.objects.all()

        is_more = len(objects[offset + size:offset + 2 * size]) > 0
        objects = objects[offset:offset + size]

        to_return = []

        for item in objects:
            to_return.append({
                'id': str(item.pk),
                'text': item.name,
            })

        return JsonResponse({'status': True, 'results': to_return, 'pagination': {'more': is_more}}, status=200)

    except Exception as error:
        logger.exception(error)
        return JsonResponse({'status': True, 'message': str(error)}, status=500)


def submit_defender_wl(request):
    try:
        logger.debug("A new Mod Defender whitelist will be saved")
        if not request.is_ajax():
            return HttpResponseBadRequest()

        try:
            rules = json.loads(request.POST['rules'])
            assert isinstance(rules, list)
        except KeyError:
            return JsonResponse({'status': False, 'error': _('Missing rules parameter')}, status=400)
        except AssertionError:
            return JsonResponse({'status': False, 'error': _('Rules parameter must be a list')}, status=400)

        if len(rules) <= 0:
            return JsonResponse({'status': False, 'error': _('Rule list given is empty')}, status=400)

        try:
            save_type = request.POST['save_type']
            save_type_list = ['create', 'edit', 'replace']
            assert isinstance(save_type, str)

            if save_type not in save_type_list:
                return JsonResponse({
                    'status': False,
                    'error': _('The save_type has to be one of the following:') + " {}".format(
                        ', '.join(save_type_list)
                    )
                }, status=400)
        except KeyError:
            return JsonResponse({'status': False, 'error': _('You must provide a save type')}, status=400)
        except AssertionError:
            return JsonResponse({'status': False, 'error': _('The save type has to be a string')}, status=400)

        if save_type == "create":
            try:
                name = request.POST['name']
                assert isinstance(name, str)
            except KeyError:
                return JsonResponse({
                    'status': False,
                    'error': _('You must provide a name for the ruleset')
                }, status=400)

            except AssertionError:
                return JsonResponse({
                    'status': False,
                    'error': _('Ruleset name has to be a string')
                }, status=400)

            name = name.replace(' ', '_')
            existing_rule_set_number = DefenderRuleset.objects.filter(name=name).count()

            if existing_rule_set_number > 0:
                return JsonResponse({
                    'status': False,
                    'error': 'A ruleset with the name "{}" already exists'.format(name)},
                    status=400
                )

            ruleset_obj = DefenderRuleset(name=name)
            ruleset_obj.raw_rules = ""
        else:
            try:
                ruleset_id = request.POST['ruleset_id']
                ruleset_id = int(ruleset_id)
            except KeyError:
                return JsonResponse({
                    'status': False,
                    'error': _('You must provide an ID for the existing ruleset')
                }, status=400)
            except ValueError:
                return JsonResponse({'status': False, 'error': _('The ruleset ID has to be an integer')}, status=400)

            try:
                ruleset_obj = DefenderRuleset.objects.get(pk=ruleset_id)
            except DefenderRuleset.DoesNotExist:
                return JsonResponse({
                    'status': False,
                    'error': 'The ruleset with the provided ID ({id}) does not exist'.format(id=ruleset_id)
                }, status=400)

        if save_type == "replace":
            logger.debug('Deleting existing rules for ruleset with ID {id}'.format(id=ruleset_obj.pk))

            for rule in ruleset_obj.rules.all():
                ruleset_obj.rules.remove(rule)
                rule.delete()

            ruleset_obj.raw_rules = ""

        for rule in rules:
            logger.debug("Processing rule {}".format(rule))

            try:
                new_rule = DefenderRule.objects.create(
                    zone=rule['zone'],
                    ids=rule['ids'],
                    key=rule['key'],
                    value=rule['value'],
                    url=rule['url'],
                    matched_type=rule['matched_type'],
                )

                logger.debug('New rule created: {}'.format(new_rule.to_dict()))

            except KeyError as error:
                error_message = 'Missing key for rule "{}" : {}'.format(rule, error)
                logger.error(error_message)

                return JsonResponse({'status': False, 'error': error_message}, status=400)

            ruleset_obj.rules.add(new_rule)
            ruleset_obj.raw_rules += '{}\n'.format(new_rule.generate_rule())

        ruleset_obj.save()

        logger.debug('New set created: {}'.format(ruleset_obj.to_dict()))

        if save_type in ['edit', 'replace']:
            logger.info('Reloading configuration for existing ruleset with ID {id}'.format(id=ruleset_obj.pk))
            defender_policy_list = DefenderPolicy.objects.filter(defender_ruleset=ruleset_obj)

            for defender_policy in defender_policy_list:
                Cluster.api_request("darwin.defender_policy.policy.write_defender_conf", defender_policy.id)

        return JsonResponse({'status': True, 'message': _('WAF ruleset saved')}, status=201)

    except Exception as error:
        logger.exception(error)

        return JsonResponse({'status': False, 'error': "Unknown error: " + str(error)}, status=500)
