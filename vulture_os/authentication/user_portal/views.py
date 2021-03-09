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
__doc__ = 'LDAP Repository views'


# Django system imports
from django.conf import settings
from django.http import HttpResponseBadRequest, HttpResponseForbidden, HttpResponseRedirect, JsonResponse
from django.shortcuts import render
from django.urls import reverse

# Django project imports
from gui.forms.form_utils import DivErrorList
from toolkit.api.responses import build_response

# Required exceptions imports
from django.core.exceptions import ObjectDoesNotExist
from authentication.user_portal.form import UserAuthenticationForm
from authentication.user_portal.models import UserAuthentication, RepoAttributesForm, RepoAttributes
from services.frontend.models import Listener
from services.frontend.form import ListenerForm
from system.cluster.models  import Cluster
from system.pki.models import X509Certificate, PROTOCOLS_TO_INT
from portal.system.sso_clients import SSOClient
from toolkit.http.utils import parse_html

# Extern modules imports
from json import loads as json_loads
from traceback import format_exception
from sys import exc_info
import ssl
import json

# Logger configuration imports
import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('gui')


def user_authentication_clone(request, object_id):
    """ UserAuthentication view used to clone an object
    N.B: Do not totally clone the object and save-it in MongoDB 
        because some attributes are unique constraints
 
    :param request: Django request object
    :param object_id: MongoDB object_id of a UserAuthentication object
    """
    """ If POST request, same as edit with no ID """
    if request.POST:
        return user_authentication_edit(request)

    try:
        profile = UserAuthentication.objects.get(pk=object_id)
    except Exception as e:
        logger.exception(e)
        return HttpResponseForbidden("Injection detected")

    profile.pk = None
    profile.name = "Copy_of_" + str(profile.name)

    form = UserAuthenticationForm(None, instance=profile, error_class=DivErrorList)

    return render(request, 'authentication/user_authentication_edit.html', {'form': form})


def user_authentication_edit(request, object_id=None, api=False):
    profile = None
    listener_obj = None
    listener_f = None
    repo_attrs_form_list = []
    repo_attrs_objs = []
    if object_id:
        try:
            profile = UserAuthentication.objects.get(pk=object_id)
            listener_obj = profile.external_listener if profile.enable_external else None
        except ObjectDoesNotExist:
            return HttpResponseForbidden("Injection detected")

    """ Create form with object if exists, and request.POST (or JSON) if exists """
    if hasattr(request, "JSON") and api:
        form = UserAuthenticationForm(request.JSON or None, instance=profile, error_class=DivErrorList)
    else:
        form = UserAuthenticationForm(request.POST or None, instance=profile, error_class=DivErrorList)

    def render_form(profile, **kwargs):
        save_error = kwargs.get('save_error')
        if api:
            if form.errors:
                return JsonResponse(form.errors.get_json_data(), status=400)
            if save_error:
                return JsonResponse({'error': save_error[0]}, status=500)

        if not repo_attrs_form_list and profile:
            for p in profile.repo_attributes:
                repo_attrs_form_list.append(RepoAttributesForm(instance=p))
        logger.info(repo_attrs_form_list)
        return render(request, 'authentication/user_authentication_edit.html',
                      {'form': form,
                       'repo_attributes': repo_attrs_form_list,
                       'repo_attribute_form': RepoAttributesForm(),
                       **kwargs})


    if request.method in ("POST", "PUT"):
        """ Handle repo attributes (user scope) """
        try:
            if api:
                repo_attrs = request.JSON.get('repo_attributes', [])
                assert isinstance(repo_attrs, list), "Repo attributes field must be a list."
            else:
                repo_attrs = json_loads(request.POST.get('repo_attributes', "[]"))
        except Exception as e:
            if api:
                return JsonResponse({
                    "error": "".join(format_exception(*exc_info()))
                })
            return render_form(profile, save_error=["Error in Repo_Attributes field : {}".format(e),
                                                           str.join('', format_exception(*exc_info()))])

        """ Handle JSON formatted listeners """
        if form.data.get('enable_external'):
            try:
                if api:
                    listener_json = request.JSON.get('external_listener_json', {})
                    assert isinstance(listener_json, list), "Listeners field must be a dict."
                else:
                    listener_json = json_loads(request.POST.get('external_listener_json', "{}"))
                assert listener_json, "Listener required if external enabled"
            except Exception as e:
                if api:
                    return JsonResponse({
                        "error": "".join(format_exception(*exc_info()))
                    })
                return render(request, 'authentication/user_authentication_edit.html', {'form': form,
                                                                                    'save_error':["Error in external listener field : {}".format(e),
                                                                                                  str.join('', format_exception(*exc_info()))]})
            """ If id is given, retrieve object from mongo """
            try:
                instance_l = Listener.objects.get(pk=listener_json['id']) if listener_json.get('id') else None
            except ObjectDoesNotExist:
                form.add_error(None, "Listener with id {} not found.".format(listener_json['id']))
            else:
                """ And instantiate form with the object, or None """
                listener_f = ListenerForm(listener_json, instance=instance_l)
                if not listener_f.is_valid():
                    if api:
                        form.add_error("external_listener_json", listener_f.errors.as_json())
                    else:
                        form.add_error("external_listener_json", listener_f.errors.as_ul())

        """ For each Health check header in list """
        for repo_attr in repo_attrs:
            repoattrform = RepoAttributesForm(repo_attr, error_class=DivErrorList)
            if not repoattrform.is_valid():
                if api:
                    form.add_error(None, repoattrform.errors.get_json_data())
                else:
                    form.add_error('repo_attributes', repoattrform.errors.as_ul())
                continue
            # Save forms in case we re-print the page
            repo_attrs_form_list.append(repoattrform)
            repo_attrs_objs.append(repoattrform.save(commit=False))

        if form.is_valid():
            # Save the form to get an id if there is not already one
            profile = form.save(commit=False)
            if profile.enable_external:
                listener_obj = listener_f.save(commit=False)
                listener_obj.save()
                profile.external_listener = listener_obj
            profile.repo_attributes = repo_attrs_objs
            profile.save()

            try:
                Cluster.api_request("authentication.user_portal.api.write_templates", profile.id)
            except Exception as e:
                if api:
                    return JsonResponse({
                        "error": "".join(format_exception(*exc_info()))
                    })

                return render_form(profile, save_error=["Cannot write configuration: {}".format(e),
                                                                                   str.join('', format_exception(*exc_info()))])

            # If everything succeed, redirect to list view
            if api:
                return build_response(profile.id, "api.portal.user_authentication", [])
            return HttpResponseRedirect(reverse("portal.user_authentication.list"))

    if not listener_f:
        listener_f = ListenerForm(instance=listener_obj, error_class=DivErrorList)

    return render_form(profile, listener_form=listener_f)


# TODO @group_required('administrator', 'system_manager')
#@group_required('administrator', 'application_manager', 'security_manager')
def sso_wizard(request):
    """ View dedicated to create a JSON structure for SSO Forward
    ;param uri: URL where the login form is
    ;param sso_vulture_agent: If set to "true", use internal Vulture user-agent instead of the one send by the user browser
    """
    if request.method == 'POST':
        try:
            tls_proto = request.POST.get('sso_forward_tls_proto')
            tls_cert = request.POST.get('sso_forward_tls_cert')
            tls_check = request.POST.get('sso_forward_tls_check')
            url = request.POST['sso_forward_url']
            user_agent = request.POST.get('sso_forward_user_agent') or request.META.get('HTTP_USER_AGENT')
            redirect_before = request.POST.get('sso_forward_follow_redirect_before')

            #proxy_balancer_id = request.POST.get('proxy_balancer')
            #if proxy_balancer_id:
            #    proxy_balancer = ProxyBalancer.objects.get(pk=proxy_balancer_id)

        except KeyError as e:
            return JsonResponse({'status': False, 'reason': "Missing field : {}".format(str(e))})

    else:
        return HttpResponseForbidden()

    ssl_context = None
    ssl_client_certificate = None
    if url[:5] == "https" and tls_proto not in ('', 'None', None):
        ssl_context = ssl.SSLContext()
        ssl_context.minimum_version = PROTOCOLS_TO_INT[tls_proto]
        if tls_cert:
            ssl_context.verify_mode = ssl.CERT_REQUIRED
            ssl_client_certificate = X509Certificate.objects.get(pk=tls_cert).bundle_filename
        else:
            ssl_context.verify_mode = ssl.CERT_NONE

    """ Transform uri as list - to test multiple uris in case of balanced app """
    uris = [url]
    # if type != "balanced":
    #     if "[]" in uri:
    #         uri = uri.replace("[]", private_uri).replace("\[", '[').replace("\]", ']')
    #     else:
    #         uri = uri.replace("\[", '[').replace("\]", ']')
    #     uris.append(uri)
    # else:
    #     if "[]" not in uri:
    #         uris.append(uri.replace("\[", '[').replace("\]", ']'))
    #     else:
    #         for proxybalancer_member in proxy_balancer.members:
    #             # Concatenate scheme and uri, and remove public dir but keep port
    #             backend_uri = "{}://{}".format(proxybalancer_member.uri_type, proxybalancer_member.uri.split('/')[0])
    #             uri_tmp = uri.replace('[]', backend_uri)
    #             uri_tmp = uri_tmp.replace('\[', "[").replace('\]', ']')
    #             uris.append(uri_tmp)

    try:
        # Directly use portal classes
        sso_client = SSOClient(user_agent, [], request.META.get('HTTP_REFERER'), ssl_client_certificate, ssl_context,
                               verify_certificate=tls_check)
        url, response = sso_client.get(url, redirect_before)
        forms = parse_html(response.content, url)

        # forms, final_uri, response, response_body = fetch_forms(logger, uris, request, user_agent,
        #                                                         ssl_context=ssl_context,
        #                                                         proxy_client_side_certificate=ssl_client_certificate)
        form_list = list()
        i = 0
        # Retrieve attributes from robobrowser.Form objects
        for f in forms:
            if str(f.method).upper() == "POST":
                control_list = list()
                for field_name, field in f.fields.items():
                    if isinstance(field._parsed, list):
                        tag = field._parsed[0]
                    else:
                        tag = field._parsed
                    # field is a robobrowser.forms.fields.Input object
                    # field._parsed is a bs4.element.Tag object
                    control_list.append({'name': tag.attrs.get('name', ""), 'id': tag.attrs.get('id', ""),
                                         'type': tag.attrs.get('type'), 'value': tag.attrs.get('value', "")})
                form_list.append({'name': f.parsed.get('name', ""), 'id': i, 'controls': control_list})
                i += 1
        response = {'status': True, 'forms': form_list}
    except TypeError as error:
        logger.exception(error)
        response = {'status': False, 'reason': "No form detected in uri(s) {} : {}".format(uris, e)}
    except Exception as error:
        logger.exception(error)
        response = {'status': False, 'reason': str(error)}

    return JsonResponse(response)
