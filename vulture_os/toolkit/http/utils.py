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
__author__ = "Jérémie Jourdin"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'System HTTP Utils Toolkit'

# Django system imports

# Django project imports

# Extern modules imports
import json
import re
import ssl
from urllib.parse import urlencode

from bs4 import BeautifulSoup
from robobrowser.forms import Form
from robobrowser.forms.fields import BaseField

import requests
from requests.adapters import HTTPAdapter
from requests.packages.urllib3.poolmanager import PoolManager

# Required exceptions imports
from toolkit.http.exceptions import FetchFormError

# Logger configuration imports


vulture_custom_agent = 'Vulture/4 (FreeBSD; Vulture OS)'


class SSLAdapter(HTTPAdapter):
    """ "Transport adapter" that allows us to use TLSv1 """
    def __init__(self, *args, **kwargs):
        self.ssl_context = kwargs.pop('ssl_context')
        super(SSLAdapter, self).__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        kwargs['ssl_context'] = self.ssl_context
        self.poolmanager = PoolManager(*args, **kwargs)


def build_url_params(url, **kwargs):
    if kwargs:
        return "{}?{}".format(url, urlencode(kwargs))
    return url

def build_url(scheme, domain, port, path):
    url = scheme + "://" + domain
    if (scheme == "https" and port != 443) or (scheme == "http" and port != 80):
        url += ":{}".format(port)
    url += path
    print(url)
    return url


def get_cookie_values (response_cookie):
    """ FIXME: This is a hack, to be improved """
    for m in re.findall(r"xpires=[a-zA-Z0-9,\-: ]+", response_cookie):
        new_m=m.replace(",","<coma>")
        response_cookie=response_cookie.replace(m,new_m)

    cookies=dict()
    for cookie in response_cookie.split(","):
        cookie=cookie.lstrip()
        for field in cookie.split(";"):
            flds = field.split("=")
            n=flds[0]
            v=flds[1]
            cookies[n]=v
            break
    return cookies

def add_cookie_to_response(app, response, response_cookie):
    if not response_cookie:
        return response

    """ FIXME: This is a hack, to be improved """
    for m in re.findall(r"xpires=[a-zA-Z0-9,\-: ]+", response_cookie):
        new_m=m.replace(",","<coma>")
        response_cookie=response_cookie.replace(m,new_m)

    for cookie in response_cookie.split(","):
        cookie=cookie.lstrip()
        i=0
        expires=None
        path=None
        domain=None
        if 'httponly' in cookie.lower():
            httponly=True
        else:
            httponly=False

        for field in cookie.split(";"):

            if i==0:
                flds = field.split("=")
                n=flds[0]
                v=flds[1]
            else:
                flds = field.split("=")
                fn=flds[0]

                if (fn.lower().lstrip()=="expires"):
                    expires=flds[1].replace("<coma>",",")
                elif (fn.lower().lstrip()=="path"):
                    path=flds[1]
                elif (fn.lower()=="domain"):
                    domain=flds[1]


            if not path:
                path = app.public_dir

            i += 1

        if app.get_redirect_uri().startswith("https://"):
            response.set_cookie(n,v,path=path,domain=domain,expires=expires,httponly=httponly,secure=True)
        else:
            response.set_cookie(n,v,path=path,domain=domain,expires=expires,httponly=httponly,secure=False)

    return response




def dict_to_multipart (fields):

    boundary = '--------VltBndS8452208838-VltBndE--'
    CRLF = '\r\n'
    L = []
    for (key, value) in fields.iteritems():
        L.append('--' + boundary)
        L.append('Content-Disposition: form-data; name="%s"' % key)
        L.append('')
        """ Convert list to string """
        if isinstance(value,basestring):
            L.append(value)
        else:
            L.append(",".join(map(str, value)))
    L.append('--' + boundary + '--')
    L.append('')
    body = CRLF.join(L)
    content_type = 'multipart/form-data; boundary=%s' % boundary
    return content_type, body

def ssoPOST(logger, uri, req, data, cookie_data, app, cookie_from_fetch, ssl_context=None):
    """ Authenticate a user against an http form
    :param logger: logger instance
    :param uri: The 'action' uri where to post the form
    :param req: The request from the user browser, used to get referer, user-agent...
    :param data: A dict containing data to be posted
    :param cookie_data: A dict containing data to be sent as Cookies
    :param app: The app object to get its configuration
    :param cookie_from_fetch: the cookie returned by the app when fetching the login page for the first time
    :return a tuple (response: an urllib2 response, response_body: the SSO response body)
    """


    """ GUI-0.4: This can be None """
    try:
        content_type = app.sso_forward_content_type
    except:
        content_type = "default"

    post_datas = None

    session = requests.Session()
    verify_certificate = False
    client_side_cert = None
    if ssl_context is not None:
        # requests version 2.18.1 needed for the following line
        session.mount("https://", SSLAdapter(ssl_context.protocol))

        verify_certificate = "/var/db/pki/" if ssl_context.verify_mode == ssl.CERT_REQUIRED else False
        client_side_cert = app.ssl_client_certificate if app.ssl_client_certificate else None

    if content_type == "json":
        #request = urllib2.Request(uri, json.dumps(data))
        post_datas = json.dumps(data)
        session.headers.update({'Content-Type': "application/json"})

    elif content_type == "default":
        #request = urllib2.Request(uri, urlencode(data))
        #request.add_header('Content-Type', "application/x-www-form-urlencoded")
        post_datas = urlencode(data)
        session.headers.update({'Content-Type': "application/x-www-form-urlencoded"})

    elif content_type == "multipart":
        content_type, post_datas = dict_to_multipart(data)
        #request = urllib2.Request(uri, data)
        #request.add_header('Content-Type', content_type)
        session.headers.update({'Content-Type': content_type})

    request_cookies = ""
    if cookie_from_fetch:
        request_cookies = "; ".join('%s=%s' % (k, v) for k, v in get_cookie_values(cookie_from_fetch).items())

    if cookie_data:
        request_cookies = request_cookies+";"+"; ".join('%s=%s' % (k, v) for k, v in cookie_data.items())

    if request_cookies != "":
        #request.add_header ('Cookie', request_cookies)
        session.headers.update({'Cookie': request_cookies})

    if app.sso_vulture_agent:
        #request.add_header('User-Agent', vulture_custom_agent)
        session.headers.update({'User-Agent': vulture_custom_agent})
    else:
        try:
            #request.add_header('User-Agent', req.META['HTTP_USER_AGENT'])
            session.headers.update({'User-Agent': req.META['HTTP_USER_AGENT']})
        except:
            #request.add_header('User-Agent', vulture_custom_agent)
            session.headers.update({'User-Agent': vulture_custom_agent})
            pass

    try:
        #request.add_header('Referer',req.META('HTTP_REFERER'))
        session.headers.update({'Referer': req.META('HTTP_REFERER')})
    except:
        pass

    """ Add Request Header, if any defined in Application config """
    try:
        for header in app.headers_in:
            if header.action in ('set', 'add'):
                #request.add_header (header.name, header.value)
                session.headers.update({header.name: header.value})
    except:
        pass

    """ NEVER enable that on production ! """
    #logger.debug("ssoPOST: Request body = " + str(post_datas))
    #logger.debug("ssoPOST: Request headers = " + str(session.headers))

    if app.sso_forward_follow_redirect_before:
        logger.debug("ssoPOST: follow redirect is 'On'")
        #opener = urllib2.build_opener()
        follow_redirect = True
    else:
        logger.debug("ssoPOST: follow redirect is 'Off'")
        #opener = urllib2.build_opener(NoRedirection)
        follow_redirect = False

    # if ssl_context:
    #     response = urllib2.urlopen(request, context=ssl_context)
    # else:
    #     response = opener.open(request)
    # response_body = response.read()

    response = session.post(uri, data=post_datas, verify=verify_certificate, cert=client_side_cert, allow_redirects=follow_redirect)
    response_body = response.content

    return response, response_body


def httpGET(uri, req, app):
    """ Send a simple GET request to URI
    :param uri: The 'action' uri where to post the form
    :param req: The request from the user browser, used to get referer, user-agent...
    :param app: The app object to get its configuration
    :return response_body: the response's body
    """
    session = requests.Session()
    #request = urllib2.Request(uri)

    if app.sso_vulture_agent:
        #request.add_header('User-Agent', vulture_custom_agent)
        session.headers.update({'User-Agent': vulture_custom_agent})
    else:
        try:
            #request.add_header('User-Agent', req.META['HTTP_USER_AGENT'])
            session.headers.update({'User-Agent': req.META['HTTP_USER_AGENT']})
        except:
            #request.add_header('User-Agent', vulture_custom_agent)
            session.headers.update({'User-Agent': vulture_custom_agent})
            pass
    try:
        #request.add_header('Referer',req.META('HTTP_REFERER'))
        session.headers.update({'User-Agent': vulture_custom_agent})
    except:
        pass

    """ Add Request Header, if any defined in Application config """
    try:
        for header in app.headers_in:
            if header.action in ('set', 'add'):
                #request.add_header (header.name, header.value)
                session.headers.update({header.name: header.value})
    except:
        pass

    #opener = urllib2.build_opener()
    #response=opener.open(request)
    #return response.read()
    response = session.get(uri)
    return response.content


""" Return a robobrowser.forms.Form list with all fields identified """
def fetch_forms(logger, uris, req, user_agent, headers=dict(), ssl_context=None, proxy_client_side_certificate=None):
    """ Fetch forms inside an html page
    :param logger: logger instance
    :param uri: The 'action' uri where to post the form
    :param req: The request from the user browser, used to get referer, user-agent...
    :param sso_vulture_agent: A Boolean telling if we have to use the Vulture User-Agent or the browser User-Agent
    :param headers: Optional dict that contains headers to send in the request
    :returns: Mechanize instance, final URI string, response's Set-Cookie string, dict with response elements
    """

    #request = urllib2.Request(uri)
    verify_certificate = False
    session = requests.Session()
    if ssl_context is not None:
        #ssl_context.options |= ssl.OP_NO_TLSv1_2 | ssl.OP_NO_TLSv1 | ssl.OP_NO_SSLv3
        session.mount("https://", SSLAdapter(ssl_context=ssl_context))

    if not proxy_client_side_certificate or not ssl_context:
        proxy_client_side_certificate = None

    #request.add_header('User-Agent', ua)
    session.headers.update({'User-Agent': user_agent})

    for k, v in headers.items():
        #request.add_header(k,v)
        session.headers.update({k: v})

    # if ssl_context:
    #     response = urllib2.urlopen(request, context=ssl_context)
    # else:
    #     opener = urllib2.build_opener()
    #     response = opener.open(request)

    # response_body=response.read()
    response = None
    errors = {}
    for uri in uris:
        try:
            response = session.get(uri, verify=verify_certificate, cert=proxy_client_side_certificate)
            response_body = response.content
            break
        except Exception as e:
            logger.error("FETCH_FORMS::Exception while getting uri '{}' : {}".format(uri, e))
            errors[uri] = e

    if not response:
        raise FetchFormError("FETCH_FORMS::No url could be fetched among the following list : {}".format(errors))

    try:
        if response.encoding.lower() != "utf-8":
            response_body = response.content.encode('utf-8')
    except Exception as e:
        raise FetchFormError("FETCH_FORMS::Exception while trying to encode response content : {}".format(e))

    if response.status_code == 401 and response.reason == "Unauthorized":
        raise FetchFormError("FETCH_FORM")

    try:
        """ Check if we have to follow a meta redirect (301/302 are already handled by urllib2) """
        redirect_re = re.compile('<meta[^>]*?url=\s*(.*?)["\']', re.IGNORECASE)
        match = redirect_re.search(response_body)
        logger.info(match)
        if match:
            uri = match.groups()[0].strip()
            response = session.get(uri, verify=verify_certificate, cert=proxy_client_side_certificate)
            #response_body=response.read()
            response_body = response.content
            if response.encoding.lower() != "utf-8":
                response_body = response.content.encode('utf-8')
    except Exception as e:
        logger.error("FETCH_FORMS::Cannot retrieve meta redirection, continuing. Details : " + str(e))

    # Parse response with BeautifulSoup and robobrowser => PYTHON 3
    parsed = BeautifulSoup(response_body, 'html.parser')
    resp = []
    for form in parsed.findAll('form'):
        f = Form(form)
        # RoboBrowser does not handle submit button
        for field in form.find_all('button'):
            # If not name, continue
            if not field.attrs.get('name'):
                continue
            if field.attrs.get('type') == "submit":
                f.add_field(BaseField(field))
        resp.append(f)
    # Python 2 with OLD mechanize
    # resp = mechanize.ParseString(response_body, response.url) #, backwards_compat=False)

    return resp, uri, response, response_body


def parse_html(body_html, base_url):
    parsed = BeautifulSoup(body_html, 'html.parser')
    forms = list()
    for form in parsed.findAll('form'):
        f = Form(form)
        # RoboBrowser does not handle submit button
        for field in form.find_all('button'):
            # If not name, continue
            if not field.attrs.get('name'):
                continue
            if field.attrs.get('type') == "submit":
                f.add_field(BaseField(field))
        if not f.action:
            f.action = base_url
        elif not re.search("^https?://", f.action):
            if f.action.startswith('/'):
                f.action = "{}{}".format('/'.join(base_url.split('/')[:3]), f.action)
            else:
                f.action = "{}/{}".format('/'.join(base_url.split('/')[:3]), f.action)
        forms.append(f)
    return forms


""" Return the URL of a string, without the fqdn and without query string
"""
def get_uri_content (uri):
    uri = re.sub('\?.*$', '', uri)
    uri = re.sub('(.*:\/\/+[a-zA-Z0-9.:\-]*\/)', '', uri)
    return uri


""" Return the FQDN of a string
"""
def get_uri_fqdn (uri):
    uri = re.sub('(.*:\/\/+[a-zA-Z0-9.:\-]*)(\/)?.*', '\\1', uri)
    return uri


""" Return the FQDN+path of a string
"""
def get_uri_fqdn_path (uri):
    uri = re.sub('(.*:\/\/+[a-zA-Z0-9.:\-]+(\/.+\/)?).*', '\\1', uri)
    return uri


""" Return the FQDN of a string, without http(s)://
"""
def get_uri_fqdn_without_scheme (uri):
    uri = re.sub('.*:\/\/+([a-zA-Z0-9.:\-\[\]]*)(\/)?.*', '\\1', uri)
    return uri


""" Return the Path of a URI
"""
def get_uri_path (uri):
    uri = re.sub('.*:\/\/+[a-zA-Z0-9.:\-\[\]]*(\/.*)', '\\1', uri)
    return uri


""" Return True if the given URI is valid, False otherwise
    HTTP, HTTPS, FTP and FTPS ONLY
"""
def check_uri(uri):
    regex = re.compile(
    r'^(?:http|ftp)s?://' # http:// or https://
    r'(?:(?:[A-Z0-9](?:[A-Z0-9\-]{0,61}[A-Z0-9])?\.)+(?:[A-Z]{2,6}\.?|[A-Z0-9\-]{2,}\.?)|' # domain...
    r'localhost|' # localhost...
    r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}|' # ...or ipv4
    r'\[?[A-F0-9]*:[A-F0-9:]+\]?)' # ...or ipv6
    r'(?::\d+)?' # optional port
    r'(?:/?|[/?]\S+)$', re.IGNORECASE)

    match = regex.match (uri)
    if match:
        return True
    return False
