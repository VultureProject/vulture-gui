from django.conf import settings
from django.http import HttpResponseForbidden
from django.http import HttpRequest
from functools import wraps
from system.cluster.models import Cluster

import logging
logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api')


def api_need_key(key_name):
    """ Decorator used to check if the given API Key is correct
    passed in

    :param group_names: List of groups
    :return:
    """

    def decorator(func):
        @wraps(func)
        def inner(cls_or_request, *args, **kwargs):
            request = None
            if not isinstance(cls_or_request, HttpRequest):
                if not isinstance(args[0], HttpRequest):
                    logger.error("API Call without request object : {} and {}".format(cls_or_request, request))
                    return HttpResponseForbidden()
                else:
                    request = args[0]
            else:
                request = cls_or_request

            global_config = Cluster().get_global_config()

            if request.user.is_authenticated:
                # Call from GUI. No need for Authorization header
                return func(request, *args, **kwargs)

            api_key = request.META.get("HTTP_" + key_name.upper())
            if getattr(global_config, key_name.replace('-', '_')) and \
                    getattr(global_config, key_name.replace('-', '_')) == api_key:
                return func(request, *args, **kwargs)

            logger.error(
                'API Call without valid API key. Method (%s): %s', request.method, request.path,
                extra={'status_code': 405, 'request': request}
            )
            return HttpResponseForbidden()

        return inner
    return decorator


