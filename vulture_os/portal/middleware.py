
from django.conf import settings


class VultureCSRFMiddleWare(object):
    """
    This is a middleware for Vulture Portal.

    Vulture portal is running locally on 127.0.0.1:9000 as a TLS server.
    It can be called "externally" by a user surfing on either an HTTP or HTTPS connexion.
    The portal has to know if HTTP or HTTPS is used by the user to set the "Secure" flag correctly in the CSRF Cookie

    """

    # Check if HTTPS is used

    def process_response(self, request, response):

        if not request.META.get("CSRF_COOKIE_USED", False):
            return response

        # Set the CSRF cookie even if it's already set, so we renew
        # the expiry timer.
        response.set_cookie(settings.CSRF_COOKIE_NAME,
                            request.META["CSRF_COOKIE"],
                            max_age=settings.CSRF_COOKIE_AGE,
                            domain=settings.CSRF_COOKIE_DOMAIN,
                            path=settings.CSRF_COOKIE_PATH,
                            secure=False,
                            httponly=True
                            )

        return response
