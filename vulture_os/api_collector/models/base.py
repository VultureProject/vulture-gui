#!/usr/bin/env python
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

__author__ = "Fabien Amelinck"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = "API Collector model classes"

# Django system imports
from django.conf import settings
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from djongo import models

# Django project imports
from services.frontend.models import Frontend
from system.pki.models import X509Certificate

# Extern modules imports

# Required exceptions imports

# Logger configuration imports
import logging

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class ApiCollector(models.Model):
    class Meta:
        abstract = True

    """ Frontend associated to this collector """
    frontend = models.ForeignKey(
        to=Frontend,
        # related_name="api_collector",
        null=True,
        on_delete=models.CASCADE
    )
    use_proxy = models.BooleanField(
        default=False,
        verbose_name=_("Use Proxy"),
        help_text=_("Use a proxy to connect to distant endpoint")
    )
    custom_proxy = models.TextField(
        default="",
        help_text=_("Custom Proxy to use when requesting logs"),
        verbose_name=_("Custom Proxy")
    )
    verify_ssl = models.BooleanField(
        default=True,
        help_text=_("Verify SSL"),
        verbose_name=_("Verify certificate")
    )
    custom_certificate = models.ForeignKey(
        to=X509Certificate,
        null=True,
        on_delete=models.SET_NULL,
        # related_name="api_collectors",
        verbose_name=_("Custom certificate"),
        help_text=_("Custom certificate to use.")
    )
    last_api_call = models.DateTimeField(
        default=timezone.now
    )
    last_collected_timestamps = models.JSONField(
        default=dict
    )


def test_crontab():
    logger.info("[TEST CRONTAB] Successfully running")