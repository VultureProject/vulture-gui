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
__author__ = "Theo Bertin"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Oauth2 PKCE toolkit'

from hashlib import sha256
from base64 import urlsafe_b64encode

def _calculate_challenge(verifier):
	if type(verifier) == str:
		verifier = verifier.encode('utf-8')
	elif type(verifier) != bytes:
		return ''
	return urlsafe_b64encode(sha256(verifier).digest()).decode('utf-8').rstrip('=')

def validate_code_verifier(verifier, challenge):
	return _calculate_challenge(verifier) == challenge