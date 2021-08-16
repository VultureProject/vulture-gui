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
__author__ = "Jérémie JOURDIN"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture Project"
__email__ = "contact@vultureproject.org"
__doc__ = 'System Utils SSL Toolkit'


import base64
import hashlib

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

# Static AES block size (block size is given in bits, but must be used as bytes)
AES_BLOCK_SIZE = int(algorithms.AES.block_size/8)

class AESCipher(object):

    def __init__(self, key):
        self.bs = 32
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = self._pad(raw)
        iv = os.urandom(AES_BLOCK_SIZE)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        enc = iv + encryptor.update(raw.encode('utf-8')) + encryptor.finalize()
        return base64.b64encode(enc)

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:AES_BLOCK_SIZE]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        data = self._unpad(decryptor.update(enc[AES_BLOCK_SIZE:]) + decryptor.finalize()).decode('utf-8')
        return data

    def _pad(self, s):
        return s + (self.bs - len(s) % self.bs) * chr(self.bs - len(s) % self.bs)

    @staticmethod
    def _unpad(s):
        return s[:-ord(s[len(s) - 1:])]
