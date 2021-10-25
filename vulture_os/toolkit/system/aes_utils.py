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
from cryptography.hazmat.primitives import padding

# Static AES block size (block size is given in bits, but must be used as bytes)
AES_BLOCK_SIZE = int(algorithms.AES.block_size/8)

class AESCipher(object):

    def __init__(self, key):
        self.bs = AES_BLOCK_SIZE
        self.key = hashlib.sha256(key.encode()).digest()

    def encrypt(self, raw):
        raw = raw.encode('utf-8')
        iv = os.urandom(self.bs)
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        encryptor = cipher.encryptor()
        padder = padding.PKCS7(self.bs*8).padder()

        padded_raw = padder.update(raw) + padder.finalize()
        enc = iv + encryptor.update(padded_raw) + encryptor.finalize()

        return base64.b64encode(enc)

    def decrypt(self, enc):
        enc = base64.b64decode(enc)
        iv = enc[:self.bs]
        cipher = Cipher(algorithms.AES(self.key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        unpadder = padding.PKCS7(self.bs*8).unpadder()

        padded_dec = decryptor.update(enc[self.bs:]) + decryptor.finalize()

        try:
            data = unpadder.update(padded_dec) + unpadder.finalize()
        except ValueError:
            # This is to account for a padding error introduced previously
            # TODO remove after correction script for version 1.3.11 has been broadly executed
            unpadder = padding.PKCS7(32*8).unpadder()
            data = unpadder.update(padded_dec) + unpadder.finalize()

        return data.decode('utf-8')
