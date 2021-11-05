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
__author__ = "Olivier de Régis"
__credits__ = []
__license__ = "GPLv3"
__version__ = "4.0.0"
__maintainer__ = "Vulture OS"
__email__ = "contact@vultureproject.org"
__doc__ = 'Forcepoint Console API Parser'


import M2Crypto
import base64
import logging
import requests
import hashlib
import zlib
import io

from django.conf import settings
from toolkit.api_parser.api_parser import ApiParser

from django.utils.translation import ugettext_lazy as _

logging.config.dictConfig(settings.LOG_SETTINGS)
logger = logging.getLogger('api_parser')


class ImpervaParseError(Exception):
    pass


class ImpervaAPIError(Exception):
    pass


class ImpervaParser(ApiParser):

    def __init__(self, data):
        super().__init__(data)

        self.imperva_base_url = data['imperva_base_url']
        self.imperva_api_key = data['imperva_api_key']
        self.imperva_api_id = data['imperva_api_id']
        self.imperva_private_key = data['imperva_private_key']
        self.imperva_last_log_file = data.get('imperva_last_log_file')

        authorization = bytes(f"{self.imperva_api_id}:{self.imperva_api_key}", "utf-8")
        authorization = base64.encodestring(authorization).decode("utf-8").replace("\n", "")

        self.headers = {
            "Authorization": f"Basic {authorization}"
        }

    def validate_checksum(self, checksum, uncompressed_and_decrypted_file_content):
        m = hashlib.md5()
        m.update(uncompressed_and_decrypted_file_content)
        cs = m.hexdigest()
        return cs == checksum

    def _unpad(self, s):
        return s[:-ord(s[len(s) - 1:])]

    def __decrypt_file(self, filename, file_header_content, file_log_content):
        file_encryption_key = file_header_content.find("key:")

        if file_encryption_key == -1:
            # Not encrypted
            # uncompress the log content
            return zlib.decompressobj().decompress(file_log_content)

        content_encrypted_sym_key = file_header_content.split("key:")[1].splitlines()[0]

        if not self.imperva_private_key:
            raise ImpervaParseError(_("Log content is encrypted, please fill the Private Key"))

        checksum = file_header_content.split("checksum:")[1].splitlines()[0]

        rsa_private_key = M2Crypto.RSA.load_key_string(bytes(self.imperva_private_key, 'utf-8'))

        content_decrypted_sym_key = rsa_private_key.private_decrypt(
            base64.b64decode(bytearray(content_encrypted_sym_key, 'utf-8')),
            M2Crypto.RSA.pkcs1_padding
        ).decode('utf-8')

        aes_key = base64.b64decode(bytearray(content_decrypted_sym_key, "utf-8"))
        # aes_keysize = 8 * len(aes_key)

        iv = b'\x00' * 16
        cipher = M2Crypto.EVP.Cipher(alg='aes_128_cbc', key=aes_key, iv=iv, op=0)
        v = cipher.update(file_log_content)
        file_content_decrypted = v + cipher.final()

        uncompressed_and_decrypted_file_content = zlib.decompressobj().decompress(
            file_content_decrypted
        )

        if not self.validate_checksum(checksum, uncompressed_and_decrypted_file_content):
            raise ImpervaParseError(_("Invalid checksum"))

        return uncompressed_and_decrypted_file_content

    def _download_log_index(self):
        url = f"{self.imperva_base_url}logs.index"

        r = requests.get(
            url,
            proxies=self.proxies,
            headers=self.headers
        )

        r.raise_for_status()
        log_files = [l for l in r.text.split('\n') if l]
        return log_files

    def get_file(self, filename):
        url = f"{self.imperva_base_url}{filename}"
        r = requests.get(
            url,
            proxies=self.proxies,
            headers=self.headers
        )

        # Let requests manage decompression
        r.raw.decode_content = True

        binary_stream = io.BytesIO()
        for chunk in r:
            binary_stream.write(chunk)

        binary_stream.seek(0)
        text_data = binary_stream.read()
        pos = text_data.index(b'|==|')

        binary_stream.seek(0)
        file_header = binary_stream.read(pos).decode('utf-8')

        binary_stream.seek(pos + 5)
        file_data = binary_stream.read()

        r.raise_for_status()

        content = self.__decrypt_file(filename, file_header, file_data)
        return content

    def test(self):
        try:
            log_files = self._download_log_index()

            return {
                'status': True,
                'data': f"Number of files: {len(log_files)}"
            }

        except ImpervaAPIError as error:
            return {
                "status": False,
                "error": str(error)
            }

    def execute(self):
        try:
            data = []
            if self.imperva_last_log_file == "":
                log_files = self._download_log_index()
                for file in log_files:
                    self.update_lock()
                    logger.info(f"[IMPERVA PARSER] Downloading {file}",
                                extra={'tenant': self.tenant_name})
                    content = self.get_file(file)
                    data.extend(content.split(b'\n'))

                    self.write_to_file(data)
                    data = []
                    self.imperva_last_log_file = file

            else:
                # Try to download the next file
                last_log_index = int(self.imperva_last_log_file.split('.')[0].split('_')[1])
                next_log_index = last_log_index + 1
                next_log_file = f"{self.imperva_last_log_file.split('_')[0]}_{next_log_index}.log"
                try:
                    content = self.get_file(next_log_file)
                    data.extend(content.split(b'\n'))
                    self.write_to_file(data)
                    self.imperva_last_log_file = next_log_file
                except Exception as e:
                    logger.exception(e, extra={'tenant': self.tenant_name})

                    # Download log files index
                    log_files = self._download_log_index()
                    first_log_id_in_index = int(log_files[0].split('.')[0].split('_')[1])
                    if next_log_index < first_log_id_in_index:
                        logger.error("Current downloaded file is not in the index file any more. "
                                     "This is probably due to a long delay in downloading. Attempting to recover",
                                     extra={'tenant': self.tenant_name})
                        self.imperva_last_log_file = ""
                    elif f"{self.imperva_last_log_file.split('_')[0]}_{next_log_index+1}.log" in log_files:
                        logger.warning("Skipping file {}".format(next_log_file),
                                       extra={'tenant': self.tenant_name})
                        self.imperva_last_log_file = next_log_file
                    else:
                        logger.info("Next file {} still does not exist.".format(next_log_file),
                                    extra={'tenant': self.tenant_name})

            self.frontend.imperva_last_log_file = self.imperva_last_log_file
            self.frontend.last_api_call = self.last_api_call
            self.finish()

        except Exception as err:
            raise ImpervaParseError(err)
