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
__doc__ = 'Imperva API Parser'
__parser__ = 'IMPERVA'


import base64
import hashlib
import io
import logging
import requests
import zlib

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from django.conf import settings
from django.utils import timezone
from django.utils.translation import gettext_lazy as _
from toolkit.api_parser.api_parser import ApiParser

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

        rsa_private_key = serialization.load_pem_private_key(bytes(self.imperva_private_key, 'utf-8'))

        content_decrypted_sym_key = rsa_private_key.decrypt(
            base64.b64decode(bytearray(content_encrypted_sym_key, 'utf-8')),
            padding.PKCS1v15()
        ).decode('utf-8')

        aes_key = base64.b64decode(bytearray(content_decrypted_sym_key, "utf-8"))
        # aes_keysize = 8 * len(aes_key)

        iv = b'\x00' * 16
        cipher = Cipher(algorithms.AES(aes_key), modes.CBC(iv))
        decryptor = cipher.decryptor()
        file_content_decrypted = decryptor.update(file_log_content) + decryptor.finalize()

        uncompressed_and_decrypted_file_content = zlib.decompressobj().decompress(
            file_content_decrypted
        )

        if not self.validate_checksum(checksum, uncompressed_and_decrypted_file_content):
            raise ImpervaParseError(_("Invalid checksum"))

        return uncompressed_and_decrypted_file_content

    def __execute_query(self, url):
        logger.info(f"[{__parser__}]:execute_query: URL: {url}", extra={'frontend': str(self.frontend)})
        return requests.get(
            url,
            proxies=self.proxies,
            verify=self.api_parser_custom_certificate if self.api_parser_custom_certificate else self.api_parser_verify_ssl,
            auth=(self.imperva_api_id, self.imperva_api_key)
        )

    def _download_log_index(self):
        url = f"{self.imperva_base_url}logs.index"

        r = self.__execute_query(url)

        r.raise_for_status()
        log_files = [log for log in r.text.split('\n') if log]
        return log_files

    def get_file(self, filename):
        url = f"{self.imperva_base_url}{filename}"

        r = self.__execute_query(url)

        r.raise_for_status()

        # Let requests manage decompression
        r.raw.decode_content = True

        binary_stream = io.BytesIO()
        for chunk in r:
            binary_stream.write(chunk)

        binary_stream.seek(0)
        text_data = binary_stream.read()
        try:
            pos = text_data.index(b'|==|')
            binary_stream.seek(0)
            file_header = binary_stream.read(pos).decode('utf-8')

            binary_stream.seek(pos + 5)
            file_data = binary_stream.read()

            content = self.__decrypt_file(filename, file_header, file_data)
            return content
        except Exception as err:
            msg = f"Could not locate string '|==|' in stream: {text_data}"
            logger.error(f"[{__parser__}]:get_file: {msg}", extra={'frontend': str(self.frontend)})
            raise ImpervaParseError(err)

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
            self.imperva_last_log_file = self.frontend.imperva_last_log_file

            # Download log files index
            log_files = self._download_log_index()

            logger.info(f"[{__parser__}]:execute: Get logs from {self.imperva_last_log_file or 'the beginning of log index'}",
                        extra={'frontend': str(self.frontend)})

            # Get next file position
            if self.imperva_last_log_file in log_files:
                start_pos = log_files.index(self.imperva_last_log_file) + 1
            else:
                start_pos = 0

            # Download files
            if files_to_download := log_files[start_pos:]:
                logger.info(f"[{__parser__}]:execute: {len(files_to_download)} files to download", extra={'frontend': str(self.frontend)})

                for file in files_to_download:
                    if not self.evt_stop.is_set():
                        try:
                            self.update_lock()
                            logger.info(f"[{__parser__}]:execute: Downloading {file}", extra={'frontend': str(self.frontend)})
                            content = self.get_file(file)
                            data = content.split(b'\n')
                            self.write_to_file(data)
                        except Exception as e:
                            logger.exception(f"[{__parser__}]:execute: Cannot retrieve & decode file {file} : {e}",
                                             extra={'frontend': str(self.frontend)})
                        finally:
                            self.frontend.imperva_last_log_file = file
                            self.frontend.last_api_call = timezone.now()
                            self.frontend.save(update_fields=['imperva_last_log_file', 'last_api_call'])
            else:
                logger.info(f"[{__parser__}]:execute: No file to download",
                            extra={'frontend': str(self.frontend)})
        except Exception as err:
            raise ImpervaParseError(err)
