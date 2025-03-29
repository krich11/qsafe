#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
EST Client Script
Version: 1.6.2
Authors: Ken Rich, GrokZoid (Grok, xAI)
Date: March 27, 2025
Description:
This script implements an EST client per RFC 7030, handling enrollment and CA cert retrieval over HTTPS. Updated to enforce TLS 1.3 with a custom TLS13HTTPAdapter, ensuring client cert presentation for authentication. Includes fallback parsing with pyOpenSSL and improved logging.
"""

import base64
import logging
import requests
import tempfile
import os
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from asn1crypto import cms
from OpenSSL import crypto
import ssl
import socket
from requests.adapters import HTTPAdapter
import urllib3

logging.basicConfig(
    level=logging.DEBUG,
    format='%(levelname)s - %(filename)s:%(lineno)d - %(message)s',
    handlers=[logging.StreamHandler()]
)
logger = logging.getLogger(__name__)

class TLS13HTTPAdapter(HTTPAdapter):
    """Custom adapter to enforce TLS 1.3 and client cert presentation."""
    def __init__(self, cert_file=None, key_file=None, *args, **kwargs):
        self.cert_file = cert_file
        self.key_file = key_file
        super().__init__(*args, **kwargs)

    def init_poolmanager(self, *args, **kwargs):
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_3
        if self.cert_file and self.key_file:
            context.load_cert_chain(certfile=self.cert_file, keyfile=self.key_file)
            logger.debug("Loaded client cert into SSLContext: cert=%s, key=%s", self.cert_file, self.key_file)
        kwargs['ssl_context'] = context
        return super().init_poolmanager(*args, **kwargs)

class ESTClient:
    def __init__(self, est_server_url=None, client_cert_pem=None, client_key_pem=None, ca_certs_pem=None):
        self.session = requests.Session()
        self._temp_files = {}
        self.headers = {
            'Accept': 'application/pkcs7-mime',
            'Content-Type': 'application/pkcs10',
            'User-Agent': 'ESTClient/1.0 (RFC 7030 Compliant)'
        }
        self.base_url = None
        self.client_cert_pem = None
        self.client_key_pem = None
        self.ca_certs_pem = None

        # Set initial params if provided
        if est_server_url:
            self.set_server_url(est_server_url)
        if client_cert_pem:
            self.set_client_cert(client_cert_pem)
        if client_key_pem:
            self.set_client_key(client_key_pem)
        if ca_certs_pem:
            self.set_trust_anchor(ca_certs_pem)

        # Mount adapter with cert/key if available
        cert_file = self._temp_files.get('client_cert', (None, None))[0]
        key_file = self._temp_files.get('client_key', (None, None))[0]
        self.session.mount('https://', TLS13HTTPAdapter(cert_file=cert_file, key_file=key_file))
        logger.debug("Session configured with TLS 1.3-only adapter")

    def _create_temp_file(self, pem_data, key):
        if key in self._temp_files:
            path, old_content = self._temp_files[key]
            if old_content == pem_data and os.path.exists(path):
                logger.debug("Temp file for %s unchanged: %s", key, path)
                return path
            os.remove(path)
        with tempfile.NamedTemporaryFile(delete=False, mode='w') as f:
            f.write(pem_data)
            self._temp_files[key] = (f.name, pem_data)
        logger.debug("Created temp file for %s: %s", key, self._temp_files[key][0])
        return self._temp_files[key][0]

    def _remove_temp_file(self, key):
        if key in self._temp_files:
            path, _ = self._temp_files[key]
            if os.path.exists(path):
                os.remove(path)
            del self._temp_files[key]
            logger.debug("Removed temp file for %s", key)

    def _ensure_temp_files(self):
        if self.client_cert_pem:
            self._create_temp_file(self.client_cert_pem, 'client_cert')
        else:
            self._remove_temp_file('client_cert')
        if self.client_key_pem:
            self._create_temp_file(self.client_key_pem, 'client_key')
        else:
            self._remove_temp_file('client_key')
        if self.ca_certs_pem:
            self._create_temp_file(self.ca_certs_pem, 'ca_certs')
            self.session.verify = self._temp_files['ca_certs'][0]
        else:
            self._remove_temp_file('ca_certs')
            self.session.verify = True
        self._update_session_adapter()
        logger.debug("Ensured temp files: %s", {k: v[0] for k, v in self._temp_files.items()})

    def set_server_url(self, est_server_url):
        if not est_server_url or not isinstance(est_server_url, str):
            raise ValueError("EST server URL must be a non-empty string")
        self.base_url = est_server_url.rstrip('/')
        logger.info("EST server URL set to %s", self.base_url)

    def get_server_url(self):
        return self.base_url

    def set_client_cert(self, client_cert_pem):
        if client_cert_pem:
            try:
                cert = x509.load_pem_x509_certificate(client_cert_pem.encode('ascii'))
                self.client_cert_pem = client_cert_pem
                self._create_temp_file(client_cert_pem, 'client_cert')
                logger.debug("Client cert set: Subject=%s, temp file: %s", cert.subject, self._temp_files['client_cert'][0])
            except Exception as e:
                logger.exception("Invalid client cert PEM: %s", str(e))
                raise ValueError(f"Invalid client cert PEM: {e}")
        else:
            self.client_cert_pem = None
            self._remove_temp_file('client_cert')
            logger.info("Client cert cleared")
        self._update_session_adapter()

    def get_client_cert(self):
        return self.client_cert_pem

    def set_client_key(self, client_key_pem):
        if client_key_pem:
            try:
                key = serialization.load_pem_private_key(client_key_pem.encode('ascii'), password=None)
                self.client_key_pem = client_key_pem
                self._create_temp_file(client_key_pem, 'client_key')
                logger.debug("Client key set, temp file: %s", self._temp_files['client_key'][0])
            except Exception as e:
                logger.exception("Invalid client key PEM: %s", str(e))
                raise ValueError(f"Invalid client key PEM: {e}")
        else:
            self.client_key_pem = None
            self._remove_temp_file('client_key')
            logger.info("Client key cleared")
        self._update_session_adapter()

    def get_client_key(self):
        return self.client_key_pem

    def _update_session_adapter(self):
        cert_file = self._temp_files.get('client_cert', (None, None))[0]
        key_file = self._temp_files.get('client_key', (None, None))[0]
        if cert_file and key_file and os.path.exists(cert_file) and os.path.exists(key_file):
            self.session.mount('https://', TLS13HTTPAdapter(cert_file=cert_file, key_file=key_file))
            logger.info("Session adapter updated with cert file: %s and key file: %s", cert_file, key_file)
        else:
            self.session.mount('https://', TLS13HTTPAdapter())
            logger.debug("Session adapter reset: cert_file=%s, key_file=%s", cert_file, key_file)

    def set_trust_anchor(self, ca_certs_pem):
        if ca_certs_pem:
            try:
                certs = x509.load_pem_x509_certificates(ca_certs_pem.encode('ascii'))
                self.ca_certs_pem = ca_certs_pem
                self._create_temp_file(ca_certs_pem, 'ca_certs')
                self.session.verify = self._temp_files['ca_certs'][0]
                logger.debug("Trust anchor set with %d certs, temp file: %s", len(certs), self._temp_files['ca_certs'][0])
                for cert in certs:
                    logger.debug("Trust anchor cert: Subject=%s, Issuer=%s", cert.subject, cert.issuer)
            except Exception as e:
                logger.exception("Invalid CA certs PEM: %s", str(e))
                raise ValueError(f"Invalid CA certs PEM: {e}")
        else:
            self.ca_certs_pem = None
            self._remove_temp_file('ca_certs')
            self.session.verify = True
            logger.info("Trust anchor cleared, using system default")
        self._update_session_adapter()

    def get_trust_anchor(self):
        return self.ca_certs_pem

    def _handle_response(self, response):
        if response.status_code != 200:
            raise Exception(f"EST request failed: {response.status_code} {response.reason}")
        return response

    def get_cacerts(self):
        if not self.base_url:
            raise ValueError("EST server URL not set")
        self._ensure_temp_files()
        url = f"{self.base_url}/cacerts"
        logger.info("Requesting CA certs from %s", url)
        try:
            response = self.session.get(url, headers={'Accept': 'application/pkcs7-mime'})
            response = self._handle_response(response)
            pkcs7_der = base64.b64decode(response.content)
            try:
                pkcs7 = cms.ContentInfo.load(pkcs7_der)
                if pkcs7['content_type'].native != 'signed_data':
                    raise ValueError("Invalid PKCS#7 content type, expected 'signed_data'")
                signed_data = pkcs7['content']
                if 'certificates' not in signed_data or not signed_data['certificates']:
                    raise ValueError("No certs in PKCS#7 response")
                certs = [x509.load_der_x509_certificate(cert.chosen.dump()) for cert in signed_data['certificates']]
            except ValueError as e:
                if "signer_infos" in str(e):
                    logger.debug("Falling back to pyOpenSSL for certs-only parsing")
                    p7 = crypto.load_pkcs7_data(crypto.FILETYPE_ASN1, pkcs7_der)
                    certs = [x509.load_der_x509_certificate(crypto.dump_certificate(crypto.FILETYPE_ASN1, c))
                             for c in p7.get_certificates()]
                else:
                    raise
            pem_certs = "\n".join(cert.public_bytes(serialization.Encoding.PEM).decode('ascii') for cert in certs)
            logger.info("Retrieved %d CA certs", len(certs))
            return pem_certs
        except Exception as e:
            logger.exception("Error in get_cacerts: %s", str(e))
            raise

    def simple_enroll(self, csr_pem):
        if not self.base_url:
            raise ValueError("EST server URL not set")
        self._ensure_temp_files()
        url = f"{self.base_url}/simpleenroll"
        logger.info("Submitting enrollment request to %s", url)
        try:
            csr = x509.load_pem_x509_csr(csr_pem.encode('ascii'))
            if not csr.is_signature_valid:
                raise ValueError("Invalid CSR signature")
            csr_b64 = base64.b64encode(csr_pem.encode('ascii')).decode('ascii')
            cert_file = self._temp_files.get('client_cert', (None, None))[0]
            key_file = self._temp_files.get('client_key', (None, None))[0]
            logger.debug("Sending POST with cert=%s, key=%s", cert_file, key_file)
            response = self.session.post(
                url,
                data=csr_b64,
                headers=self.headers,
                # cert=(cert_file, key_file),  # Remove this; handled by adapter
                verify=self.session.verify if self.ca_certs_pem else True
            )
            response = self._handle_response(response)
            pkcs7_der = base64.b64decode(response.content)
            logger.debug("Raw PKCS#7 response (DER, hex): %s", pkcs7_der.hex()[:100] + "..." if len(pkcs7_der) > 50 else pkcs7_der.hex())

            try:
                cert = x509.load_pem_x509_certificate(response.content)
                logger.info("Response is a single PEM certificate")
                return cert.public_bytes(serialization.Encoding.PEM).decode('ascii')
            except ValueError:
                logger.debug("Response is not a raw PEM certificate, trying PKCS#7 parsing")

            try:
                pkcs7 = cms.ContentInfo.load(pkcs7_der)
                if pkcs7['content_type'].native != 'signed_data':
                    raise ValueError("Invalid PKCS#7 content type, expected 'signed_data'")
                signed_data = pkcs7['content']
                if 'certificates' not in signed_data or not signed_data['certificates']:
                    raise ValueError("No certs in PKCS#7 response")
                certs = [x509.load_der_x509_certificate(cert.chosen.dump()) for cert in signed_data['certificates']]
                logger.info("Parsed PKCS#7 with %d certificates", len(certs))
            except Exception as e:
                logger.debug("asn1crypto failed: %s, falling back to pyOpenSSL", str(e))
                p7 = crypto.load_pkcs7_data(crypto.FILETYPE_ASN1, pkcs7_der)
                certs = [x509.load_der_x509_certificate(crypto.dump_certificate(crypto.FILETYPE_ASN1, c))
                         for c in p7.get_certificates()]
                logger.info("Parsed PKCS#7 with pyOpenSSL, %d certificates", len(certs))

            cert_pem = certs[0].public_bytes(serialization.Encoding.PEM).decode('ascii')
            logger.info("Enrolled cert with serial number: %s", certs[0].serial_number)
            return cert_pem
        except Exception as e:
            logger.exception("Error in simple_enroll: %s", str(e))
            raise

if __name__ == "__main__":
    client = ESTClient("https://localhost:8443/.well-known/est")
    with open("ca_cert.pem", "r") as f:
        client.set_trust_anchor(f.read())
    try:
        ca_certs = client.get_cacerts()
        print(ca_certs)
    finally:
        client.close()



