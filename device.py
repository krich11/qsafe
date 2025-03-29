#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Device class script
Version: 1.5.1
Authors: Ken Rich, GrokZoid (Grok, xAI)
Date: March 28, 2025
Description:
This script defines the Device class used for device management, standardizing on PEM strings for certificates and keys, with a storage_key for future use. Updated to store LDevID certificate and key from EST enrollment, added method to clear LDevID data, added storage for CA certificates retrieved from EST server, added get_entropy method to return raw bytes from the entropy property based on index, and updated version for consistency with CLI enhancements.
"""

import json
import os
import secrets
import logging
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.backends import default_backend
from est import ESTClient

# Configure logging without timestamps
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s - %(filename)s:%(lineno)d - %(message)s'
)
logger = logging.getLogger(__name__)

class Device:
    def __init__(self):
        self.est = ESTClient()
        self.device_name = "device"
        self.idevid_private_key = None  # Plain PEM string
        self.idevid_certificate = None  # PEM string
        self.ldevid_private_key = None  # Plain PEM string
        self.ldevid_certificate = None  # PEM string
        self.trust_anchor_pem = None    # PEM string
        self.cacerts_pem = None         # PEM string for CA certificates bundle
        self.serial_number = None
        self.mac_address = None
        self.entropy = secrets.token_bytes(4096)  # 4096 bytes of random data
        self.storage_key = secrets.token_bytes(32)  # 256-bit key, unused for now

    def set_device_name(self, name):
        self.device_name = name

    def get_device_name(self):
        return self.device_name

    def idevid_store_private_key(self, private_key):
        """Store the IDevID private key as a plain PEM string."""
        try:
            if not isinstance(private_key, rsa.RSAPrivateKey):
                raise ValueError("Private key must be an RSAPrivateKey object")
            pem_key = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            self.idevid_private_key = pem_key
            logger.debug("Stored IDevID private key")
        except Exception as e:
            logger.exception("Error storing IDevID private key: %s", str(e))
            raise

    def idevid_store_certificate(self, certificate):
        """Store the IDevID certificate as a PEM string."""
        try:
            if isinstance(certificate, x509.Certificate):
                self.idevid_certificate = certificate.public_bytes(
                    serialization.Encoding.PEM
                ).decode('utf-8')
            elif isinstance(certificate, bytes):
                self.idevid_certificate = certificate.decode('utf-8')
            elif isinstance(certificate, str):
                self.idevid_certificate = certificate
            else:
                raise ValueError("Certificate must be an x509.Certificate, bytes, or str")
            logger.debug("Stored IDevID certificate")
        except Exception as e:
            logger.exception("Error storing IDevID certificate: %s", str(e))
            raise

    def idevid_get_private_key(self):
        """Retrieve the IDevID private key as a PEM string."""
        try:
            if not self.idevid_private_key:
                logger.debug("No IDevID private key available")
                return None
            if not isinstance(self.idevid_private_key, str):
                raise ValueError(f"Stored private key must be a string, got {type(self.idevid_private_key)}")
            if not self.idevid_private_key.startswith("-----BEGIN RSA PRIVATE KEY-----"):
                raise ValueError("Stored private key is not a valid PEM string")
            logger.debug("Retrieved IDevID private key")
            return self.idevid_private_key
        except Exception as e:
            logger.exception("Error retrieving IDevID private key: %s", str(e))
            raise

    def idevid_get_certificate(self):
        """Retrieve the IDevID certificate as a PEM string."""
        return self.idevid_certificate

    def ldevid_store_private_key(self, private_key):
        """Store the LDevID private key as a plain PEM string."""
        try:
            if not isinstance(private_key, rsa.RSAPrivateKey):
                raise ValueError("Private key must be an RSAPrivateKey object")
            pem_key = private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ).decode('utf-8')
            self.ldevid_private_key = pem_key
            logger.debug("Stored LDevID private key")
        except Exception as e:
            logger.exception("Error storing LDevID private key: %s", str(e))
            raise

    def ldevid_store_certificate(self, certificate):
        """Store the LDevID certificate as a PEM string."""
        try:
            if isinstance(certificate, x509.Certificate):
                self.ldevid_certificate = certificate.public_bytes(
                    serialization.Encoding.PEM
                ).decode('utf-8')
            elif isinstance(certificate, bytes):
                self.ldevid_certificate = certificate.decode('utf-8')
            elif isinstance(certificate, str):
                self.ldevid_certificate = certificate
            else:
                raise ValueError("Certificate must be an x509.Certificate, bytes, or str")
            logger.debug("Stored LDevID certificate")
        except Exception as e:
            logger.exception("Error storing LDevID certificate: %s", str(e))
            raise

    def ldevid_get_private_key(self):
        """Retrieve the LDevID private key as a PEM string."""
        try:
            if not self.ldevid_private_key:
                logger.debug("No LDevID private key available")
                return None
            if not isinstance(self.ldevid_private_key, str):
                raise ValueError(f"Stored private key must be a string, got {type(self.ldevid_private_key)}")
            if not self.ldevid_private_key.startswith("-----BEGIN RSA PRIVATE KEY-----"):
                raise ValueError("Stored private key is not a valid PEM string")
            logger.debug("Retrieved LDevID private key")
            return self.ldevid_private_key
        except Exception as e:
            logger.exception("Error retrieving LDevID private key: %s", str(e))
            raise

    def ldevid_get_certificate(self):
        """Retrieve the LDevID certificate as a PEM string."""
        return self.ldevid_certificate

    def clear_ldevid(self):
        """Clear the LDevID certificate and private key."""
        try:
            self.ldevid_certificate = None
            self.ldevid_private_key = None
            logger.info("LDevID certificate and private key cleared")
        except Exception as e:
            logger.exception("Error clearing LDevID data: %s", str(e))
            raise

    def store_cacerts(self, cacerts_pem):
        """Store the CA certificates bundle as a PEM string."""
        try:
            if not isinstance(cacerts_pem, str):
                raise ValueError("CA certificates must be a PEM string")
            self.cacerts_pem = cacerts_pem
            logger.debug("Stored CA certificates")
        except Exception as e:
            logger.exception("Error storing CA certificates: %s", str(e))
            raise

    def get_cacerts(self):
        """Retrieve the stored CA certificates bundle as a PEM string."""
        return self.cacerts_pem

    def set_serial_number(self, serial_number):
        self.serial_number = serial_number

    def set_mac_address(self, mac_address):
        self.mac_address = mac_address

    def get_serial_number(self):
        return self.serial_number

    def get_mac_address(self):
        return self.mac_address

    def get_entropy(self, index, length=32):
        """
        Retrieve raw entropy bytes from the stored entropy property based on an index.
        
        Args:
            index (int): Index from 0 to 4061 to select entropy slice.
            length (int): Length of entropy in bytes (default 32).
        
        Returns:
            bytes: Raw bytes from the entropy pool.
        
        Raises:
            ValueError: If index is out of range or length is invalid or exceeds bounds.
        """
        if not 0 <= index <= 4061:
            raise ValueError("Index must be between 0 and 4061")
        if length <= 0:
            raise ValueError("Length must be positive")
        if index + length > 4096:
            raise ValueError(f"Requested entropy slice (index={index}, length={length}) exceeds entropy pool size (4096 bytes)")
        
        # Pull raw bytes from the entropy pool
        start = index
        entropy = self.entropy[start:start + length]
        logger.debug("Retrieved %d bytes of raw entropy from index %d", length, index)
        return entropy

    def save_to_file(self, filename):
        """Save the device properties to a JSON file with PEM strings."""
        try:
            data = {
                "device_name": self.device_name,
                "serial_number": self.serial_number,
                "mac_address": self.mac_address,
                "est_server_url": self.est.get_server_url(),
                "storage_key": base64.b64encode(self.storage_key).decode('utf-8'),
                "idevid_private_key": self.idevid_private_key,  # Plain PEM string
                "idevid_certificate": self.idevid_certificate,  # PEM string
                "ldevid_private_key": self.ldevid_private_key,  # Plain PEM string
                "ldevid_certificate": self.ldevid_certificate,  # PEM string
                "trust_anchor_pem": self.trust_anchor_pem,      # PEM string
                "cacerts_pem": self.cacerts_pem,                # PEM string
                "entropy": base64.b64encode(self.entropy).decode('utf-8'),
            }
            with open(filename, 'w') as f:
                json.dump(data, f, indent=4)
            logger.debug("Device properties saved to %s", filename)
        except Exception as e:
            logger.exception("Error saving to file: %s", str(e))
            raise

    def load_device_from_file(self, filename):
        """Load device properties from a JSON file, with warnings for missing fields."""
        try:
            if not os.path.exists(filename):
                raise FileNotFoundError(f"{filename} does not exist")
            with open(filename, 'r') as f:
                data = json.load(f)

            self.device_name = data.get("device_name", self.device_name)
            if not self.device_name:
                logger.warning("No device_name found in %s, using default: %s", filename, self.device_name)

            self.serial_number = data.get("serial_number")
            if "serial_number" not in data or data["serial_number"] is None:
                logger.warning("No serial_number found in %s", filename)

            self.mac_address = data.get("mac_address")
            if "mac_address" not in data or data["mac_address"] is None:
                logger.warning("No mac_address found in %s", filename)

            est_server_url = data.get("est_server_url")
            if est_server_url:
                self.est.set_server_url(est_server_url)
            else:
                logger.warning("No est_server_url found in %s, EST operations may fail until set", filename)

            storage_key = data.get("storage_key")
            if storage_key:
                try:
                    self.storage_key = base64.b64decode(storage_key)
                except Exception as e:
                    logger.warning("Invalid storage_key in %s, regenerating: %s", filename, str(e))
                    self.storage_key = secrets.token_bytes(32)
            else:
                logger.warning("No storage_key found in %s, regenerating", filename)
                self.storage_key = secrets.token_bytes(32)

            self.idevid_private_key = data.get("idevid_private_key")
            if self.idevid_private_key is not None and not isinstance(self.idevid_private_key, str):
                logger.warning("Invalid idevid_private_key type in %s, ignoring: got %s", filename, type(self.idevid_private_key))
                self.idevid_private_key = None
            elif self.idevid_private_key and not self.idevid_private_key.startswith("-----BEGIN RSA PRIVATE KEY-----"):
                logger.warning("idevid_private_key in %s is not a valid PEM string, ignoring", filename)
                self.idevid_private_key = None
            if "idevid_private_key" not in data or data["idevid_private_key"] is None:
                logger.warning("No idevid_private_key found in %s", filename)

            self.idevid_certificate = data.get("idevid_certificate")
            if "idevid_certificate" not in data or data["idevid_certificate"] is None:
                logger.warning("No idevid_certificate found in %s", filename)

            self.ldevid_private_key = data.get("ldevid_private_key")
            if self.ldevid_private_key is not None and not isinstance(self.ldevid_private_key, str):
                logger.warning("Invalid ldevid_private_key type in %s, ignoring: got %s", filename, type(self.ldevid_private_key))
                self.ldevid_private_key = None
            elif self.ldevid_private_key and not self.ldevid_private_key.startswith("-----BEGIN RSA PRIVATE KEY-----"):
                logger.warning("ldevid_private_key in %s is not a valid PEM string, ignoring", filename)
                self.ldevid_private_key = None
            if "ldevid_private_key" not in data or data["ldevid_private_key"] is None:
                logger.warning("No ldevid_private_key found in %s", filename)

            self.ldevid_certificate = data.get("ldevid_certificate")
            if "ldevid_certificate" not in data or data["ldevid_certificate"] is None:
                logger.warning("No ldevid_certificate found in %s", filename)

            self.trust_anchor_pem = data.get("trust_anchor_pem")
            if "trust_anchor_pem" not in data or data["trust_anchor_pem"] is None:
                logger.warning("No trust_anchor_pem found in %s", filename)

            self.cacerts_pem = data.get("cacerts_pem")
            if "cacerts_pem" not in data or data["cacerts_pem"] is None:
                logger.warning("No cacerts_pem found in %s", filename)

            entropy = data.get("entropy")
            if entropy:
                try:
                    self.entropy = base64.b64decode(entropy)
                except Exception as e:
                    logger.warning("Invalid entropy in %s, regenerating: %s", filename, str(e))
                    self.entropy = secrets.token_bytes(4096)
            else:
                logger.warning("No entropy found in %s, regenerating", filename)
                self.entropy = secrets.token_bytes(4096)

            logger.debug("Device properties loaded from %s", filename)
        except Exception as e:
            logger.exception("Error loading from file: %s", str(e))
            raise

    def load_trust_anchor_from_file(self, filename):
        """Load the trust anchor from a PEM file as a string."""
        try:
            if not os.path.exists(filename):
                raise FileNotFoundError(f"{filename} does not exist")
            with open(filename, 'r') as f:
                self.trust_anchor_pem = f.read()
            logger.debug("Trust anchor loaded from %s", filename)
        except Exception as e:
            logger.exception("Error loading trust anchor: %s", str(e))
            raise

    def dump_properties(self):
        """Print device properties for debugging."""
        try:
            properties = {
                "device_name": str(self.device_name),
                "serial_number": str(self.serial_number),
                "mac_address": str(self.mac_address),
                "est_server_url": self.est.get_server_url(),
                "storage_key (b64)": str(base64.b64encode(self.storage_key).decode('utf-8')),
                "idevid_private_key": str(self.idevid_private_key),
                "idevid_certificate": str(self.idevid_certificate),
                "ldevid_private_key": str(self.ldevid_private_key),
                "ldevid_certificate": str(self.ldevid_certificate),
                "trust_anchor_pem": str(self.trust_anchor_pem),
                "cacerts_pem": str(self.cacerts_pem),
                "entropy (b64)": str(base64.b64encode(self.entropy).decode('utf-8')),
            }
            for key, value in properties.items():
                print(f"{key}: \n==================\n{value}\n")
        except Exception as e:
            logger.exception("Error dumping properties: %s", str(e))
            raise



