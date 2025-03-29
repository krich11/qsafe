#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Utilities Module
Version: 1.0.1
Authors: Ken Rich
Date: March 24, 2025
Description:
This script performs utilitarian tasks related to this project, supporting PEM strings. Updated to load CA cert and key from filesystem for IDevID generation.
"""

import secrets
import base64
import datetime
import logging
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
import os

# Configure logging without timestamps
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s - %(filename)s:%(lineno)d - %(message)s'
)
logger = logging.getLogger(__name__)

def generate_key():
    """Generate a new RSA private key."""
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

def generate_self_signed_ca():
    """Generate a self-signed CA certificate and key."""
    ca_key = generate_key()
    ca_subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "Self-Signed CA")
    ])
    ca_cert = x509.CertificateBuilder().subject_name(ca_subject).issuer_name(ca_subject).public_key(
        ca_key.public_key()).serial_number(1).not_valid_before(
        datetime.datetime.utcnow()).not_valid_after(
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)).sign(ca_key, hashes.SHA256(), default_backend())
    return ca_key, ca_cert

def generate_idevid(serial_number, mac_address, filename=None, password=None):
    """Generate an IDevID certificate and related keys using a CA cert and key from the filesystem."""
    try:
        # Paths to CA certificate and key
        CA_CERT_FILE = "idevid_ca_cert.pem"
        CA_KEY_FILE = "idevid_ca_key.pem"

        # Check if CA files exist
        if not os.path.exists(CA_CERT_FILE):
            logger.error("CA certificate file %s not found.", CA_CERT_FILE)
            raise FileNotFoundError(f"{CA_CERT_FILE} missing")
        if not os.path.exists(CA_KEY_FILE):
            logger.error("CA key file %s not found.", CA_KEY_FILE)
            raise FileNotFoundError(f"{CA_KEY_FILE} missing")

        # Load the CA certificate
        with open(CA_CERT_FILE, "rb") as f:
            ca_cert_pem = f.read()
        ca_cert = x509.load_pem_x509_certificate(ca_cert_pem, default_backend())
        logger.info("Loaded CA certificate: Subject=%s", ca_cert.subject)

        # Load the CA private key (assuming no password for simplicity)
        with open(CA_KEY_FILE, "rb") as f:
            ca_key_pem = f.read()
        ca_key = serialization.load_pem_private_key(ca_key_pem, password=None, backend=default_backend())
        logger.info("Loaded CA private key")

        # Generate the IDevID private key
        key = generate_key()

        # Define the subject and SAN
        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"{serial_number}::{mac_address}")
        ])
        san = x509.SubjectAlternativeName([
            x509.DNSName(f"{serial_number}::{mac_address}")
        ])

        # Generate the CSR
        csr = x509.CertificateSigningRequestBuilder().subject_name(
            subject).add_extension(san, critical=False).sign(
            key, hashes.SHA256(), default_backend())

        # Generate the IDevID certificate signed by the loaded CA
        idevid_cert = x509.CertificateBuilder().subject_name(
            subject).issuer_name(ca_cert.subject).public_key(
            key.public_key()).serial_number(
            int.from_bytes(serial_number.encode(), 'big')).not_valid_before(
            datetime.datetime.utcnow()).not_valid_after(
            datetime.datetime.utcnow() + datetime.timedelta(days=365)).add_extension(
            san, critical=False).sign(ca_key, hashes.SHA256(), default_backend())

        logger.info("Generated IDevID certificate: Subject=%s, Issuer=%s", idevid_cert.subject, idevid_cert.issuer)
        return ca_key, ca_cert, key, csr, idevid_cert

    except Exception as e:
        logger.exception("An error occurred during IDevID generation: %s", str(e))
        raise

def log_certificate_details(cert):
    """Log the details of a certificate."""
    logger.info("Certificate Details:")
    logger.info("Subject: %s", cert.subject)
    logger.info("Issuer: %s", cert.issuer)
    logger.info("Serial Number: %s", cert.serial_number)
    logger.info("Not Before: %s", cert.not_valid_before_utc)
    logger.info("Not After: %s", cert.not_valid_after_utc)
    public_key_pem = cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
    logger.info("Public Key:\n%s", public_key_pem)



