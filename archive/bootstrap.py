#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
HMAC and CSR Processing Script
Version: 1.0.0
Authors: Ken Rich, Microsoft 365 Copilot
Date: March 24, 2025
Description:
This script performs various tasks related to HMAC generation, CSR creation, and validation.
It includes functions to generate HMACs, create CSRs with additional attributes, and validate HMACs.
Usage:
To be determined based on the subroutines and functionality added.
Dependencies:
- cryptography
- hashlib
- hmac
License:
[Your License Information]
"""
import argparse
import logging
from utils import generate_idevid, save_cert
from device import Device
from cryptography.hazmat.primitives import serialization

# Configure logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def parse_arguments():
    """
    Parse command line arguments.
    """
    parser = argparse.ArgumentParser(description="HMAC and CSR Processing Script")
    parser.add_argument("--password", type=str, default="aruba123", help="Password for P12 encryption")
    parser.add_argument("--serial_number", type=str, default="123456", help="Serial number of the device")
    parser.add_argument("--mac_address", type=str, default="00:11:22:33:44:55", help="MAC address of the device")
    return parser.parse_args()

def main(serial_number, mac_address, password):
    """
    Main function to orchestrate the HMAC and CSR processing tasks.
    """
    try:
        ca_key, ca_cert, idevid_key, csr, idevid_cert = generate_idevid(serial_number, mac_address)

        # Log certificate details
        logging.info("IDevID Certificate Details:")
        logging.info("Subject: %s", idevid_cert.subject)
        logging.info("Issuer: %s", idevid_cert.issuer)
        logging.info("Serial Number: %s", idevid_cert.serial_number)
        logging.info("Not Before: %s", idevid_cert.not_valid_before_utc)
        logging.info("Not After: %s", idevid_cert.not_valid_after_utc)
        public_key_pem = idevid_cert.public_bytes(serialization.Encoding.PEM).decode("utf-8")
        logging.info("Public Key:\n%s", public_key_pem)

        logging.info("Saving PKI package")
        save_cert(idevid_key, idevid_cert, "idevid")
        save_cert(ca_key, ca_cert, "ca")
        save_cert(idevid_key, idevid_cert, "idevid", password)
        save_cert(ca_key, ca_cert, "ca", password)

        device = Device()
        device.idevid_store_private_key(idevid_key)
        device.idevid_store_certificate(idevid_cert)
        device.set_serial_number(serial_number)
        device.set_mac_address(mac_address)
        device.save_to_file("device.json")
        device.load_from_file("device.json")

        logging.info("=" * 20)
        logging.info("Subject: %s", device.idevid_get_certificate().subject)

    except Exception as e:
        logging.error("An error occurred: %s", str(e))
        raise

if __name__ == "__main__":
    args = parse_arguments()
    main(args.serial_number, args.mac_address, args.password)

