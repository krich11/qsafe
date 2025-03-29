#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
CLI script
Version: 1.8.4
Authors: Ken Rich, GrokZoid (Grok, xAI)
Date: March 28, 2025
Description:
This script implements a command-line interface to interact with the device management functions, using PEM strings for certificates and keys. Updated to store LDevID certificate and key from EST enrollment, added export command for certificates and keys, added clear command for LDevID data, attempts to load default.json on startup, enhanced show command to display CA certs, trust anchor, and detailed attributes for all certs and keys, fixed deprecation warnings by using not_valid_before_utc and not_valid_after_utc, added debug command to toggle debug logging with troubleshooting prints converted to debug logs, modified show cacerts to use stored CA certs, fixed debug toggle to affect root logger, updated do_enroll to include serial number, MAC address, index, and nonce in CSR with custom OIDs under PEN 47196 with proper DER encoding for OtherName using asn1crypto, fixed logging of UnrecognizedExtension values, and included a hidden command for fun.
"""

import cmd
from getpass import getpass
from device import Device
from utils import generate_idevid, log_certificate_details
from cryptography.hazmat.primitives import serialization
import base64
import cryptography
from cryptography import x509
from OpenSSL import crypto
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID, ObjectIdentifier
from cryptography.hazmat.primitives import hashes
import os
import logging
import random
from asn1crypto.core import OctetString, Sequence, ObjectIdentifier as ASN1ObjectIdentifier

# Configure logging without timestamps, applied to root logger
logging.basicConfig(
    level=logging.INFO,
    format='%(levelname)s - %(filename)s:%(lineno)d - %(message)s'
)
logger = logging.getLogger(__name__)

# Define a custom ASN.1 structure for OtherName
class OtherNameValue(Sequence):
    _fields = [
        ('type_id', ASN1ObjectIdentifier),
        ('value', OctetString, {'explicit': 0}),
    ]

class DeviceCLI(cmd.Cmd):
    intro = "Welcome to the Device CLI. Type help or ? to list commands.\n"
    prompt = "() "
    device = Device()

    def __init__(self):
        super().__init__()
        # Attempt to load default.json on startup
        default_file = "default.json"
        try:
            if os.path.exists(default_file):
                self.device.load_device_from_file(default_file)
                loaded_name = self.device.get_device_name() or "unnamed_device"
                logger.info("Loaded default.json: Name=%s, Serial Number=%s, MAC Address=%s",
                            loaded_name, self.device.get_serial_number(), self.device.get_mac_address())
                print(f"Found and loaded {default_file}: Name={loaded_name}, Serial Number={self.device.get_serial_number() or 'Not set'}, MAC Address={self.device.get_mac_address() or 'Not set'}")
                self.set_prompt(loaded_name)
            else:
                logger.info("No default.json found, starting with empty device")
        except Exception as e:
            logger.exception("Error loading default.json on startup: %s", str(e))
            print(f"Error loading {default_file} on startup: {str(e)}")

    def emptyline(self):
        pass

    def set_prompt(self, name):
        logger.info("Setting prompt to %s.", name)
        self.prompt = "(" + name + ") "

    def do_dump_properties(self, arg):
        "Dump the device class properties."
        self.device.dump_properties()

    def do_generate(self, arg):
        "Generate resources: generate [idevid]"
        args = arg.split()
        if len(args) == 1 and args[0] == "idevid":
            self.generate_idevid()
        else:
            print("Usage: generate [idevid]")

    def help_generate(self):
        print("Generate resources: generate [idevid]")
        print("  idevid: Generate an IDevID")

    def generate_idevid(self):
        "Generate IDevID"
        try:
            device_name = input("Enter Device Name: ")
            serial_number = input("Enter serial number: ")
            mac_address = input("Enter MAC address: ")
            filename = input("Enter path and filename for device persistent storage (JSON format): ")
            ca_key, ca_cert, idevid_key, csr, idevid_cert = generate_idevid(serial_number, mac_address)
            log_certificate_details(idevid_cert)
            self.device.idevid_store_private_key(idevid_key)
            self.device.idevid_store_certificate(idevid_cert)
            self.device.set_device_name(device_name)
            self.device.set_serial_number(serial_number)
            self.device.set_mac_address(mac_address)
            self.device.save_to_file(filename)
            logger.info("IDevID generated and saved to %s", filename)
            self.set_prompt(device_name)
        except Exception as e:
            logger.exception("Error generating IDevID: %s", str(e))
            print(f"Error generating IDevID: {str(e)}")

    def do_load(self, arg):
        "Load data from the filesystem: load [device | trust-anchor] [filename]"
        args = arg.split()
        if len(args) < 1:
            print("Usage: load [device | trust-anchor] [filename]")
            return
        target = args[0]
        try:
            if target == "device":
                if len(args) == 1:
                    logger.info("No filename provided, attempting default.json")
                    print("Usage: load device [<filename>]\nNote: When filename is omitted, default.json is attempted.")
                    filename = "./default.json"
                else:
                    filename = args[1]
                self.device.load_device_from_file(filename)
                loaded_name = self.device.get_device_name() or "unnamed_device"
                logger.info("Device loaded: Name=%s, Serial Number=%s, MAC Address=%s",
                            loaded_name, self.device.get_serial_number(), self.device.get_mac_address())
                print(f"Device loaded: Name={loaded_name}, Serial Number={self.device.get_serial_number() or 'Not set'}, MAC Address={self.device.get_mac_address() or 'Not set'}")
                self.set_prompt(loaded_name)
            elif target == "trust-anchor":
                if len(args) == 1:
                    logger.info("No filename provided, attempting ta.pem")
                    print("Usage: load trust-anchor [<filename>]\nNote: When filename is omitted, ta.pem is attempted.")
                    filename = "./ta.pem"
                else:
                    filename = args[1]
                self.device.load_trust_anchor_from_file(filename)
                logger.info("Trust anchor loaded from %s", filename)
                print(f"Trust anchor: {filename} successfully loaded.")
        except Exception as e:
            logger.exception("Unable to load file: %s", str(e))
            print(f"Unable to load file: {str(e)}")

    def help_load(self):
        print("Load data from file: load [device | trust-anchor] [filename]")
        print("  device: Load device data from JSON file")
        print("  trust-anchor: Load trust anchor from PEM file")

    def do_show(self, arg):
        "Show device information: show <property>"
        args = arg.split()
        if len(args) != 1:
            print("Usage: show <property>")
            return
        property = args[0]
        try:
            if property == "name":
                print(f"Device Name: {self.device.get_device_name()}")
            elif property == "serial_number":
                print(f"Serial Number: {self.device.get_serial_number()}")
            elif property == "mac_address":
                print(f"MAC Address: {self.device.get_mac_address()}")
            elif property == "idevid_cert":
                cert_pem = self.device.idevid_get_certificate()
                if cert_pem:
                    cert = x509.load_pem_x509_certificate(cert_pem.encode('ascii'))
                    print(f"IDevID Certificate Attributes:")
                    print(f"  Subject: {cert.subject}")
                    print(f"  Issuer: {cert.issuer}")
                    print(f"  Serial Number: {cert.serial_number}")
                    print(f"  Not Before: {cert.not_valid_before_utc}")
                    print(f"  Not After: {cert.not_valid_after_utc}")
                    print(f"  Public Key: {cert.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode('ascii')}")
                    print(f"IDevID Certificate PEM:\n{cert_pem}")
                else:
                    print("No IDevID certificate available")
            elif property == "idevid_key":
                key_pem = self.device.idevid_get_private_key()
                if key_pem:
                    key = serialization.load_pem_private_key(key_pem.encode('ascii'), password=None)
                    print(f"IDevID Private Key Attributes:")
                    print(f"  Key Size: {key.key_size} bits")
                    print(f"  Public Key: {key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode('ascii')}")
                    print(f"IDevID Private Key PEM:\n{key_pem}")
                else:
                    print("No IDevID private key available")
            elif property == "ldevid_cert":
                cert_pem = self.device.ldevid_get_certificate()
                if cert_pem:
                    cert = x509.load_pem_x509_certificate(cert_pem.encode('ascii'))
                    print(f"LDevID Certificate Attributes:")
                    print(f"  Subject: {cert.subject}")
                    print(f"  Issuer: {cert.issuer}")
                    print(f"  Serial Number: {cert.serial_number}")
                    print(f"  Not Before: {cert.not_valid_before_utc}")
                    print(f"  Not After: {cert.not_valid_after_utc}")
                    print(f"  Public Key: {cert.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode('ascii')}")
                    print(f"LDevID Certificate PEM:\n{cert_pem}")
                else:
                    print("No LDevID certificate available")
            elif property == "ldevid_key":
                key_pem = self.device.ldevid_get_private_key()
                if key_pem:
                    key = serialization.load_pem_private_key(key_pem.encode('ascii'), password=None)
                    print(f"LDevID Private Key Attributes:")
                    print(f"  Key Size: {key.key_size} bits")
                    print(f"  Public Key: {key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode('ascii')}")
                    print(f"LDevID Private Key PEM:\n{key_pem}")
                else:
                    print("No LDevID private key available")
            elif property == "cacerts":
                cacerts_pem = self.device.get_cacerts()
                if cacerts_pem:
                    # Split PEM into individual certificates if multiple are present
                    certs = []
                    current_cert = []
                    for line in cacerts_pem.splitlines():
                        if line.startswith("-----BEGIN CERTIFICATE-----"):
                            if current_cert:
                                certs.append("\n".join(current_cert))
                            current_cert = [line]
                        elif line.startswith("-----END CERTIFICATE-----"):
                            current_cert.append(line)
                            certs.append("\n".join(current_cert))
                            current_cert = []
                        elif current_cert:
                            current_cert.append(line)
                    if current_cert:  # Handle any leftover
                        certs.append("\n".join(current_cert))
                    
                    print(f"Stored CA Certificates Bundle ({len(certs)} certificates):")
                    for i, cert_pem in enumerate(certs, 1):
                        cert = x509.load_pem_x509_certificate(cert_pem.encode('ascii'))
                        print(f"Certificate {i} Attributes:")
                        print(f"  Subject: {cert.subject}")
                        print(f"  Issuer: {cert.issuer}")
                        print(f"  Serial Number: {cert.serial_number}")
                        print(f"  Not Before: {cert.not_valid_before_utc}")
                        print(f"  Not After: {cert.not_valid_after_utc}")
                        print(f"  Public Key: {cert.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode('ascii')}")
                        print(f"Certificate {i} PEM:\n{cert_pem}")
                else:
                    print("No stored CA certificates available (use 'cacerts' command to retrieve)")
            elif property == "trust_anchor":
                trust_anchor_pem = self.device.trust_anchor_pem
                if trust_anchor_pem:
                    cert = x509.load_pem_x509_certificate(trust_anchor_pem.encode('ascii'))
                    print(f"Trust Anchor Attributes:")
                    print(f"  Subject: {cert.subject}")
                    print(f"  Issuer: {cert.issuer}")
                    print(f"  Serial Number: {cert.serial_number}")
                    print(f"  Not Before: {cert.not_valid_before_utc}")
                    print(f"  Not After: {cert.not_valid_after_utc}")
                    print(f"  Public Key: {cert.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode('ascii')}")
                    print(f"Trust Anchor PEM:\n{trust_anchor_pem}")
                else:
                    print("No trust anchor available")
            elif property == "all":
                print(f"Device Name: {self.device.get_device_name()}")
                print(f"Serial Number: {self.device.get_serial_number()}")
                print(f"MAC Address: {self.device.get_mac_address()}")
                
                cert_pem = self.device.idevid_get_certificate()
                if cert_pem:
                    cert = x509.load_pem_x509_certificate(cert_pem.encode('ascii'))
                    print(f"IDevID Certificate Attributes:")
                    print(f"  Subject: {cert.subject}")
                    print(f"  Issuer: {cert.issuer}")
                    print(f"  Serial Number: {cert.serial_number}")
                    print(f"  Not Before: {cert.not_valid_before_utc}")
                    print(f"  Not After: {cert.not_valid_after_utc}")
                    print(f"  Public Key: {cert.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode('ascii')}")
                    print(f"IDevID Certificate PEM:\n{cert_pem}")
                
                key_pem = self.device.idevid_get_private_key()
                if key_pem:
                    key = serialization.load_pem_private_key(key_pem.encode('ascii'), password=None)
                    print(f"IDevID Private Key Attributes:")
                    print(f"  Key Size: {key.key_size} bits")
                    print(f"  Public Key: {key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode('ascii')}")
                    print(f"IDevID Private Key PEM:\n{key_pem}")
                
                cert_pem = self.device.ldevid_get_certificate()
                if cert_pem:
                    cert = x509.load_pem_x509_certificate(cert_pem.encode('ascii'))
                    print(f"LDevID Certificate Attributes:")
                    print(f"  Subject: {cert.subject}")
                    print(f"  Issuer: {cert.issuer}")
                    print(f"  Serial Number: {cert.serial_number}")
                    print(f"  Not Before: {cert.not_valid_before_utc}")
                    print(f"  Not After: {cert.not_valid_after_utc}")
                    print(f"  Public Key: {cert.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode('ascii')}")
                    print(f"LDevID Certificate PEM:\n{cert_pem}")
                
                key_pem = self.device.ldevid_get_private_key()
                if key_pem:
                    key = serialization.load_pem_private_key(key_pem.encode('ascii'), password=None)
                    print(f"LDevID Private Key Attributes:")
                    print(f"  Key Size: {key.key_size} bits")
                    print(f"  Public Key: {key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode('ascii')}")
                    print(f"LDevID Private Key PEM:\n{key_pem}")
            else:
                print(f"Unknown property: {property}")
        except Exception as e:
            logger.exception("Error showing property %s: %s", property, str(e))
            print(f"Error showing {property}: {str(e)}")

    def help_show(self):
        print("Show device information: show <property>")
        print("  name: Show the device's name")
        print("  serial_number: Show the device's serial number")
        print("  mac_address: Show the device's MAC address")
        print("  idevid_cert: Show the device's IDevID certificate with attributes")
        print("  idevid_key: Show the device's IDevID private key with attributes")
        print("  ldevid_cert: Show the device's LDevID certificate with attributes")
        print("  ldevid_key: Show the device's LDevID private key with attributes")
        print("  cacerts: Show the stored CA certificates bundle with attributes")
        print("  trust_anchor: Show the trust anchor certificate with attributes")
        print("  all: Show all device information")

    def do_enroll(self, arg):
        "Enroll the device with an EST server"
        logger.info("Enrolling on EST Server URL: %s", self.device.est.get_server_url())
        print(f"Enrolling on EST Server URL: {self.device.est.get_server_url()}")
        try:
            logger.debug("Setting client cert: %s", self.device.idevid_get_certificate())
            self.device.est.set_client_cert(self.device.idevid_get_certificate())
            logger.debug("Setting client key: %s", self.device.idevid_get_private_key())
            self.device.est.set_client_key(self.device.idevid_get_private_key())
            logger.debug("Setting trust anchor: %s", self.device.trust_anchor_pem)
            self.device.est.set_trust_anchor(self.device.trust_anchor_pem)

            # Generate new key for LDevID
            key = rsa.generate_private_key(public_exponent=65537, key_size=2048)

            # Gather device attributes
            device_name = self.device.get_device_name()
            serial_number = self.device.get_serial_number() or "N/A"
            mac_address = self.device.get_mac_address() or "00:00:00:00:00:00"
            index = random.randint(0, 4061)  # Random index for now; could be an arg
            nonce = self.device.get_entropy(index, 32)  # 32 bytes raw entropy

            # Define custom OIDs under PEN 47196
            NONCE_OID = ObjectIdentifier("1.3.6.1.4.1.47196.1")  # Nonce
            INDEX_OID = ObjectIdentifier("1.3.6.1.4.1.47196.2")  # Index
            MAC_OID = ObjectIdentifier("1.3.6.1.5.5.7.8.4")      # Hardware module name (RFC 4108)

            # DER-encode the MAC address as an OtherName value
            mac_value = OtherNameValue({
                'type_id': MAC_OID.dotted_string,
                'value': OctetString(mac_address.encode('ascii'))
            })
            mac_der = mac_value.dump()

            # Build CSR
            csr_builder = x509.CertificateSigningRequestBuilder()
            csr_builder = csr_builder.subject_name(
                x509.Name([
                    x509.NameAttribute(NameOID.COMMON_NAME, device_name),
                    x509.NameAttribute(NameOID.SERIAL_NUMBER, serial_number),
                ])
            )
            csr_builder = csr_builder.add_extension(
                x509.SubjectAlternativeName([
                    x509.OtherName(MAC_OID, mac_der)
                ]),
                critical=False
            )
            csr_builder = csr_builder.add_extension(
                x509.UnrecognizedExtension(NONCE_OID, nonce),
                critical=False
            )
            csr_builder = csr_builder.add_extension(
                x509.UnrecognizedExtension(INDEX_OID, index.to_bytes(2, byteorder='big')),
                critical=False
            )
            csr = csr_builder.sign(key, hashes.SHA256())
            csr_pem = csr.public_bytes(serialization.Encoding.PEM).decode('ascii')

            # Log CSR details
            csr_obj = x509.load_pem_x509_csr(csr_pem.encode('ascii'))
            csr_text = f"Certificate Request:\n  Subject: {csr_obj.subject}\n  Public Key: {csr_obj.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode('ascii')}"
            extensions = csr_obj.extensions
            if extensions:
                csr_text += "\n  Extensions:"
                for ext in extensions:
                    if ext.oid == MAC_OID:
                        # Decode the DER to display the MAC
                        decoded_mac = OtherNameValue.load(ext.value.value)
                        mac_value = decoded_mac['value'].native.decode('ascii')
                        csr_text += f"\n    HardwareModuleName ({ext.oid}): {mac_value}"
                    elif ext.oid == NONCE_OID:
                        csr_text += f"\n    Nonce ({ext.oid}): {ext.value.value.hex()}"
                    elif ext.oid == INDEX_OID:
                        csr_text += f"\n    Index ({ext.oid}): {int.from_bytes(ext.value.value, 'big')}"
                    else:
                        csr_text += f"\n    {ext.oid._name}: {ext.value}"
            logger.info("Generated CSR for enrollment:\n%s", csr_text)

            # Enroll and store
            cert_pem = self.device.est.simple_enroll(csr_pem)
            self.device.ldevid_store_private_key(key)
            self.device.ldevid_store_certificate(cert_pem)
            logger.info("Enrollment successful")
            print(f"Enrollment successful. New LDevID certificate:\n{cert_pem}")
        except Exception as e:
            logger.exception("Error during enrollment: %s", str(e))
            print(f"Error during enrollment: {str(e)}")

    def do_cacerts(self, arg):
        "Retrieve CA certificates from the EST server and store them"
        try:
            self.device.est.set_trust_anchor(self.device.trust_anchor_pem)
            logger.info("Trying to reach out to the EST server")
            print("Trying to reach out to the EST server")
            logger.debug("Using trust anchor: %s", self.device.est.get_trust_anchor())
            cacerts = self.device.est.get_cacerts()
            self.device.store_cacerts(cacerts)
            logger.info("Retrieved and stored CA certificates")
            print(f"Retrieved and stored CA certificates:\n{cacerts}")
        except Exception as e:
            logger.exception("Error retrieving CA certificates: %s", str(e))
            print(f"Error retrieving CA certificates: {str(e)}")

    def do_set(self, arg):
        "Set device property: set <property> <value>"
        args = arg.split(maxsplit=1)
        if len(args) != 2:
            print("Usage: set <property> <value>")
            return
        property, value = args
        try:
            if property == "name":
                self.device.set_device_name(value)
                self.set_prompt(value)
                print(f"Device name set to {value}")
            elif property == "serial_number":
                self.device.set_serial_number(value)
                print(f"Serial Number set to {value}")
            elif property == "mac_address":
                self.device.set_mac_address(value)
                print(f"MAC Address set to {value}")
            elif property == "est_server_url":
                self.device.est.set_server_url(value)
                print(f"EST Server URL set to: {value}")
            else:
                print(f"Unknown property: {property}")
        except Exception as e:
            logger.exception("Error setting property: %s", str(e))
            print(f"Error setting property: {str(e)}")

    def help_set(self):
        print("Set device property: set <property> <value>")
        print("  name: Set the device's name")
        print("  serial_number: Set the device's serial number")
        print("  mac_address: Set the device's MAC address")
        print("  est_server_url: Set the EST server URL")

    def do_save(self, arg):
        "Save device to file: save <filename>"
        filename = arg.strip()
        if not filename:
            logger.info("No filename provided, using default.json")
            print("Usage: save [<filename>]\nNote: When filename is omitted, default.json is attempted.")
            filename = "./default.json"
        try:
            self.device.save_to_file(filename)
            logger.info("Device saved to %s", filename)
            print(f"Device saved to {filename}")
        except Exception as e:
            logger.exception("Error saving device: %s", str(e))
            print(f"Error saving device: {str(e)}")

    def help_save(self):
        print("Save device to file: save <filename>")

    def do_export(self, arg):
        "Export certificates or keys to filesystem: export [certs | keys]"
        args = arg.split()
        if len(args) != 1 or args[0] not in ["certs", "keys"]:
            print("Usage: export [certs | keys]")
            return
        target = args[0]
        device_name = self.device.get_device_name() or "unnamed_device"
        try:
            if target == "certs":
                idevid_cert = self.device.idevid_get_certificate()
                if idevid_cert:
                    filename = f"{device_name}-idevid-cert.pem"
                    with open(filename, 'w') as f:
                        f.write(idevid_cert)
                    logger.info("Exported IDevID certificate to %s", filename)
                    print(f"Exported IDevID certificate to {filename}")
                else:
                    logger.warning("No IDevID certificate to export")
                    print("No IDevID certificate to export")
                
                ldevid_cert = self.device.ldevid_get_certificate()
                if ldevid_cert:
                    filename = f"{device_name}-ldevid-cert.pem"
                    with open(filename, 'w') as f:
                        f.write(ldevid_cert)
                    logger.info("Exported LDevID certificate to %s", filename)
                    print(f"Exported LDevID certificate to {filename}")
                else:
                    logger.warning("No LDevID certificate to export")
                    print("No LDevID certificate to export")
            
            elif target == "keys":
                idevid_key = self.device.idevid_get_private_key()
                if idevid_key:
                    filename = f"{device_name}-idevid-key.pem"
                    with open(filename, 'w') as f:
                        f.write(idevid_key)
                    logger.info("Exported IDevID private key to %s", filename)
                    print(f"Exported IDevID private key to {filename}")
                else:
                    logger.warning("No IDevID private key to export")
                    print("No IDevID private key to export")
                
                ldevid_key = self.device.ldevid_get_private_key()
                if ldevid_key:
                    filename = f"{device_name}-ldevid-key.pem"
                    with open(filename, 'w') as f:
                        f.write(ldevid_key)
                    logger.info("Exported LDevID private key to %s", filename)
                    print(f"Exported LDevID private key to {filename}")
                else:
                    logger.warning("No LDevID private key to export")
                    print("No LDevID private key to export")
        except Exception as e:
            logger.exception("Error exporting %s: %s", target, str(e))
            print(f"Error exporting {target}: {str(e)}")

    def help_export(self):
        print("Export certificates or keys to filesystem: export [certs | keys]")
        print("  certs: Export IDevID and LDevID certificates as <name>-<idevid/ldevid>-cert.pem")
        print("  keys: Export IDevID and LDevID private keys as <name>-<idevid/ldevid>-key.pem")

    def do_clear(self, arg):
        "Clear LDevID certificate and private key: clear ldevid"
        args = arg.split()
        if len(args) != 1 or args[0] != "ldevid":
            print("Usage: clear ldevid")
            return
        try:
            self.device.clear_ldevid()
            logger.info("LDevID certificate and private key cleared")
            print("LDevID certificate and private key cleared")
        except Exception as e:
            logger.exception("Error clearing LDevID: %s", str(e))
            print(f"Error clearing LDevID: {str(e)}")

    def help_clear(self):
        print("Clear LDevID certificate and private key: clear ldevid")

    def do_debug(self, arg):
        "Toggle debug logging: debug [on | off]"
        args = arg.split()
        if len(args) != 1 or args[0] not in ["on", "off"]:
            print("Usage: debug [on | off]")
            return
        root_logger = logging.getLogger()
        if args[0] == "on":
            root_logger.setLevel(logging.DEBUG)
            logger.info("Debug logging enabled")
            print("Debug logging enabled")
        else:
            root_logger.setLevel(logging.INFO)
            logger.info("Debug logging disabled")
            print("Debug logging disabled")

    def help_debug(self):
        print("Toggle debug logging: debug [on | off]")
        print("  on: Enable debug-level logging")
        print("  off: Disable debug-level logging (default)")

    def do_42(self, arg):
        "Hidden command: What's the meaning of life, the universe, and everything?"
        print("Elon’s Tesla just towed the Hitchhiker’s Guide at 88 mph—42’s the answer, but the question’s still buffering on Mars. Don’t panic, the Boring Company’s digging deeper!")

    def do_exit(self, arg):
        "Exit the CLI"
        logger.info("Exiting CLI")
        print("Exiting.")
        return True

    def help_exit(self):
        print("Exit the CLI")

if __name__ == "__main__":
    DeviceCLI().cmdloop()



