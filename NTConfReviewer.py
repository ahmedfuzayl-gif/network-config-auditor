#!/usr/bin/env python3
"""
NTConfReviewer.py (v4.0.0) - Offline Multi-Vendor Network & Firewall Security Review
Enterprise Static Configuration Auditing Engine

Comprehensive, dependency-free, all-in-one static analyzer and compliance auditing
engine for enterprise firewalls, routers, switches, and load balancers.

Supported Vendor Platforms & Assets:
  * Cisco Systems:
    - Cisco ASA / PIX / FWSM / FirePOWER (CLI & context configs)
    - Cisco IOS & IOS-XE (Routers: 800-4000, ISR, ASR1k; Switches: Catalyst 2960-9600)
    - Cisco NX-OS (Nexus 2000, 3000, 5000, 7000, 9000 Series)
    - Cisco IOS-XR (ASR 9000, CRS, NCS Series)
  * Fortinet:
    - FortiGate / FortiOS 5.x, 6.x, 7.0, 7.2, 7.4, 7.6 (Native CLI backup & full config)
  * Palo Alto Networks:
    - PAN-OS XML running-config.xml & CLI 'set' format (PA-200 to PA-7000, VM, Panorama)
  * Juniper Networks:
    - Junos SRX Series Firewalls (hierarchical and 'display set' CLI)
    - Junos EX Series Switches & MX/M Series Routers
    - ScreenOS / SSG Firewalls
  * Check Point:
    - Check Point Gaia / R77 / R80 / R81 (clish CLI, objects.C, rulebases_5_0.fws)
  * Arista Networks:
    - Arista EOS (7000 Series routing switches, vEOS)
  * Aruba Networks / HPE:
    - ArubaOS-Switch, ProCurve, Provision, ArubaOS-CX
  * Brocade / Foundry / Ruckus:
    - FastIron, ICX stackables, ServerIron, NetIron, BigIron
  * Extreme Networks:
    - ExtremeXOS (Summit, BlackDiamond, Alpine, X-Series)
  * F5 Networks:
    - BIG-IP TMOS v10, v11, v12+ (bigip.conf, bigip_base.conf, tmsh commands)
  * WatchGuard:
    - WatchGuard Firebox / Fireware OS (XML backup & CLI configs)
  * Huawei Technologies:
    - Huawei VRP (Quidway switches, Eudemon firewalls)

Audit Rule Domains:
  1. Administrative Access & Management Plane (Telnet, HTTP, SSH, timeouts, ACLs, WAN exposure)
  2. Authentication, Authorization & Accounting (AAA, password policies, encryption types, MFA)
  3. SNMP Security (v1/v2c cleartext, default strings, write access, missing ACLs, SNMPv3)
  4. Logging, Auditing & SIEM (Syslog host, redundancy, log timestamps, buffer, console, traffic logs)
  5. Time Synchronization (NTP servers, NTP count, NTP authentication, timezones)
  6. Warning Banners & Legal Notices (MOTD, Login banners, information leakage)
  7. Insecure Services & Protocol Hardening (CDP, LLDP, proxy ARP, directed broadcast, finger, pad)
  8. Firewall Policy & ACL Optimization (Any-Any permits, unlogged rules, broad ports, disabled rules)
  9. Threat Prevention & UTM (IPS, Antivirus, URL filtering, App control, SSL inspection, scan defense)
 10. Cryptography & VPN Standards (Weak ciphers, DES/3DES/MD5, DH groups < 14, TLS 1.0/1.1)
 11. Switch & Layer 2 Security (STP BPDU Guard, Root Guard, Port Security, VLAN 1, Trunk hygiene)

Compliance Framework Cross-Mappings:
  * CIS Benchmarks & CIS Critical Security Controls v8
  * DoD DISA STIGs (Cisco ASA, IOS-XE, NX-OS, Junos SRX, FortiGate, PAN-OS, F5)
  * NIST SP 800-53 Rev 5 & NIST SP 800-171 Rev 3
  * PCI-DSS v4.0
  * CMMC 2.0 (Level 1 & Level 2)

Input Formats:
  * Raw text configs (.conf, .cfg, .set, .txt, .xml, .backup, .log)
  * ZIP, TAR, TGZ archives or directories containing multi-vendor fleets

Examples:
  python NTConfReviewer.py firewall.conf -o review_report
  python NTConfReviewer.py fleet.zip -o fleet_audit
  python NTConfReviewer.py --dir ./configs --recursive -o audit_report
  python NTConfReviewer.py firewall.conf --vendor fortigate --model "FortiGate 2000E"
  python NTConfReviewer.py --list-supported
  python NTConfReviewer.py --self-test
"""

import argparse
import csv
import html
import json
import os
import re
import shlex
import sys
import tarfile
import zipfile
from collections import defaultdict
from datetime import datetime
from xml.etree import ElementTree as ET


TOOL_NAME = "Enterprise Network & Firewall Security Review"
TOOL_SUBTITLE = "Enterprise Multi-Vendor Static Configuration Security Analyzer"
TOOL_VERSION = "4.0.0"

BANNER = r"""
.  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .
.                                                                 .
.                                                                 .
.                               /\                                .
.                              /  \                               .
.                             / /\ \                              .
.                            / /  \ \                             .
.                           / / /\ \ \                            .
.                          | | |  | | |                           .
.                          | | |  | | |                           .
.                           \ \ \/ / /                            .
.                            \ \  / /                             .
.                             \ \/ /                              .
.                              \  /                               .
.                               \/                                .
.                                                                 .
.                                                                 .
.  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .  .
""".strip("\n")


def print_banner():
    print(BANNER)

SEV = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Info": 4}
SEV_WEIGHT = {"Critical": 10, "High": 7, "Medium": 4, "Low": 1, "Info": 0}

REFERENCES = {
    "cisco-config": (
        "Cisco ASA CLI: Viewing the Running Configuration",
        "https://www.cisco.com/c/en/us/td/docs/security/asa/asa-cli-reference/A-H/asa-command-ref-A-H/cli-usage.html"),
    "cisco-mgmt": (
        "Cisco ASA General Operations: Management Access",
        "https://www.cisco.com/c/en/us/td/docs/security/asa/asa917/configuration/general/asa-917-general-config/admin-management.html"),
    "cisco-ios-hardening": (
        "Cisco IOS Security Configuration Guide / Device Hardening",
        "https://www.cisco.com/c/en/us/support/docs/ip/access-lists/13608-21.html"),
    "cisco-nxos-hardening": (
        "Cisco NX-OS Security Configuration Guide",
        "https://www.cisco.com/c/en/us/td/docs/switches/datacenter/sw/security/nx-os_security_guide.html"),
    "fortinet-hardening": (
        "Fortinet FortiGate Best Practices: Hardening",
        "https://docs.fortinet.com/document/fortigate/7.6.0/best-practices/555436/hardening"),
    "fortinet-profiles": (
        "Fortinet FortiGate Best Practices: Security Profiles",
        "https://docs.fortinet.com/document/fortigate/7.0.0/best-practices/889496/security-profiles"),
    "fortinet-backup": (
        "Fortinet FortiGate: Configuration Backups and Reset",
        "https://docs.fortinet.com/document/fortigate/latest/administration-guide/702257"),
    "palo-policy": (
        "Palo Alto Networks: Security Policy Rule Best Practices",
        "https://docs.paloaltonetworks.com/best-practices/security-policy-best-practices/security-policy-rule-best-practices"),
    "palo-mgmt": (
        "Palo Alto Networks: Administrative Access Best Practices",
        "https://docs.paloaltonetworks.com/best-practices/administrative-access-best-practices"),
    "palo-logging": (
        "Palo Alto Networks: Configure Log Forwarding",
        "https://docs.paloaltonetworks.com/ngfw/administration/monitoring/configure-log-forwarding"),
    "juniper-policy": (
        "Juniper Junos: Configuring Security Policies",
        "https://www.juniper.net/documentation/us/en/software/junos/security-policies/topics/topic-map/security-policy-configuration.html"),
    "juniper-logging": (
        "Juniper Junos: Security Policy Logging",
        "https://www.juniper.net/documentation/us/en/software/junos/cli-reference/topics/ref/statement/security-edit-log-security-policies.html"),
    "juniper-snmp": (
        "Juniper Junos: Configure SNMPv3",
        "https://www.juniper.net/documentation/us/en/software/junos/network-mgmt/topics/topic-map/configure-snmpv3.html"),
    "juniper-config": (
        "Juniper Junos: View the Configuration",
        "https://www.juniper.net/documentation/us/en/software/junos/cli/topics/topic-map/junos-configuartion-viewing.html"),
    "checkpoint-hardening": (
        "Check Point Security Hardening Best Practices",
        "https://supportcenter.checkpoint.com/supportcenter/portal?eventSubmit_doGoviewsolutiondetails=&solutionid=sk112249"),
    "arista-hardening": (
        "Arista EOS Security Configuration and Hardening Guide",
        "https://www.arista.com/en/support/toi"),
    "aruba-hardening": (
        "ArubaOS-Switch and ArubaOS-CX Hardening Guide",
        "https://www.arubanetworks.com/techdocs/"),
    "brocade-hardening": (
        "Ruckus FastIron Security Configuration Guide",
        "https://docs.commscope.com/bundle/fastiron-08090-securityguide/page/GUID-E7453CA2-75E2-4C10-85A2-A6EB3ACDE80C.html"),
    "extreme-hardening": (
        "ExtremeXOS Security User Guide",
        "https://documentation.extremenetworks.com/exos_31.7/"),
    "f5-hardening": (
        "F5 BIG-IP Security Hardening Guide",
        "https://my.f5.com/manage/s/article/K13092"),
    "watchguard-hardening": (
        "WatchGuard Fireware OS Hardening Best Practices",
        "https://www.watchguard.com/help/docs/help-center/en-US/Content/en-US/Fireware/fireware_security_best_practices.html"),
    "huawei-hardening": (
        "Huawei VRP Security Hardening Specifications",
        "https://support.huawei.com/enterprise/en/doc/EDOC1100088924/"),
    "screenos-hardening": (
        "Juniper ScreenOS Concepts and Examples Security Guide",
        "https://www.juniper.net/documentation/en_US/screenos6.3.0/information-products/pathway-pages/screenos/index.html"),
    "nokia-ipso-hardening": (
        "Nokia IPSO Security Configuration and Hardening",
        "https://supportcenter.checkpoint.com/"),
    "dell-hardening": (
        "Dell PowerConnect Hardening Guide",
        "https://www.dell.com/support"),
    "alteon-hardening": (
        "Alteon OS Application Switch Configuration Guide",
        "https://www.radware.com/"),
    "cis-benchmarks": (
        "CIS (Center for Internet Security) Benchmarks",
        "https://www.cisecurity.org/cis-benchmarks/"),
    "disa-stig": (
        "DoD Cyber Exchange DISA Security Technical Implementation Guides (STIGs)",
        "https://public.cyber.mil/stigs/"),
    "nist-800-53": (
        "NIST Special Publication 800-53 Rev. 5: Security and Privacy Controls",
        "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"),
    "pci-dss": (
        "Payment Card Industry Data Security Standard (PCI DSS) v4.0",
        "https://www.pcisecuritystandards.org/document_library/"),
}

SUPPORTED_MODELS = {
    "cisco-asa": ("ASA 5505", "ASA 5510", "ASA 5520", "ASA 5525-X", "ASA 5545-X", "ASA 5555-X", "ASA 5585-X", "ASAv", "PIX 515", "PIX 525", "FWSM"),
    "cisco-ios": ("Catalyst 2960", "Catalyst 3550", "Catalyst 3560", "Catalyst 3650", "Catalyst 3750", "Catalyst 3850", "Catalyst 9200", "Catalyst 9300", "Catalyst 9500", "ISR 1100", "ISR 1900", "ISR 2900", "ISR 3900", "ISR 4000", "ASR 1000", "CSR 1000v"),
    "cisco-nxos": ("Nexus 2000", "Nexus 3000", "Nexus 5000", "Nexus 5010", "Nexus 7000", "Nexus 9000"),
    "cisco-xr": ("ASR 9000", "ASR 9001", "CRS-1", "CRS-3", "NCS 5500"),
    "fortigate": ("FortiGate 40F", "FortiGate 60E", "FortiGate 60F", "FortiGate 80F", "FortiGate 100E", "FortiGate 100F", "FortiGate 200E", "FortiGate 200F", "FortiGate 500E", "FortiGate 600E", "FortiGate 1000D", "FortiGate 1500D", "FortiGate 2000E", "FortiGate 3301E", "FortiGate 3700D", "FortiGate VM"),
    "paloalto": ("PA-200", "PA-220", "PA-400", "PA-800", "PA-820", "PA-850", "PA-3000", "PA-3020", "PA-3200", "PA-3220", "PA-5000", "PA-5220", "PA-5250", "PA-7000", "PA-VM", "Panorama"),
    "juniper": ("SRX300", "SRX320", "SRX330", "SRX340", "SRX345", "SRX380", "SRX550", "SRX1500", "SRX4100", "SRX4200", "EX2200", "EX2300", "EX3300", "EX3400", "EX4200", "EX4300", "MX104", "MX204", "MX480", "MX960", "vSRX"),
    "checkpoint": ("Quantum 3000", "Quantum 6000", "Quantum 7000", "Quantum 16000", "Quantum 26000", "Smart-1", "CloudGuard", "Check Point Gaia"),
    "arista": ("Arista 7050", "Arista 7060", "Arista 7150", "Arista 7280", "Arista 7500", "vEOS"),
    "aruba-hp": ("ProCurve 2500", "ProCurve 2600", "ProCurve 2800", "ProCurve 2900", "ProCurve 3500", "ProCurve 5400", "Aruba 2930", "Aruba 3810", "Aruba CX 6200", "Aruba CX 6300"),
    "brocade-ruckus": ("FastIron Edge", "FastIron Workgroup", "ICX 6450", "ICX 7150", "ICX 7250", "ICX 7450", "ServerIron", "BigIron", "NetIron", "ICX"),
    "extreme": ("Summit X440", "Summit X460", "Summit X670", "BlackDiamond 8800", "Alpine 3800"),
    "f5-bigip": ("BIG-IP 2000", "BIG-IP 4000", "BIG-IP 5000", "BIG-IP 7000", "BIG-IP 10000", "BIG-IP iSeries", "VIPRION", "BIG-IP VE"),
    "watchguard": ("Firebox T15", "Firebox T35", "Firebox T80", "Firebox M270", "Firebox M370", "Firebox M470", "Firebox M570", "FireboxV", "XTM 5 Series"),
    "huawei": ("Quidway S2300", "Quidway S3300", "Quidway S5300", "Quidway S5700", "Eudemon 200", "Eudemon 1000E"),
    "screenos": ("NetScreen-5GT", "NetScreen-50", "SSG-5", "SSG-20", "SSG-140", "SSG-550", "ISG-1000", "ISG-2000"),
    "nokia-ipso": ("IP390", "IP560", "IP1280", "IP2450"),
    "dell-powerconnect": ("PowerConnect 3500", "PowerConnect 5500", "PowerConnect 6200", "PowerConnect 7000", "PowerConnect 8100"),
    "alteon-os": ("Alteon 180e", "Alteon 184", "Alteon 2208", "Alteon 2424", "Alteon 3408"),
}

MODEL_NOTES = {
    "SRX330": (
        "SRX330 is retained as an expected asset label because it was supplied by the user, "
        "but it is not listed in Juniper's current SRX300-line hardware documentation. Verify "
        "whether the intended platform is SRX300, SRX320, SRX340, or another model."),
    "PIX 515": "Cisco PIX 500-series firewall is End-of-Life (EOL). Hardware does not receive security patches; migrate to modern NGFW.",
    "PIX 525": "Cisco PIX 500-series firewall is End-of-Life (EOL). Hardware does not receive security patches; migrate to modern NGFW.",
    "FWSM": "Cisco Catalyst 6500 FWSM is End-of-Life (EOL). Plan migration to modern dedicated or virtual firewalls.",
    "NetScreen-5GT": "Juniper NetScreen-5GT is End-of-Life (EOL). Hardware does not receive security patches; plan migration to Juniper SRX.",
    "SSG-5": "Juniper SSG-5 firewall is End-of-Life (EOL). Plan hardware migration to Juniper SRX.",
    "SSG-20": "Juniper SSG-20 firewall is End-of-Life (EOL). Plan hardware migration to Juniper SRX.",
    "SSG-140": "Juniper SSG-140 firewall is End-of-Life (EOL). Plan hardware migration to Juniper SRX.",
    "SSG-550": "Juniper SSG-550 firewall is End-of-Life (EOL). Plan hardware migration to Juniper SRX.",
    "IP390": "Nokia IP390 is End-of-Life (EOL). Migrate to Check Point Quantum running Gaia OS.",
    "IP560": "Nokia IP560 is End-of-Life (EOL). Migrate to Check Point Quantum running Gaia OS.",
}

TEXT_EXTENSIONS = {
    "", ".cfg", ".conf", ".config", ".txt", ".set", ".xml", ".backup", ".log", ".c", ".fws", ".ndb"
}
ARCHIVE_EXTENSIONS = {".zip", ".tar", ".tgz", ".tar.gz", ".tar.bz2", ".tar.xz"}


class Finding:
    def __init__(self, rule_id, device, title, severity, category, confidence,
                 evidence, impact, recommendation, reference_key,
                 compliance=None, remediation_cmd=""):
        self.rule_id = rule_id
        self.device = device
        self.title = title
        self.severity = severity
        self.category = category
        self.confidence = confidence
        self.evidence = [(n, redact_evidence(t)) for n, t in evidence]
        self.impact = impact
        self.recommendation = recommendation
        self.reference_key = reference_key
        self.compliance = compliance or {}
        self.remediation_cmd = remediation_cmd

    @property
    def reference(self):
        return REFERENCES.get(self.reference_key, (self.reference_key, ""))[0]

    @property
    def reference_url(self):
        return REFERENCES.get(self.reference_key, ("", ""))[1]

    def as_dict(self):
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "category": self.category,
            "confidence": self.confidence,
            "title": self.title,
            "evidence": [{"line": n or None, "text": t.strip()} for n, t in self.evidence],
            "impact": self.impact,
            "recommendation": self.recommendation,
            "reference": self.reference,
            "reference_url": self.reference_url,
            "compliance": self.compliance,
            "remediation_cmd": self.remediation_cmd,
        }


class DeviceInfo:
    def __init__(self, vendor="unknown", vendor_confidence="Low", model="Unknown",
                 model_confidence="Unknown", hostname="Unknown", os_version="Unknown",
                 config_format="Unknown", scope="Partial/unknown", evidence=None, warnings=None):
        self.vendor = vendor
        self.vendor_confidence = vendor_confidence
        self.model = model
        self.model_confidence = model_confidence
        self.hostname = hostname
        self.os_version = os_version
        self.config_format = config_format
        self.scope = scope
        self.evidence = evidence or []
        self.warnings = warnings or []

    @property
    def supported(self):
        return self.model in SUPPORTED_MODELS.get(self.vendor, ())

    def as_dict(self):
        return {
            "vendor": self.vendor, "vendor_confidence": self.vendor_confidence,
            "model": self.model, "model_confidence": self.model_confidence,
            "hostname": self.hostname, "os_version": self.os_version,
            "config_format": self.config_format, "scope": self.scope,
            "expected_model": self.supported, "detection_evidence": self.evidence,
            "warnings": self.warnings,
        }


class AuditResult:
    def __init__(self, source, info, findings):
        self.source = source
        self.info = info
        self.findings = sorted(findings, key=lambda f: (SEV.get(f.severity, 9), f.rule_id))

    @property
    def risk_score(self):
        return min(100, sum(SEV_WEIGHT.get(f.severity, 0) for f in self.findings))

    @property
    def compliance_summary(self):
        summary = {"CIS": 0, "DISA_STIG": 0, "NIST_800_53": 0, "PCI_DSS": 0, "CMMC": 0}
        for f in self.findings:
            if f.compliance.get("cis"): summary["CIS"] += 1
            if f.compliance.get("stig"): summary["DISA_STIG"] += 1
            if f.compliance.get("nist_53"): summary["NIST_800_53"] += 1
            if f.compliance.get("pci_dss"): summary["PCI_DSS"] += 1
            if f.compliance.get("cmmc"): summary["CMMC"] += 1
        return summary

    def as_dict(self):
        return {
            "source": self.source, "device": self.info.as_dict(),
            "risk_score": self.risk_score, "counts": counts(self.findings),
            "compliance_summary": self.compliance_summary,
            "findings": [f.as_dict() for f in self.findings],
        }


def read_text_file(path):
    with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
        return [(i + 1, line.rstrip("\r\n")) for i, line in enumerate(fh)]


def lines_from_bytes(data):
    text = data.decode("utf-8-sig", errors="replace")
    return [(i + 1, line.rstrip("\r")) for i, line in enumerate(text.splitlines())]


def joined(lines):
    return "\n".join(text for _, text in lines)


REDACT_SECRETS = True

# Cisco Type 7 Decryption Key Table
CISCO_TYPE7_KEY = [
    0x64, 0x73, 0x66, 0x64, 0x3b, 0x6b, 0x66, 0x6f, 0x41, 0x2c,
    0x2e, 0x69, 0x79, 0x65, 0x77, 0x72, 0x6b, 0x6c, 0x64, 0x4a,
    0x4b, 0x44, 0x48, 0x53, 0x55, 0x42
]

# Juniper Type 9 Decryption Constants
JUNIPER_ENCODING = [
    [1, 4, 32],
    [1, 16, 32],
    [1, 8, 32],
    [1, 64],
    [1, 32],
    [1, 4, 16, 128],
    [1, 32, 64],
]
JUNIPER_KEYS = ["QzF3n6/9CAtpu0O", "B1IREhcSyrleKvMW8LXx", "7N-dVbwsY2g4oaJZGUDj", "iHkq.mPf5T"]
JUNIPER_KEYS_STRING = "".join(JUNIPER_KEYS)
JUNIPER_KEYS_LENGTH = len(JUNIPER_KEYS_STRING)
JUNIPER_CHARACTER_KEYS = {}
for _idx, _key in enumerate(JUNIPER_KEYS):
    for _c in _key:
        JUNIPER_CHARACTER_KEYS[_c] = 3 - _idx


def decode_cisco_type7(ciphertext):
    """
    Decodes a Cisco Type 7 encrypted password string.
    Returns the decoded plaintext string or None if invalid.
    """
    if not ciphertext:
        return None
    raw = ciphertext.strip().strip('"').strip("'")
    if len(raw) < 4 or len(raw) % 2 != 0:
        return None
    try:
        index = int(raw[:2], 10)
    except ValueError:
        return None
    result = []
    for i in range(2, len(raw), 2):
        try:
            val = int(raw[i:i+2], 16)
        except ValueError:
            return None
        k = CISCO_TYPE7_KEY[(index + (i // 2 - 1)) % len(CISCO_TYPE7_KEY)]
        result.append(chr(val ^ k))
    return "".join(result)


def decode_juniper_type9(ciphertext):
    """
    Decodes a Junos $9$ reversible encrypted password string.
    Returns the decoded plaintext string or None if invalid.
    """
    if not ciphertext or "$9$" not in ciphertext:
        return None
    raw = ciphertext.strip().strip('"').strip("'")
    try:
        password_characters = raw.split("$9$", 1)[1].strip()
        if not password_characters:
            return None
        first_character = password_characters[0]
        extra_chars = JUNIPER_CHARACTER_KEYS.get(first_character, 0)
        stripped = password_characters[extra_chars + 1:]
        previous_char = first_character
        decrypted = ""
        while stripped:
            decode = JUNIPER_ENCODING[len(decrypted) % len(JUNIPER_ENCODING)]
            if len(stripped) < len(decode):
                break
            nibble = stripped[0:len(decode)]
            stripped = stripped[len(decode):]
            val = 0
            for index, char in enumerate(nibble):
                gap = ((JUNIPER_KEYS_STRING.index(char) - JUNIPER_KEYS_STRING.index(previous_char)) % JUNIPER_KEYS_LENGTH) - 1
                val += gap * decode[index]
                previous_char = char
            decrypted += chr(val)
        return decrypted if decrypted else None
    except Exception:
        return None


def decode_reversible_password(token):
    """
    Attempts to decode known reversible password formats (Cisco Type 7, Juniper Type 9).
    Returns (format_name, plaintext) or (None, None).
    """
    if not token:
        return None, None
    raw = token.strip().strip('"').strip("'")
    if "$9$" in raw:
        dec = decode_juniper_type9(raw)
        if dec:
            return "Juniper $9$", dec
    if re.match(r"^[0-9a-fA-F]{4,}$", raw) and len(raw) % 2 == 0:
        dec = decode_cisco_type7(raw)
        if dec and all(32 <= ord(c) <= 126 for c in dec):
            return "Cisco Type 7", dec
    return None, None


def redact_evidence(text):
    if not REDACT_SECRETS:
        return str(text)
    value = str(text)
    substitutions = [
        (r"(?i)(\b(?:enable\s+password|enable\s+secret|passwd)\s+(?:[05789]\s+)?)(\S+)", r"\1<redacted>"),
        (r"(?i)(\bpassword\s+(?:0|5|7|8|9|encrypted|pbkdf2)?\s*)(\S+)", r"\1<redacted>"),
        (r"(?i)(\b(?:encrypted-password|plain-text-password)\s+)(\S+)", r"\1<redacted>"),
        (r"(?i)(\bset\s+(?:password|passwd|secret|psksecret|private-key)\s+)(.+)$", r"\1<redacted>"),
        (r"(?i)(\b(?:authentication-key|privacy-key)\b.*\bvalue\s+)(\"[^\"]+\"|\S+)", r"\1<redacted>"),
        (r"(?i)(\b(?:authentication-key|privacy-key)\s+)(\"?\$[^\s;\"]+\"?)", r"\1<redacted>"),
        (r"(?i)(\bpre-shared-key\s+(?:(?:ascii-text|hexadecimal)\s+)?)(\"[^\"]+\"|\S+)", r"\1<redacted>"),
        (r"(?i)(\bsnmp-server user\b.*\bauth\s+\S+\s+)(\S+)", r"\1<redacted>"),
        (r"(?i)(\bsnmp-server user\b.*\bpriv\s+\S+(?:\s+\d+)?\s+)(\S+)", r"\1<redacted>"),
        (r"(?i)(\bsnmp-server\s+community\s+)(\S+)", r"\1<redacted>"),
        (r"(?i)(\bsnmp\s+community\s+)(\"[^\"]+\"|\S+)", r"\1<redacted>"),
        (r"(?i)(<snmp-comm-string>)([^<]+)(</snmp-comm-string>)", r"\1<redacted>\3"),
        (r"(?i)(\bcommunity\s+)(public|private)(\b)", r"\1<redacted>\3"),
        (r"(?i)(\b(?:key|secret|radius-server key|tacacs-server key)\s+(?:0|7)?\s*)(\"[^\"]+\"|\S+)", r"\1<redacted>"),
        (r"(?i)(\[Trivially decoded:\s*\")[^\"]+(\"\])", r"\1<redacted>\2"),
    ]
    for pattern, replacement in substitutions:
        value = re.sub(pattern, replacement, value)
    return value


def normalize_model(raw, vendor=None):
    if not raw:
        return None
    text = re.sub(r"\s+", " ", raw.upper().replace("_", "-").strip())
    # Cisco ASA
    if vendor in (None, "cisco-asa") and re.search(r"ASA[- ]?5525(?:-X)?", text):
        return "ASA 5525-X"
    if vendor in (None, "cisco-asa") and re.search(r"ASA[- ]?55(\d{2})(?:-X)?", text):
        m = re.search(r"ASA[- ]?55(\d{2})(?:-X)?", text)
        return f"ASA 55{m.group(1)}-X" if int(m.group(1)) >= 12 else f"ASA 55{m.group(1)}"
    # Palo Alto
    if vendor in (None, "paloalto") and re.search(r"PA[- ]?5220", text):
        return "PA-5220"
    if vendor in (None, "paloalto") and re.search(r"PA[- ]?(\d{3,4})", text):
        return "PA-" + re.search(r"PA[- ]?(\d{3,4})", text).group(1)
    # Fortinet FortiGate
    if vendor in (None, "fortigate"):
        match = re.search(r"(?:FORTIGATE[- ]?|FGT[- ]?|FG[- ]?)(2000E|3301E|1500D|100E|100F|60E|60F|200E|200F|500E|600E)\b", text)
        if not match and vendor == "fortigate":
            match = re.search(r"\b(2000E|3301E|1500D|100E|100F|60E|60F|200E|200F|500E|600E)\b", text)
        if match:
            return "FortiGate " + match.group(1)
    # Juniper
    if vendor in (None, "juniper"):
        match = re.search(r"\bSRX[- ]?(300|320|330|340|345|380|550|1500|4100|4200)\b", text)
        if match:
            return "SRX" + match.group(1)
        match = re.search(r"\bEX[- ]?(2200|2300|3300|3400|4200|4300)\b", text)
        if match:
            return "EX" + match.group(1)
        match = re.search(r"\bMX[- ]?(104|204|480|960)\b", text)
        if match:
            return "MX" + match.group(1)
    # Cisco IOS / Catalyst / Nexus
    if vendor in (None, "cisco-ios"):
        match = re.search(r"(?:WS-C|CATALYST[- ]?|CAT[- ]?)?(2960|3550|3560|3650|3750|3850|9200|9300|9500)", text)
        if match:
            return "Catalyst " + match.group(1)
        match = re.search(r"(?:CISCO[- ]?)?(19\d{2}|29\d{2}|39\d{2}|43\d{2}|44\d{2}|1100|1000)", text)
        if match:
            return "ISR " + match.group(1)
    if vendor in (None, "cisco-nxos"):
        match = re.search(r"NEXUS[- ]?(2\d{3}|3\d{3}|5\d{3}|5010|7\d{3}|9\d{3})", text)
        if match:
            return "Nexus " + match.group(1)
    # Arista
    if vendor in (None, "arista"):
        match = re.search(r"\b(VEOS|7050|7060|7150|7280|7500)\b", text)
        if match:
            return "vEOS" if match.group(1) == "VEOS" else ("Arista " + match.group(1))
    # Aruba / HP ProCurve
    if vendor in (None, "aruba-hp"):
        match = re.search(r"(?:PROCURVE[- ]?|SWITCH[- ]?|ARUBA[- ]?)?(25\d{2}|26\d{2}|28\d{2}|29\d{2}|35\d{2}|54\d{2})", text)
        if match:
            return "ProCurve " + match.group(1)[:2] + "00"
    # Brocade / Ruckus
    if vendor in (None, "brocade-ruckus"):
        match = re.search(r"(ICX[- ]?7\d{3}|ICX[- ]?6\d{3}|ICX|FASTIRON|SERVERIRON)", text)
        if match:
            return "ICX" if "ICX" in match.group(1) else match.group(1).replace("-", " ")
    # Extreme
    if vendor in (None, "extreme"):
        match = re.search(r"(SUMMIT[- ]?X\d{3}|BLACKDIAMOND[- ]?\d{4}|ALPINE[- ]?\d{4})", text)
        if match:
            return match.group(1).title().replace("-", " ")
    # WatchGuard
    if vendor in (None, "watchguard"):
        match = re.search(r"(FIREBOX|XTM[- ]?\d+|FIREBOXV|XTM 5 SERIES)", text)
        if match:
            return "XTM 5 Series" if "XTM 5" in match.group(1) else match.group(1)
    # F5
    if vendor in (None, "f5-bigip"):
        match = re.search(r"BIG-IP[- ]?(\d{4}|VE|VIPRION)", text)
        if match:
            return "BIG-IP " + match.group(1)
    # ScreenOS
    if vendor in (None, "screenos"):
        match = re.search(r"\b(SSG[- ]?5|SSG[- ]?20|SSG[- ]?140|SSG[- ]?550|ISG[- ]?1000|ISG[- ]?2000|NETSCREEN[- ]?5GT|NETSCREEN[- ]?50)\b", text)
        if match:
            val = re.sub(r"\s+", "-", match.group(1).upper())
            if re.match(r"^SSG\d", val):
                return "SSG-" + val[3:]
            if re.match(r"^ISG\d", val):
                return "ISG-" + val[3:]
            if re.match(r"^NETSCREEN", val):
                return "NetScreen-" + val[9:].lstrip("-")
            return val
    # Nokia IPSO
    if vendor in (None, "nokia-ipso"):
        match = re.search(r"\b(IP390|IP560|IP1280|IP2450)\b", text)
        if match:
            return match.group(1).upper()
    # Dell PowerConnect
    if vendor in (None, "dell-powerconnect"):
        match = re.search(r"(?:POWERCONNECT[- ]?|DELL[- ]?(?:SWITCH[- ]?)?)?(35\d{2}|55\d{2}|62\d{2}|70\d{2}|81\d{2})", text)
        if match:
            series = match.group(1)[:2] + "00"
            return "PowerConnect " + series
    # Alteon
    if vendor in (None, "alteon-os"):
        match = re.search(r"(?:ALTEON[- ]?)?(180E|184|2208|2424|3408)", text)
        if match:
            return "Alteon " + match.group(1).lower()
    return None


def infer_scope(vendor, lower, config_format):
    markers = {
        "fortigate": ("config system global", "config system interface", "config firewall policy"),
        "paloalto": ("deviceconfig system", "rulebase security rules", "network interface", "<devices>"),
        "juniper": ("system {", "security {", "set system ", "set security "),
        "cisco-asa": ("asa version", "interface ", "access-list ", "hostname "),
        "cisco-ios": ("version 1", "interface ", "line vty", "hostname "),
        "cisco-nxos": ("version ", "feature ", "interface ", "hostname "),
        "checkpoint": ("rulebase", "objects", "clish", "hostname"),
        "arista": ("transceiver", "spanning-tree", "interface ", "hostname "),
        "aruba-hp": ("configuration editor", "interface ", "max-vlans", "hostname "),
        "brocade-ruckus": ("ver ", "interface ", "vlan ", "hostname "),
        "extreme": ("configure vlan", "configure snmp", "module devmgr"),
        "f5-bigip": ("net self", "sys httpd", "ltm virtual", "auth user"),
        "watchguard": ("<profile>", "<system-parameters>", "<policy-list>"),
        "screenos": ("set hostname", "set interface", "set policy", "set admin"),
        "nokia-ipso": ("set user", "set snmp", "set hostname", "add user"),
        "dell-powerconnect": ("username", "interface", "spanning-tree", "hostname"),
        "alteon-os": ("/cfg/sys", "/cfg/slb", "/cfg/port", "/c/sys"),
    }
    line_count = lower.count("\n") + 1
    if vendor == "paloalto" and config_format == "PAN-OS XML" and "<config" in lower and "<devices>" in lower:
        return "Likely full"
    if vendor == "watchguard" and "<profile>" in lower and "<system-parameters>" in lower:
        return "Likely full"
    score = sum(marker in lower for marker in markers.get(vendor, ()))
    if vendor == "fortigate":
        complete = ("#config-version=" in lower or "#conf_file_ver=" in lower or (line_count >= 150 and score >= 3))
    elif vendor == "juniper":
        complete = (("## last commit:" in lower and score >= 2) or (line_count >= 120 and score >= 3))
    elif vendor in ("cisco-asa", "cisco-ios", "cisco-nxos", "cisco-xr"):
        complete = ((re.search(r"(?m)^\s*:\s*saved\s*$", lower) is not None and score >= 2) or (line_count >= 100 and score >= 3))
    elif vendor == "paloalto":
        complete = line_count >= 150 and score >= 3
    elif score >= 2 and line_count >= 50:
        complete = True
    else:
        complete = False
    return "Likely full" if complete else "Partial/unknown"


def detect_device(lines, source_name="", forced_vendor=None, forced_model=None):
    text, lower = joined(lines), joined(lines).lower()
    evidence, scores = [], defaultdict(int)

    # Multi-Vendor Detection Signatures & Heuristics
    markers = {
        "fortigate": [
            (r"(?m)^\s*#(?:config-version|conf_file_ver)=", 9),
            (r"(?m)^\s*config system global\b", 6),
            (r"(?m)^\s*config firewall policy6?\b", 6),
            (r"(?m)^\s*config vdom\b", 4),
            (r"\bfortigate[- ]\d", 6),
            (r"\bfortios\b", 5),
        ],
        "paloalto": [
            (r"(?m)^\s*set (?:shared |devices \S+ vsys \S+ )?(?:pre-|post-)?rulebase security rules\b", 8),
            (r"(?m)^\s*set deviceconfig system\b", 7),
            (r"<config\b[^>]*version=", 6),
            (r"<rulebase>|<pre-rulebase>|<post-rulebase>", 6),
            (r"\bpan-os\b|\bpa-\d{4}\b", 6),
            (r"<devices><entry name=\"localhost\.localdomain\">", 5),
        ],
        "juniper": [
            (r"(?m)^\s*set security policies\b", 8),
            (r"(?m)^\s*set system host-name\b", 6),
            (r"\bfrom-zone\s+\S+\s+to-zone\b", 5),
            (r"\broot-authentication\b", 4),
            (r"(?m)^\s*system\s*\{", 4),
            (r"(?m)^\s*security\s*\{", 5),
            (r"\bjunos\b|\bsrx\d{3,4}\b", 5),
            (r"(?m)^##\s*Last commit:", 5),
        ],
        "cisco-asa": [
            (r"(?mi)^\s*ASA Version\b", 10),
            (r"(?mi)^\s*Cisco Adaptive Security Appliance Software Version\b", 10),
            (r"(?m)^\s*nameif\s+\S+", 4),
            (r"(?m)^\s*access-list\s+\S+\s+extended\b", 6),
            (r"(?m)^\s*crypto ikev[12]\b", 4),
            (r"\bASA[- ]?55\d{2}", 6),
            (r"(?mi)PIX Version\b", 9),
        ],
        "cisco-nxos": [
            (r"(?m)^\s*version\s+\d+\.\d+\([^\)]+\)N[1-9]", 10),
            (r"(?m)^\s*feature\s+(?:telnet|ssh|lacp|vpc|interface-vlan|tacacs\+|fcoe|port-track)\b", 8),
            (r"(?m)^\s*role name (?:network-admin|network-operator)\b", 6),
            (r"(?m)^\s*(?:no )?password strength-check\b", 5),
            (r"\bTitaniaNexus|\bNexus\s*\d{4}\b|\bNX-OS\b", 6),
        ],
        "cisco-xr": [
            (r"(?mi)\bIOS[- ]XR\b", 10),
            (r"(?m)^\s*RP/\d+/RSP\d+/", 9),
            (r"(?m)^\s*admin\s+show\b", 5),
            (r"(?m)^\s*interface TenGigE\S+", 4),
        ],
        "cisco-ios": [
            (r"(?m)^\s*version 1[25]\.\d+", 8),
            (r"(?m)^\s*Current configuration with default configurations exposed", 9),
            (r"(?m)^\s*service timestamps (?:debug|log) datetime", 6),
            (r"(?m)^\s*service password-encryption\b", 5),
            (r"(?m)^\s*boot-start-marker\b", 6),
            (r"(?m)^\s*line vty 0 \d+", 5),
            (r"(?m)^\s*spanning-tree mode (?:pvst|rapid-pvst|mst)", 5),
            (r"(?mi)cisco catalyst|cisco ios", 5),
        ],
        "checkpoint": [
            (r"(?m)^\s*\(rulebase\b", 8),
            (r"(?m)^\s*\(rule_num\b", 8),
            (r"(?m)^\s*:[a-zA-Z0-9_-]+\s*\(", 8),
            (r"(?m)^\s*set clish\b", 7),
            (r"\bCheckPoint\b|\bCheck Point\b|\bGaia\b", 6),
        ],
        "arista": [
            (r"(?m)^\s*! Command: show running-config", 4),
            (r"(?mi)\bEOS-\d+\.\d+", 9),
            (r"(?m)^\s*transceiver qsfp default-mode", 7),
            (r"(?m)^\s*management api http-commands", 8),
            (r"\barista\b", 6),
        ],
        "aruba-hp": [
            (r"(?m);\s*Configuration Editor;\s*Created on release #", 10),
            (r"(?m)^\s*sntp server priority\b", 7),
            (r"(?m)^\s*max-vlans\s+\d+", 6),
            (r"(?m)^\s*password-manager\b", 6),
            (r"\bProCurve\b|\bArubaOS\b", 6),
        ],
        "brocade-ruckus": [
            (r"(?m)^\s*ver\s+0[4-8]\.\d+\.\d+", 9),
            (r"(?m)^\s*enable super-user-password\b", 8),
            (r"\bFastIron\b|\bServerIron\b|\bICX\b|\bBrocade\b", 7),
            (r"(?m)^\s*module 1 (?:fcx|icx)", 7),
        ],
        "extreme": [
            (r"(?m)^\s*# Module devmgr configuration\.", 9),
            (r"(?m)^\s*# Module netLogin configuration\.", 7),
            (r"(?m)^\s*configure sys-recovery-level\b", 8),
            (r"(?m)^\s*configure ssh2 key-size\b", 8),
            (r"\bExtremeXOS\b|\bSummitXOS\b", 8),
        ],
        "f5-bigip": [
            (r"(?m)^\s*auth password-policy\s*\{", 8),
            (r"(?m)^\s*sys httpd\s*\{", 8),
            (r"(?m)^\s*net self\s+\S+\s*\{", 8),
            (r"(?m)^\s*cm device\s+\S+\s*\{", 7),
            (r"\bbigip\.conf\b|\bF5 BIG-IP\b|\bTMOS\b", 8),
        ],
        "watchguard": [
            (r"(?m)<profile\b[^>]*>", 8),
            (r"(?m)<for-version>[^<]+</for-version>", 8),
            (r"(?m)<for-model>[^<]+</for-model>", 8),
            (r"\bWatchGuard\b|\bFirebox\b|\bFireware\b", 8),
        ],
        "huawei": [
            (r"(?m)^\s*sysname\s+\S+", 6),
            (r"(?m)^\s*display current-configuration\b", 7),
            (r"(?m)^\s*super password\s+", 7),
            (r"\bQuidway\b|\bEudemon\b|\bHuawei\b|\bVRP\b", 6),
        ],
        "screenos": [
            (r"(?mi)^\s*set\s+policy\s+id\s+\d+\s+from\b", 10),
            (r"(?mi)^\s*set\s+admin\s+(?:name|password|user)\b", 9),
            (r"(?mi)^\s*set\s+interface\s+(?:ethernet|serial|\"[^\"]+\")\s+zone\b", 8),
            (r"\bScreenOS\b|\bNetScreen\b|\bSSG[- ]?\d+\b|\bISG[- ]?\d+\b", 8),
        ],
        "nokia-ipso": [
            (r"(?mi)^\s*set\s+ipforwarding\s+(?:on|off)\b", 9),
            (r"(?mi)^\s*add\s+user\s+\S+\s+uid\s+\d+", 9),
            (r"(?mi)^\s*set\s+interface\s+\S+\s+active\s+(?:on|off)\b", 8),
            (r"\bIPSO\b|\bNokia\s*IP\b", 8),
        ],
        "dell-powerconnect": [
            (r"(?mi)^\s*(?:set|enable)\s+password\s+level\s+\d+", 9),
            (r"(?mi)^\s*ip\s+(?:ssh|telnet)\s+server\b", 7),
            (r"(?mi)\bPowerConnect\s+(?:3\d{3}|5\d{3}|6\d{3}|7\d{3}|8\d{3})\b", 10),
            (r"\bDell\b", 6),
        ],
        "alteon-os": [
            (r"(?m)^\s*(?:/cfg/sys/|/c/sys/)", 10),
            (r"(?m)^\s*(?:/cfg/slb/|/c/slb/)", 10),
            (r"\bAlteon\s+OS\b|\bAlteon\s+Application\s+Switch\b", 9),
        ],
    }

    for vendor_name, vendor_markers in markers.items():
        for pattern, points in vendor_markers:
            if re.search(pattern, text, re.I):
                scores[vendor_name] += points

    if re.search(r"\b(?:objects|rulebases|fwauth|asm).*\.(?:C|fws|NDB)$", source_name, re.I):
        scores["checkpoint"] += 12

    positive_scores = [(k, v) for k, v in scores.items() if v > 0]

    if forced_vendor:
        vendor, vendor_confidence = forced_vendor, "Forced"
        evidence.append("Vendor forced by --vendor")
    elif positive_scores:
        ordered = sorted(positive_scores, key=lambda item: item[1], reverse=True)
        # Disambiguate Cisco families when top score is Cisco
        cisco_scores = {k: scores.get(k, 0) for k in ("cisco-nxos", "cisco-asa", "cisco-xr", "cisco-ios") if scores.get(k, 0) > 0}
        if cisco_scores and ordered[0][0] in cisco_scores:
            best_cisco = max(cisco_scores.items(), key=lambda x: x[1])
            if best_cisco[1] >= 6:
                vendor = best_cisco[0]
            else:
                vendor = ordered[0][0]
        else:
            vendor = ordered[0][0]

        top = scores[vendor]
        second = max([v for k, v in positive_scores if k != vendor], default=0)
        if top >= 8 and top >= second + 2:
            vendor_confidence = "High"
        elif top >= 5 and top > second:
            vendor_confidence = "Medium"
        else:
            vendor_confidence = "Low"
        evidence.append("Detection scores: " + ", ".join(f"{k}={v}" for k, v in ordered[:4]))
    else:
        vendor, vendor_confidence = "unknown", "Low"
        evidence.append("No vendor-specific signatures found")

    # Determine Config Format
    if vendor == "paloalto":
        config_format = "PAN-OS XML" if re.search(r"<config\b|<response\b", lower) else "PAN-OS set CLI"
    elif vendor == "juniper":
        config_format = "Junos set CLI" if re.search(r"(?m)^\s*set\s+", text) else "Junos hierarchical"
    elif vendor == "fortigate":
        config_format = "FortiOS CLI"
    elif vendor == "cisco-asa":
        config_format = "Cisco ASA CLI"
    elif vendor == "cisco-nxos":
        config_format = "Cisco NX-OS CLI"
    elif vendor == "cisco-ios":
        config_format = "Cisco IOS CLI"
    elif vendor == "checkpoint":
        config_format = "Check Point SmartCenter Config" if "(" in text else "Check Point Gaia CLI"
    elif vendor == "watchguard":
        config_format = "WatchGuard XML" if "<profile" in text else "WatchGuard CLI"
    elif vendor == "f5-bigip":
        config_format = "F5 TMOS Config"
    elif vendor == "screenos":
        config_format = "ScreenOS CLI"
    elif vendor == "nokia-ipso":
        config_format = "Nokia IPSO CLI"
    elif vendor == "dell-powerconnect":
        config_format = "Dell PowerConnect CLI"
    elif vendor == "alteon-os":
        config_format = "Alteon OS Config"
    elif vendor == "unknown":
        config_format = "Unknown text"
    else:
        config_format = "Native CLI / Structured"

    # Hostname Extraction
    hostname = "Unknown"
    hostname_patterns = {
        "fortigate": [r"(?m)^\s*set hostname\s+(.+?)\s*$", r"Hostname:\s*(\S+)"],
        "paloalto": [r"(?m)^\s*set deviceconfig system hostname\s+(\S+)", r"<hostname>([^<]+)</hostname>"],
        "juniper": [r"(?m)^\s*(?:set\s+system\s+)?host-name\s+([^;\s]+)", r"Hostname:\s*(\S+)"],
        "cisco-asa": [r"(?m)^\s*hostname\s+(\S+)"],
        "cisco-ios": [r"(?m)^\s*hostname\s+(\S+)"],
        "cisco-nxos": [r"(?m)^\s*hostname\s+(\S+)"],
        "checkpoint": [r"(?m)^\s*set hostname\s+(\S+)", r"Hostname:\s*(\S+)"],
        "arista": [r"(?m)^\s*hostname\s+(\S+)"],
        "aruba-hp": [r'(?m)^\s*hostname\s+"?([^"\r\n]+)"?'],
        "brocade-ruckus": [r"(?m)^\s*hostname\s+(\S+)"],
        "extreme": [r'(?m)^\s*configure snmp sysName\s+"?([^"\r\n]+)"?'],
        "f5-bigip": [r"(?m)^\s*hostname\s+(\S+)"],
        "huawei": [r"(?m)^\s*sysname\s+(\S+)"],
        "screenos": [r'(?m)^\s*set hostname\s+"?([^"\r\n]+)"?'],
        "nokia-ipso": [r'(?m)^\s*set hostname\s+"?([^"\r\n]+)"?'],
        "dell-powerconnect": [r'(?m)^\s*hostname\s+"?([^"\r\n]+)"?'],
        "alteon-os": [r'(?m)^\s*(?:/cfg/sys/name|/c/sys/name)\s+(\S+)'],
    }
    for pat in hostname_patterns.get(vendor, [r"(?m)^\s*hostname\s+(\S+)"]):
        m = re.search(pat, text, re.I)
        if m:
            hostname = next((g for g in m.groups() if g), "Unknown").strip('"')
            break

    # OS Version Extraction
    os_version = "Unknown"
    version_patterns = {
        "fortigate": [
            r"(?mi)^Version:\s*FortiGate-\S+\s+v([^,\s]+)",
            r"(?mi)^\s*#config-version=[^:]+:V([^:]+)",
            r"(?mi)^\s*#config-version=(?:FGT|FG)[^\s:]*?-(\d+\.\d+\.\d+)(?:-|:)",
        ],
        "paloalto": [r"<sw-version>([^<]+)</sw-version>", r"<config\b[^>]*version=\"([^\"]+)\"", r"(?mi)^sw-version:\s*(\S+)"],
        "juniper": [r"(?mi)^Junos:\s*(\S+)", r"(?m)^\s*version\s+([^;\s]+)"],
        "cisco-asa": [r"(?mi)^\s*(?:ASA|PIX|FWSM) Version\s+([^\s]+)", r"(?mi)^\s*Cisco Adaptive Security Appliance Software Version\s+([^\s]+)"],
        "cisco-nxos": [r"(?m)^\s*version\s+([^\s]+)"],
        "cisco-ios": [r"(?m)^\s*version\s+([^\s]+)"],
        "watchguard": [r"<for-version>([^<]+)</for-version>"],
        "brocade-ruckus": [r"(?m)^\s*ver\s+([^\s]+)"],
        "arista": [r"(?mi)EOS-([^\s,]+)"],
        "screenos": [r"(?mi)ScreenOS\s+([^\s,]+)", r"(?mi)version\s+([^\s,;]+)"],
        "nokia-ipso": [r"(?mi)IPSO\s+([^\s,]+)"],
    }
    for pat in version_patterns.get(vendor, []):
        m = re.search(pat, text)
        if m:
            os_version = m.group(1).strip()
            break

    # Model Extraction
    model, model_confidence = None, "Unknown"
    if forced_model:
        model = normalize_model(forced_model, vendor) or forced_model.strip()
        model_confidence = "Forced"
        evidence.append("Model forced by --model")
    else:
        exact_patterns = {
            "fortigate": [r"(?mi)^\s*#(?:config-version|conf_file_ver)=([^:]+)", r"(?mi)^Version:\s*(FortiGate-\S+)"],
            "paloalto": [r"<model>([^<]+)</model>", r"(?mi)^model:\s*(\S+)"],
            "juniper": [r"(?mi)^Model:\s*(\S+)", r"<product-model>([^<]+)</product-model>"],
            "cisco-asa": [r"(?mi)^Hardware:\s*([^,]+)", r"(?mi)^(?:PID|Model(?: ID)?):\s*(ASA\S+|PIX\S+|FWSM)"],
            "cisco-nxos": [r"(?mi)\b(Nexus\s*5010|Nexus\s*5\d{3}|Nexus\s*7\d{3}|Nexus\s*9\d{3})\b"],
            "cisco-ios": [r"(?mi)cisco\s+((?:WS-C\d{4}|Catalyst\s*\d{4}|CISCO\d{4}))"],
            "arista": [r"(?mi)device:\s*\S+\s*\(([^,\)]+)", r"(?mi)\b(vEOS|DCS-\d{4}[A-Z]?|7\d{3}[A-Z]?)\b"],
            "aruba-hp": [r"(?mi)\b(ProCurve\s*\S+|Switch\s*\d{4}|J\d{4}[A-Z]?)\b"],
            "brocade-ruckus": [r"(?mi)\b(ICX[- ]?7\d{3}|ICX[- ]?6\d{3}|ICX|FastIron\s*\S+)\b"],
            "extreme": [r"(?mi)\b(Summit[- ]?X\d{3}|BlackDiamond[- ]?\d{4})\b"],
            "f5-bigip": [r"(?mi)\b(BIG-IP\s*(?:\d{4}|VE|VIPRION))\b"],
            "watchguard": [r"<for-model>([^<]+)</for-model>"],
            "screenos": [r"(?mi)\b(SSG[- ]?\d+|ISG[- ]?\d+|NetScreen[- ]?\w+)\b"],
            "nokia-ipso": [r"(?mi)\b(IP\d{3,4})\b"],
            "dell-powerconnect": [r"(?mi)\b(PowerConnect\s*\d{4})\b"],
            "alteon-os": [r"(?mi)\b(Alteon\s*\d{3,4}[a-z]?)\b"],
        }
        for pat in exact_patterns.get(vendor, []):
            m = re.search(pat, text)
            if m and normalize_model(m.group(1), vendor):
                model = normalize_model(m.group(1), vendor)
                model_confidence = "Exact"
                evidence.append("Model marker: " + redact_evidence(m.group(0).strip()))
                break
        if not model:
            for label, candidate in (("hostname", hostname), ("filename", source_name)):
                if normalize_model(candidate, vendor):
                    model = normalize_model(candidate, vendor)
                    model_confidence = "Inferred"
                    evidence.append(f"Model inferred from {label}: {candidate}")
                    break
    model = model or "Unknown"

    warnings = []
    if model in MODEL_NOTES:
        warnings.append(MODEL_NOTES[model])
    if model != "Unknown" and model not in SUPPORTED_MODELS.get(vendor, ()):
        warnings.append("Detected model is outside standard baseline inventory; standard vendor auditing rules applied.")
    if model == "Unknown":
        warnings.append("Hardware model is absent. Append system/version output or use --model for exact asset inventory.")

    return DeviceInfo(vendor, vendor_confidence, model, model_confidence, hostname, os_version,
                      config_format, infer_scope(vendor, lower, config_format), evidence, warnings)


def tokens(value):
    try:
        return shlex.split(value or "", comments=False, posix=True)
    except ValueError:
        return re.findall(r"\S+", value or "")


def flat_tokens(value):
    return [str(item).strip('[]"').lower() for item in tokens(value) if str(item).strip('[]"')]


def setting(settings, key, default=None):
    return settings.get(key, (default, 0))


def absence_confidence(info):
    return "High" if info.scope == "Likely full" else "Low"


# ----------------------------------------------------------------------
# COMPLIANCE CROSS-MAPPING DATABASE (CIS, STIG, NIST 800-53, PCI-DSS, CMMC)
# ----------------------------------------------------------------------
def comp_map(standard_tag):
    catalog = {
        "TELNET": {
            "cis": "CIS Control 4.1: Secure Configuration / CIS Benchmarks Management Access",
            "stig": "V-220521 (CAT I): The network device must not use cleartext protocols for management.",
            "nist_53": "AC-17(2), CM-7, SC-8", "nist_171": "3.1.13, 3.4.7",
            "pci_dss": "Req 2.2.3, 2.2.7", "cmmc": "AC.L2-3.1.13"
        },
        "HTTP": {
            "cis": "CIS Control 4.1: Disable Insecure Web Management",
            "stig": "V-220522 (CAT I): Unencrypted HTTP administration must be disabled.",
            "nist_53": "AC-17(2), CM-7(1)", "nist_171": "3.1.13, 3.4.7",
            "pci_dss": "Req 2.2.3, 2.3.1", "cmmc": "AC.L2-3.1.13"
        },
        "SSH": {
            "cis": "CIS Control 4.1: Enforce SSHv2 and Modern Cryptographic Ciphers",
            "stig": "V-220523 (CAT II): SSH version 2 must be enforced with approved crypto.",
            "nist_53": "AC-17(2), SC-13", "nist_171": "3.1.13, 3.13.11",
            "pci_dss": "Req 2.2.4, 2.3.1", "cmmc": "AC.L2-3.1.13"
        },
        "PWD_ENCR": {
            "cis": "CIS Control 5.2: Use Unique and Reversible-Proof Passwords",
            "stig": "V-220525 (CAT I): Passwords must use strong non-reversible hashing algorithms.",
            "nist_53": "IA-5(1), SC-28", "nist_171": "3.5.1, 3.5.10",
            "pci_dss": "Req 8.3.6", "cmmc": "IA.L2-3.5.1"
        },
        "AAA_LOCKOUT": {
            "cis": "CIS Control 5.4: Implement Centralized AAA and Account Lockout",
            "stig": "V-220526 (CAT II): Devices must enforce logon lockout thresholds.",
            "nist_53": "AC-7, IA-2", "nist_171": "3.1.8, 3.5.1",
            "pci_dss": "Req 8.3.4", "cmmc": "AC.L2-3.1.8"
        },
        "SNMP": {
            "cis": "CIS Control 4.8: Secure SNMP Deployment",
            "stig": "V-220530 (CAT II): Insecure SNMP community strings must be disabled; require SNMPv3.",
            "nist_53": "CM-6, CM-7, IA-2", "nist_171": "3.4.2, 3.5.2",
            "pci_dss": "Req 2.2.1, 2.2.4", "cmmc": "CM.L2-3.4.2"
        },
        "LOGGING": {
            "cis": "CIS Control 8.2, 8.5: Centralized Logging and Audit Trail",
            "stig": "V-220540 (CAT II): The network device must transmit audit records to a central syslog/SIEM.",
            "nist_53": "AU-2, AU-3, AU-6, AU-12", "nist_171": "3.3.1, 3.3.2",
            "pci_dss": "Req 10.2.1, 10.3.1", "cmmc": "AU.L2-3.3.1"
        },
        "TIME": {
            "cis": "CIS Control 8.4: Authoritative Time Source Synchronization",
            "stig": "V-220545 (CAT III): NTP synchronization with trusted sources must be configured.",
            "nist_53": "AU-8(1)", "nist_171": "3.3.7",
            "pci_dss": "Req 10.6.1", "cmmc": "AU.L2-3.3.7"
        },
        "BANNER": {
            "cis": "CIS Control 4.1: Configured Warning and Legal Notices",
            "stig": "V-220510 (CAT III): Display approved legal warning banner prior to logon.",
            "nist_53": "AC-8", "nist_171": "3.1.9",
            "pci_dss": "Req 2.2.1", "cmmc": "AC.L2-3.1.9"
        },
        "PERMISSIVE_POLICY": {
            "cis": "CIS Control 4.4, 12.1: Implement Defensive Firewall Access Rules",
            "stig": "V-239855 (CAT II): Restrict traffic; eliminate permit any-any rules.",
            "nist_53": "AC-3, AC-4, SC-7", "nist_171": "3.1.3, 3.13.1",
            "pci_dss": "Req 1.2.1, 1.3.1", "cmmc": "AC.L1-3.1.1"
        },
        "POLICY_LOGGING": {
            "cis": "CIS Control 8.5: Log Permitted and Denied Network Traffic",
            "stig": "V-239856 (CAT II): Security filter rules must generate log audit events.",
            "nist_53": "AU-2, AU-12", "nist_171": "3.3.1",
            "pci_dss": "Req 10.2.2", "cmmc": "AU.L2-3.3.1"
        },
        "UTM_INSPECTION": {
            "cis": "CIS Control 10: Malware Defenses / Control 13: Network Monitoring",
            "stig": "V-240100 (CAT II): Application and content filtering inspection must be applied.",
            "nist_53": "SI-3, SI-4", "nist_171": "3.14.2, 3.14.4",
            "pci_dss": "Req 5.2.1, 11.4", "cmmc": "SI.L2-3.14.2"
        },
        "WEAK_CRYPTO": {
            "cis": "CIS Control 3.10, 3.11: Modern Cryptographic Ciphers & Algorithms",
            "stig": "V-220550 (CAT I): Deprecated cryptographic ciphers (DES, 3DES, MD5, DH <14) prohibited.",
            "nist_53": "SC-8, SC-13", "nist_171": "3.13.8, 3.13.11",
            "pci_dss": "Req 4.2.1", "cmmc": "SC.L2-3.13.8"
        },
        "SWITCH_SECURITY": {
            "cis": "CIS Control 12.3: Network Infrastructure Segmentation and Layer 2 Security",
            "stig": "V-220560 (CAT II): Spanning tree BPDU guard and port protection must be enforced.",
            "nist_53": "CM-7, SC-7", "nist_171": "3.4.7, 3.13.1",
            "pci_dss": "Req 1.2.5", "cmmc": "CM.L2-3.4.7"
        },
        "LEGACY_SERVICES": {
            "cis": "CIS Control 4.7: Uninstall or Disable Insecure Services",
            "stig": "V-220570 (CAT II): Unnecessary network services (PAD, Finger, BootP) must be disabled.",
            "nist_53": "CM-7(1)", "nist_171": "3.4.6, 3.4.7",
            "pci_dss": "Req 2.2.2", "cmmc": "CM.L2-3.4.6"
        },
    }
    return catalog.get(standard_tag, {})


# ----------------------------------------------------------------------
# VENDOR AUDIT ENGINES (ENTERPRISE & EOL MULTI-VENDOR PLATFORMS)
# ----------------------------------------------------------------------

# --- 1. FORTINET FORTIGATE / FORTIOS ---
def parse_fortigate(lines):
    parsed = {"entries": defaultdict(list), "settings": defaultdict(list)}
    stack = []

    def context():
        return [(block["path"], block["current"]["id"])
                for block in stack if block.get("current")]

    def close_entry(block):
        if block.get("current") is not None:
            block["entries"].append(block["current"])
            block["current"] = None

    def close_block(block):
        close_entry(block)
        if block["entries"]:
            parsed["entries"][block["path"]].extend(block["entries"])
        if block["settings"]:
            parsed["settings"][block["path"]].append({
                "lineno": block["lineno"], "settings": block["settings"],
                "context": block["context"]})

    for lineno, raw in lines:
        value, lowered = raw.strip(), raw.strip().lower()
        if not value or value.startswith("#"):
            continue
        if lowered.startswith("config "):
            stack.append({"path": value[7:].strip().lower(), "lineno": lineno,
                          "settings": {}, "entries": [], "current": None, "context": context()})
        elif lowered.startswith("edit ") and stack:
            close_entry(stack[-1])
            stack[-1]["current"] = {"id": value[5:].strip().strip('"'), "lineno": lineno,
                                     "settings": {}, "context": context()}
        elif lowered == "next" and stack:
            close_entry(stack[-1])
        elif lowered == "end" and stack:
            close_block(stack.pop())
        elif lowered.startswith("set ") and stack:
            key, _, raw_value = value[4:].partition(" ")
            target = stack[-1]["current"]["settings"] if stack[-1]["current"] else stack[-1]["settings"]
            target[key.lower()] = (raw_value.strip(), lineno)
        elif lowered.startswith("unset ") and stack:
            key = value[6:].strip().lower()
            target = stack[-1]["current"]["settings"] if stack[-1]["current"] else stack[-1]["settings"]
            target[key] = (None, lineno)
    while stack:
        close_block(stack.pop())
    return parsed


def forti_setting_blocks(parsed, path):
    return parsed["settings"].get(path, [])


def forti_entries(parsed, path):
    return parsed["entries"].get(path, [])


def forti_context(entry):
    vdoms = [name for path, name in entry.get("context", []) if path == "vdom"]
    return f" [VDOM {vdoms[-1]}]" if vdoms else ""


def check_fortigate(lines, device, info, absence_checks=True):
    parsed, findings = parse_fortigate(lines), []
    permissive, no_logging, disabled, no_inspection = [], [], [], []

    for path in ("firewall policy", "firewall policy6"):
        for entry in forti_entries(parsed, path):
            values = entry["settings"]
            status = (setting(values, "status", "enable")[0] or "enable").lower()
            action = (setting(values, "action", "deny")[0] or "deny").lower()
            name = (setting(values, "name", entry["id"])[0] or entry["id"]).strip('"')
            label = f'{path} {entry["id"]} "{name}"{forti_context(entry)}'
            if status == "disable":
                disabled.append((entry["lineno"], label + ": status disable"))
                continue
            if action != "accept":
                continue
            source = flat_tokens(setting(values, "srcaddr", "")[0])
            destination = flat_tokens(setting(values, "dstaddr", "")[0])
            services = flat_tokens(setting(values, "service", "")[0])
            if "all" in source and "all" in destination and "all" in services:
                permissive.append((entry["lineno"], label + ": all -> all, service ALL, accept"))
            logging = (setting(values, "logtraffic", "")[0] or "").lower()
            if logging in ("", "disable"):
                no_logging.append((entry["lineno"], label + f": logtraffic {logging or 'unset'}"))
            profile_keys = {"av-profile", "webfilter-profile", "dnsfilter-profile", "ips-sensor",
                            "application-list", "ssl-ssh-profile", "profile-group"}
            utm = (setting(values, "utm-status", "disable")[0] or "disable").lower() == "enable"
            if not utm and not any(key in values for key in profile_keys) and ("all" in source or "all" in destination):
                no_inspection.append((entry["lineno"], label + ": broad accept with no security profile evident"))

    if permissive:
        findings.append(Finding("FGT-POL-001", device, "Overly permissive all-to-all accept policy", "High",
            "Firewall policy", "High", permissive[:25],
            "An unrestricted source, destination, and service policy defeats segmentation and expands attack surface.",
            "Replace it with business-justified rules scoped to named interfaces, addresses, users, applications, and services.",
            "fortinet-hardening", comp_map("PERMISSIVE_POLICY"),
            remediation_cmd="config firewall policy\n  edit <ID>\n    set srcaddr <SPECIFIC_SUBNET>\n    set dstaddr <SPECIFIC_HOST>\n    set service <SPECIFIC_SVC>\n  next\nend"))
    if no_logging:
        findings.append(Finding("FGT-LOG-001", device, "Enabled accept policies without traffic logging", "Medium",
            "Logging", "High", no_logging[:25], "Permitted sessions may leave no useful investigation record.",
            "Set logtraffic all or an approved risk-based value and forward relevant logs to central storage/SIEM.",
            "fortinet-hardening", comp_map("POLICY_LOGGING"),
            remediation_cmd="config firewall policy\n  edit <ID>\n    set logtraffic all\n  next\nend"))
    if no_inspection:
        findings.append(Finding("FGT-UTM-001", device, "Broad accept policies without security inspection profiles", "Medium",
            "Threat prevention", "Medium", no_inspection[:25],
            "Uninspected allowed traffic can carry exploits or malware without appropriate detection.",
            "Apply risk-appropriate IPS, antivirus, application, web/DNS, and SSL inspection profiles.",
            "fortinet-profiles", comp_map("UTM_INSPECTION"),
            remediation_cmd="config firewall policy\n  edit <ID>\n    set utm-status enable\n    set ips-sensor default\n    set av-profile default\n  next\nend"))
    if disabled:
        findings.append(Finding("FGT-HYG-001", device, "Disabled firewall policies retained", "Info",
            "Rulebase hygiene", "High", disabled[:25], "Stale policies complicate review and can be re-enabled accidentally.",
            "Confirm ownership and remove obsolete disabled policies through change control.", "fortinet-hardening", comp_map("PERMISSIVE_POLICY"),
            remediation_cmd="config firewall policy\n  delete <ID>\nend"))

    # Management interfaces
    insecure_mgt, broad_mgt = [], []
    for entry in forti_entries(parsed, "system interface"):
        values = entry["settings"]
        allowed = flat_tokens(setting(values, "allowaccess", "")[0])
        bad = sorted(set(allowed) & {"http", "telnet"})
        if bad:
            insecure_mgt.append((entry["lineno"], f'interface "{entry["id"]}": {", ".join(bad)} allowed'))
        role = (setting(values, "role", "")[0] or "").lower()
        alias = (setting(values, "alias", "")[0] or "").lower()
        looks_external = role == "wan" or re.search(r"(^|[-_])(wan|outside|internet)([-_]|$)", entry["id"] + " " + alias, re.I)
        services = sorted(set(allowed) & {"https", "ssh", "snmp", "fgfm"})
        if looks_external and services:
            broad_mgt.append((entry["lineno"], f'possible WAN interface "{entry["id"]}": {", ".join(services)}'))

    if insecure_mgt:
        findings.append(Finding("FGT-MGT-001", device, "Cleartext HTTP/Telnet management enabled", "High",
            "Management plane", "High", insecure_mgt, "Cleartext management exposes credentials and sessions.",
            "Remove HTTP/Telnet; use HTTPS/SSH on dedicated management networks.",
            "fortinet-hardening", comp_map("TELNET"),
            remediation_cmd="config system interface\n  edit <NAME>\n    set allowaccess ping https ssh\n  next\nend"))
    if broad_mgt:
        findings.append(Finding("FGT-MGT-002", device, "Management services enabled on a possible WAN interface", "High",
            "Management plane", "Medium", broad_mgt, "Internet-facing administration increases attack exposure.",
            "Remove WAN management; restrict sources with trusted hosts and local-in policies.",
            "fortinet-hardening", comp_map("TELNET"),
            remediation_cmd="config system interface\n  edit <WAN_NAME>\n    unset allowaccess\n  next\nend"))

    # System global settings
    weak_global = []
    for block in forti_setting_blocks(parsed, "system global"):
        values = block["settings"]
        if (setting(values, "strong-crypto", "enable")[0] or "enable").lower() == "disable":
            weak_global.append((setting(values, "strong-crypto")[1], "set strong-crypto disable"))
        timeout = setting(values, "admintimeout")
        if timeout[0] is not None:
            try:
                if int(timeout[0]) == 0 or int(timeout[0]) > 15:
                    weak_global.append((timeout[1], f"set admintimeout {timeout[0]} (exceeds 15 min)"))
            except ValueError: pass
        lockout = setting(values, "admin-lockout-threshold")
        if lockout[0] is not None:
            try:
                if int(lockout[0]) == 0:
                    weak_global.append((lockout[1], "set admin-lockout-threshold 0 (lockout disabled)"))
            except ValueError: pass
        dh_params = setting(values, "dh-params")
        if dh_params[0] and str(dh_params[0]).isdigit() and int(dh_params[0]) < 2048:
            weak_global.append((dh_params[1], f"set dh-params {dh_params[0]} (<2048 bit)"))
        tls = setting(values, "admin-https-ssl-versions")
        if tls[0] and re.search(r"tlsv1-0|tlsv1-1", tls[0], re.I):
            weak_global.append((tls[1], f"set admin-https-ssl-versions {tls[0]} (legacy TLS permitted)"))

    if weak_global:
        findings.append(Finding("FGT-SYS-001", device, "Weak administrative crypto, lockout, or timeout settings", "High",
            "System hardening", "High", weak_global,
            "Weak management controls increase interception, brute-force, and unattended-session risk.",
            "Enable strong crypto, DH >=2048, TLS 1.2+, non-zero lockout threshold, and short idle timeout.",
            "fortinet-hardening", comp_map("AAA_LOCKOUT"),
            remediation_cmd="config system global\n  set strong-crypto enable\n  set admintimeout 10\n  set admin-lockout-threshold 3\n  set admin-lockout-duration 900\n  set dh-params 2048\nend"))

    # Administrator accounts
    open_admins, no_mfa = [], []
    for entry in forti_entries(parsed, "system admin"):
        values = entry["settings"]
        trust = [value for key, (value, _) in values.items() if key.startswith("trusthost")]
        unrestricted = not trust or any(value is None or re.search(r"^0\.0\.0\.0\s+0\.0\.0\.0$|^::/0$", value.strip()) for value in trust)
        if unrestricted:
            open_admins.append((entry["lineno"], f'admin "{entry["id"]}": no effective trusted-host restriction'))
        remote_group = setting(values, "remote-group")[0]
        two_factor = (setting(values, "two-factor", "disable")[0] or "disable").lower()
        if not remote_group and two_factor in ("", "disable"):
            no_mfa.append((entry["lineno"], f'local admin "{entry["id"]}": two-factor not enabled'))

    if open_admins:
        findings.append(Finding("FGT-USR-001", device, "Administrator account without trusted-host restriction", "Medium",
            "Management plane", "High", open_admins, "Unrestricted admins can be targeted from any reachable address.",
            "Define trusted-host subnets on every administrative account.", "fortinet-hardening", comp_map("TELNET"),
            remediation_cmd="config system admin\n  edit <ADMIN>\n    set trusthost1 10.0.0.0 255.255.0.0\n  next\nend"))
    if no_mfa:
        findings.append(Finding("FGT-USR-002", device, "Local administrator without two-factor authentication", "Medium",
            "Authentication", "High", no_mfa, "Single-factor credentials provide less resistance to credential stuffing or compromise.",
            "Enable FortiToken / MFA or migrate administration to central IdP / RADIUS / SAML.", "fortinet-hardening", comp_map("AAA_LOCKOUT"),
            remediation_cmd="config system admin\n  edit <ADMIN>\n    set two-factor fortitoken\n  next\nend"))

    # SNMP
    snmp_v12, snmp_default = [], []
    for entry in forti_entries(parsed, "system snmp community"):
        snmp_v12.append((entry["lineno"], f'SNMP community id "{entry["id"]}" configured (v1/v2c)'))
        name = (setting(entry["settings"], "name", "")[0] or "").lower().strip('"')
        if name in ("public", "private"):
            snmp_default.append((entry["lineno"], f'SNMP community "{name}" uses well-known default string'))
    if snmp_v12:
        findings.append(Finding("FGT-SNMP-001", device, "SNMP v1/v2c community configuration present", "High",
            "SNMP security", "High", snmp_v12, "SNMP v1/v2c transmits queries, traps, and community strings unencrypted.",
            "Migrate to SNMPv3 with authPriv (SHA-256 and AES-128+) and restrict query sources.", "fortinet-hardening", comp_map("SNMP"),
            remediation_cmd="config system snmp community\n  delete <ID>\nend\nconfig system snmp user\n  edit snmpv3user\n    set security-level auth-priv\n    set auth-proto sha256\n    set priv-proto aes\n  next\nend"))
    if snmp_default:
        findings.append(Finding("FGT-SNMP-002", device, "Default SNMP community string in use", "Critical",
            "SNMP security", "High", snmp_default, "Default community strings are known to automated scanners.",
            "Remove default communities immediately.", "fortinet-hardening", comp_map("SNMP"),
            remediation_cmd="config system snmp community\n  delete <ID>\nend"))

    # VPN / IPsec
    weak_vpn = []
    for entry in forti_entries(parsed, "vpn ipsec phase1-interface"):
        proposals = flat_tokens(setting(entry["settings"], "proposal", "")[0])
        bad = [p for p in proposals if re.search(r"des\b|3des\b|md5\b", p, re.I)]
        if bad:
            weak_vpn.append((entry["lineno"], f'phase1 "{entry["id"]}": proposals contain weak algorithms: {", ".join(bad)}'))
        dh = flat_tokens(setting(entry["settings"], "dhgrp", "")[0])
        weak_dh = [g for g in dh if g in ("1", "2", "5")]
        if weak_dh:
            weak_vpn.append((entry["lineno"], f'phase1 "{entry["id"]}": weak Diffie-Hellman groups: {", ".join(weak_dh)}'))
    if weak_vpn:
        findings.append(Finding("FGT-VPN-001", device, "Weak IPsec cryptography configured", "High",
            "Cryptography", "High", weak_vpn, "Weak ciphers, hashing, or DH groups risk session eavesdropping or cryptanalysis.",
            "Use AES-GCM or AES-256 with SHA-256+ and DH group 14+ (2048-bit) or ECDH 19/20.", "fortinet-hardening", comp_map("WEAK_CRYPTO"),
            remediation_cmd="config vpn ipsec phase1-interface\n  edit <NAME>\n    set proposal aes256-sha256\n    set dhgrp 14 19\n  next\nend"))

    # Absence checks
    if absence_checks:
        confidence = absence_confidence(info)
        ntp_blocks = forti_setting_blocks(parsed, "system ntp")
        ntp_ok = any((setting(block["settings"], "ntpsync", "enable")[0] or "enable").lower() == "enable"
                     for block in ntp_blocks)
        if not ntp_blocks or not ntp_ok:
            findings.append(Finding("FGT-TIME-001", device, "Enabled NTP synchronization not found", "Medium",
                "Time synchronization", confidence, [(0, "config system ntp with ntpsync enable not found")],
                "Unsynchronized timestamps undermine event correlation.",
                "Configure multiple trusted NTP servers and verify synchronization.", "fortinet-hardening", comp_map("TIME"),
                remediation_cmd="config system ntp\n  set type fortiguard\nend"))
        syslog_ok = False
        for suffix in ("", "2", "3", "4"):
            for block in forti_setting_blocks(parsed, f"log syslogd{suffix} setting"):
                values = block["settings"]
                if ((setting(values, "status", "disable")[0] or "disable").lower() == "enable"
                        and setting(values, "server")[0]):
                    syslog_ok = True
        if not syslog_ok:
            findings.append(Finding("FGT-LOG-002", device, "Enabled remote syslog destination not found", "High",
                "Logging", confidence, [(0, "enabled log syslogd setting with server not found")],
                "Local logs can be lost or altered during compromise or failure.",
                "Forward events to redundant protected log collectors/SIEM and monitor delivery.", "fortinet-hardening", comp_map("LOGGING"),
                remediation_cmd="config log syslogd setting\n  set status enable\n  set server <SYSLOG_IP>\nend"))
        password_policy_ok = any((setting(block["settings"], "status", "disable")[0] or "disable").lower() == "enable"
                                 for block in forti_setting_blocks(parsed, "system password-policy"))
        if not password_policy_ok:
            findings.append(Finding("FGT-AUTH-001", device, "Enabled administrator password policy not found", "Medium",
                "Authentication", confidence, [(0, "config system password-policy status enable not found")],
                "Weak or reusable local passwords are easier to compromise.",
                "Enable an administrator password policy aligned with organizational requirements.", "fortinet-hardening", comp_map("AAA_LOCKOUT"),
                remediation_cmd="config system password-policy\n  set status enable\n  set min-lower-case-letter 1\n  set min-upper-case-letter 1\n  set min-non-alphanumeric 1\n  set min-number 1\n  set min-length 14\nend"))

    return findings


# --- 2. PALO ALTO NETWORKS (PAN-OS XML & CLI SET) ---
def xml_to_panos_paths(lines):
    try:
        root = ET.fromstring(joined(lines).lstrip("\ufeff"))
    except ET.ParseError:
        return [], "PAN-OS XML could not be parsed; XML-specific checks were skipped"
    output, ignored = [], {"response", "result", "config"}

    def walk(element, path):
        tag = element.tag.split("}", 1)[-1]
        current = list(path)
        if tag not in ignored:
            if tag == "entry":
                current.append(shlex.quote(element.attrib.get("name", "entry")))
            elif tag == "member":
                value = (element.text or "").strip()
                if value:
                    output.append((0, " ".join(current + [shlex.quote(value)])))
                return
            else:
                current.append(tag)
        if list(element):
            for child in element:
                walk(child, current)
        else:
            value = (element.text or "").strip()
            output.append((0, " ".join(current + ([shlex.quote(value)] if value else []))))
    walk(root, [])
    return output, None


def panos_paths(lines):
    paths = [(n, text.strip()[4:].strip()) for n, text in lines if text.strip().startswith("set ")]
    xml_paths, warning = (xml_to_panos_paths(lines) if re.search(r"<config\b|<response\b", joined(lines), re.I)
                          else ([], None))
    return paths + xml_paths, warning


def parse_panos_rules(paths):
    fields = {"from", "to", "source", "destination", "source-user", "category", "application",
              "service", "action", "log-start", "log-end", "log-setting", "disabled", "description",
              "tag", "schedule", "profile-setting", "option"}
    rules = {}
    for number, path in paths:
        words, index = flat_tokens(path), None
        for candidate, word in enumerate(words):
            if (word in ("rulebase", "pre-rulebase", "post-rulebase") and candidate + 3 < len(words)
                    and words[candidate + 1:candidate + 3] == ["security", "rules"]):
                index = candidate
                break
        if index is None:
            continue
        name = words[index + 3]
        rule = rules.setdefault(name, {"lineno": number, "kind": words[index], "values": defaultdict(list)})
        current = None
        for word in words[index + 4:]:
            if word in fields:
                current = word
                rule["values"].setdefault(current, [])
            elif current:
                rule["values"][current].append(word)
    return rules


def check_paloalto(lines, device, info, absence_checks=True):
    paths, xml_warning = panos_paths(lines)
    findings, rules = [], parse_panos_rules(paths)

    def find(pattern):
        rx = re.compile(pattern, re.I)
        return [(n, path) for n, path in paths if rx.search(path)]

    permissive, no_logging, no_forwarding, service_any, no_profiles, disabled = [], [], [], [], [], []
    for name, rule in rules.items():
        values, label = rule["values"], f'{rule["kind"]} security rule "{name}"'
        if "yes" in values.get("disabled", []):
            disabled.append((rule["lineno"], label + ": disabled yes"))
            continue
        if "allow" not in values.get("action", []):
            continue
        if all("any" in values.get(field, []) for field in ("from", "to", "source", "destination", "application")):
            permissive.append((rule["lineno"], label + ": from/to/source/destination/application any, allow"))
        if "yes" not in values.get("log-end", []):
            no_logging.append((rule["lineno"], label + ": log-end is not yes"))
        if not values.get("log-setting"):
            no_forwarding.append((rule["lineno"], label + ": no log-setting profile"))
        if "any" in values.get("service", []) and "any" not in values.get("application", []):
            service_any.append((rule["lineno"], label + ": service any instead of application-default"))
        if not values.get("profile-setting"):
            no_profiles.append((rule["lineno"], label + ": no profile-setting"))

    default_rules = {}
    for number, path in paths:
        words = flat_tokens(path)
        try:
            index = words.index("default-security-rules")
        except ValueError:
            continue
        if index + 2 >= len(words) or words[index + 1] != "rules":
            continue
        name = words[index + 2]
        data = default_rules.setdefault(name, {"lineno": number, "log-end": False, "log-setting": False})
        remainder = words[index + 3:]
        if remainder[:2] == ["log-end", "yes"]:
            data["log-end"] = True
        if remainder and remainder[0] == "log-setting" and len(remainder) > 1:
            data["log-setting"] = True

    weak_default_logging = [
        (data["lineno"], f'default security rule "{name}": '
         f'log-end={"yes" if data["log-end"] else "not yes"}, '
         f'log-setting={"configured" if data["log-setting"] else "missing"}')
        for name, data in default_rules.items()
        if not data["log-end"] or not data["log-setting"]
    ]

    if permissive:
        findings.append(Finding("PAN-POL-001", device, "Overly permissive any/any allow security rule", "High",
            "Firewall policy", "High", permissive[:25], "An unrestricted rule defeats segmentation and App-ID least privilege.",
            "Constrain zones, sources, destinations, users, and applications.", "palo-policy", comp_map("PERMISSIVE_POLICY"),
            remediation_cmd="set rulebase security rules <RULE> source <ADDR> destination <ADDR> application <APP> service application-default"))
    if no_logging:
        findings.append(Finding("PAN-LOG-001", device, "Allow rules without session-end logging", "Medium",
            "Logging", "High", no_logging[:25], "Allowed sessions may lack required investigation records.",
            "Enable Log at Session End except for documented high-volume exceptions.", "palo-policy", comp_map("POLICY_LOGGING"),
            remediation_cmd="set rulebase security rules <RULE> log-end yes"))
    if no_forwarding:
        findings.append(Finding("PAN-LOG-002", device, "Allow rules without a Log Forwarding profile", "Medium",
            "Logging", "High", no_forwarding[:25], "Local logs may not reach central monitoring/storage.",
            "Attach the approved Log Forwarding profile (often named default).", "palo-logging", comp_map("LOGGING"),
            remediation_cmd="set rulebase security rules <RULE> log-setting <PROFILE_NAME>"))
    if service_any:
        findings.append(Finding("PAN-APP-001", device, "Application rules use service any", "Medium",
            "Application control", "High", service_any[:25], "Applications can run on non-standard ports.",
            "Use application-default unless a documented requirement needs specific ports.", "palo-policy", comp_map("UTM_INSPECTION"),
            remediation_cmd="set rulebase security rules <RULE> service application-default"))
    if no_profiles:
        findings.append(Finding("PAN-THR-001", device, "Allow rules lack Security Profiles/profile group", "High",
            "Threat prevention", "Medium", no_profiles[:25], "Allowed traffic may carry attacks without inspection.",
            "Attach an approved best-practice Security Profile Group and document exceptions.", "palo-policy", comp_map("UTM_INSPECTION"),
            remediation_cmd="set rulebase security rules <RULE> profile-setting group <GROUP_NAME>"))
    if disabled:
        findings.append(Finding("PAN-HYG-001", device, "Disabled security rules retained", "Info",
            "Rulebase hygiene", "High", disabled[:25], "Stale rules complicate review and can be re-enabled.",
            "Confirm ownership and remove obsolete disabled rules.", "palo-policy", comp_map("PERMISSIVE_POLICY"),
            remediation_cmd="delete rulebase security rules <RULE>"))
    if weak_default_logging:
        findings.append(Finding("PAN-LOG-003", device, "Default security rules are not fully logged and forwarded", "Medium",
            "Logging", "High", weak_default_logging[:25],
            "Traffic matching intrazone-default or interzone-default behavior may not reach central monitoring.",
            "Enable session-end logging and attach the approved Log Forwarding profile to default security rules.",
            "palo-policy", comp_map("POLICY_LOGGING"),
            remediation_cmd="set rulebase default-security-rules rules intrazone-default log-end yes log-setting default"))

    telnet = find(r"\bdeviceconfig system service disable-telnet no\b")
    clear_http = find(r"\bdeviceconfig system service disable-http no\b")
    if telnet:
        findings.append(Finding("PAN-MGT-001", device, "Telnet management explicitly enabled", "High",
            "Management plane", "High", telnet, "Telnet exposes credentials and sessions in cleartext.",
            "Disable Telnet and restrict hardened SSH to management sources.", "palo-mgmt", comp_map("TELNET"),
            remediation_cmd="set deviceconfig system service disable-telnet yes"))
    if clear_http:
        findings.append(Finding("PAN-MGT-002", device, "Cleartext HTTP management explicitly enabled", "High",
            "Management plane", "High", clear_http, "HTTP management can expose credentials and session data.",
            "Disable HTTP; use trusted-certificate HTTPS from isolated management hosts.", "palo-mgmt", comp_map("HTTP"),
            remediation_cmd="set deviceconfig system service disable-http yes"))

    weak_crypto = find(r"\b(?:ike|ipsec)[^\n]*(?:encryption|authentication|dh-group)[^\n]*(?:\bdes\b|\b3des\b|\bmd5\b|\bsha1\b|\bgroup[125]\b)")
    if weak_crypto:
        findings.append(Finding("PAN-VPN-001", device, "Weak IKE/IPsec cryptography configured", "High",
            "Cryptography", "High", weak_crypto[:25], "Legacy algorithms weaken tunnel confidentiality and integrity.",
            "Use AES-GCM/AES-256, SHA-256+, and DH group 14 or elliptic-curve groups.", "palo-policy", comp_map("WEAK_CRYPTO"),
            remediation_cmd="set network ike crypto-profiles ipsec-crypto-profiles <NAME> encryption aes-256-gcm authentication none dh-group group14"))

    snmp_v2 = find(r"\b(?:version v2c|snmpv2c|snmp-setting access-setting version v2)\b")
    if snmp_v2:
        findings.append(Finding("PAN-SNMP-001", device, "SNMP v2c configuration detected", "Medium",
            "Management plane", "High", snmp_v2[:25], "SNMPv2c lacks modern authentication/privacy.",
            "Use SNMPv3 with authentication/privacy and restrict managers.", "palo-mgmt", comp_map("SNMP"),
            remediation_cmd="delete deviceconfig system snmp-setting snmpv2c\nset deviceconfig system snmp-setting version v3"))

    if xml_warning:
        findings.append(Finding("PAN-PARSE-001", device, "PAN-OS XML parsing was incomplete", "Info",
            "Input quality", "High", [(0, xml_warning)], "Some controls may not have been evaluated.",
            "Export a valid named configuration snapshot or set-format configuration.", "palo-policy",
            comp_map("PERMISSIVE_POLICY")))

    if absence_checks:
        confidence = absence_confidence(info)
        missing = [
            (r"\bdeviceconfig system permitted-ip\b", "PAN-MGT-003", "Management permitted-IP restriction not found",
             "High", "Management plane", "deviceconfig system permitted-ip not found",
             "The management interface may accept connections from any reachable source.",
             "Restrict management to approved subnets/jump hosts and isolate the path.", "palo-mgmt", "TELNET",
             "set deviceconfig system permitted-ip [ 10.0.0.0/8 ]"),
            (r"\bdeviceconfig system ntp-servers\b", "PAN-TIME-001", "NTP servers not found", "Medium",
             "Time synchronization", "deviceconfig system ntp-servers not found",
             "Unsynchronized timestamps undermine event correlation.",
             "Configure primary and secondary trusted NTP servers.", "palo-mgmt", "TIME",
             "set deviceconfig system ntp-servers primary-ntp-server ntp-server-address <IP>"),
            (r"\bdeviceconfig system login-banner\b", "PAN-BAN-001", "Login warning banner not found", "Info",
             "Legal notice", "deviceconfig system login-banner not found",
             "An approved banner establishes authorized-use expectations.",
             "Configure the organization-approved warning.", "palo-mgmt", "BANNER",
             "set deviceconfig system login-banner \"Authorized access only.\""),
            (r"\bpassword-profile\b", "PAN-AUTH-001", "Administrator password profile not found", "Medium",
             "Authentication", "password-profile not found",
             "Local admin passwords may lack intended length/lifecycle controls.",
             "Assign an approved password profile or centralized authentication with MFA.", "palo-mgmt", "AAA_LOCKOUT",
             "set mgt-config password-complexity enabled yes min-password-length 14"),
        ]
        for pattern, rule_id, title, severity, category, evidence_txt, impact, recommendation, reference, comp_tag, remed_syntax in missing:
            if not find(pattern):
                findings.append(Finding(rule_id, device, title, severity, category, confidence,
                                        [(0, evidence_txt)], impact, recommendation, reference, comp_map(comp_tag),
                                        remediation_cmd=remed_syntax))
    return findings


# --- 3. JUNIPER NETWORKS (JUNOS SRX, EX, MX - HIERARCHICAL & SET CLI) ---
def juniper_to_paths(lines):
    if any(re.match(r"\s*(?:set|deactivate)\s+", text) for _, text in lines[:300]):
        result, deactivated = [], []
        for number, text in lines:
            stripped = text.strip()
            if stripped.startswith("set "):
                result.append((number, stripped[4:].strip(), True))
            elif stripped.startswith("deactivate "):
                deactivated.append((number, stripped[11:].strip()))
        for number, prefix in deactivated:
            matched = False
            for index, (set_number, path, active) in enumerate(result):
                if path == prefix or path.startswith(prefix + " "):
                    result[index] = (set_number, path, False)
                    matched = True
            if not matched:
                result.append((number, prefix + " deactivated", False))
        return result

    result, stack, in_comment = [], [], False
    for number, raw in lines:
        text = raw
        if in_comment:
            if "*/" not in text:
                continue
            text, in_comment = text.split("*/", 1)[1], False
        while "/*" in text:
            before, after = text.split("/*", 1)
            if "*/" in after:
                text = before + " " + after.split("*/", 1)[1]
            else:
                text, in_comment = before, True
                break
        text = re.sub(r"(?<!\S)#.*$", "", text).strip()
        if not text:
            continue
        lexical = re.findall(r'"(?:\\.|[^"])*"|[{};]|[^\s{};]+', text)
        pending = []
        for token in lexical:
            if token == "{":
                name = " ".join(pending).strip()
                if name:
                    stack.append(name)
                pending = []
            elif token == ";":
                statement = " ".join(stack + ([" ".join(pending)] if pending else [])).strip()
                if statement:
                    active = not any(part.startswith("inactive:") for part in stack + pending)
                    statement = re.sub(r"(^|\s)inactive:\s*", r"\1", statement)
                    result.append((number, statement, active))
                pending = []
            elif token == "}":
                if pending:
                    statement = " ".join(stack + [" ".join(pending)]).strip()
                    if statement:
                        result.append((number, statement, True))
                    pending = []
                if stack:
                    stack.pop()
            else:
                pending.append(token)
    return result


def check_juniper(lines, device, info, absence_checks=True):
    paths, findings = juniper_to_paths(lines), []

    def find(pattern, active_only=True):
        rx = re.compile(pattern, re.I)
        return [(n, path) for n, path, active in paths if (active or not active_only) and rx.search(path)]

    telnet = find(r"^system services (?:ftp|telnet|rlogin)\b")
    if telnet:
        findings.append(Finding("JUN-MGT-001", device, "Cleartext FTP/Telnet/Rlogin service enabled", "High",
            "Management plane", "High", telnet, "Cleartext administration exposes credentials and sessions.",
            "Delete FTP/Telnet/Rlogin and use hardened SSH/SCP from restricted management sources.", "juniper-config", comp_map("TELNET"),
            remediation_cmd="delete system services telnet\ndelete system services ftp"))
    http = find(r"^system services web-management http(?:\s|$)")
    if http:
        findings.append(Finding("JUN-MGT-002", device, "Cleartext J-Web HTTP management enabled", "High",
            "Management plane", "High", http, "HTTP management can expose credentials and session data.",
            "Disable HTTP; use HTTPS with a trusted certificate on a restricted management interface.", "juniper-config", comp_map("HTTP"),
            remediation_cmd="delete system services web-management http\nset system services web-management https"))
    weak_ssh = find(r"^system services ssh protocol-version v1-only\b") + find(
        r"^system services ssh root-login allow\b")
    if weak_ssh:
        findings.append(Finding("JUN-SSH-001", device, "Weak SSH configuration", "High",
            "Management plane", "High", weak_ssh[:25],
            "SSHv1 is obsolete, and direct root login reduces accountability.",
            "Use SSHv2 only, deny direct root login, and use named least-privilege accounts.", "juniper-config", comp_map("SSH"),
            remediation_cmd="set system services ssh root-login deny"))

    policies = {}
    policy_rx = re.compile(
        r"^security policies (?:from-zone (\S+) to-zone (\S+) |global )policy (\S+) (.*)$", re.I)
    for number, path, active in paths:
        match = policy_rx.match(path)
        if not match:
            continue
        from_zone, to_zone, name, rest = match.groups()
        key = (from_zone or "global", to_zone or "global", name.strip('"'))
        policy = policies.setdefault(key, {"lineno": number, "active": active, "source": set(),
            "destination": set(), "application": set(), "actions": set(), "logging": set()})
        policy["active"] = policy["active"] and active
        words = flat_tokens(rest)
        if len(words) >= 3 and words[0] == "match":
            field = {"source-address": "source", "destination-address": "destination"}.get(words[1], words[1])
            if field in ("source", "destination", "application"):
                policy[field].update(words[2:])
        if words[:2] == ["then", "permit"]:
            policy["actions"].add("permit")
        if words[:2] in (["then", "deny"], ["then", "reject"]):
            policy["actions"].add("deny")
        if words[:3] in (["then", "log", "session-close"], ["then", "log", "session-init"]):
            policy["logging"].add(words[2])

    permissive, no_logging, inactive = [], [], []
    for (from_zone, to_zone, name), policy in policies.items():
        label = f"{from_zone}->{to_zone} policy {name}"
        if not policy["active"]:
            inactive.append((policy["lineno"], label + ": inactive/deactivated"))
            continue
        if "permit" not in policy["actions"]:
            continue
        if all("any" in policy[field] for field in ("source", "destination", "application")):
            permissive.append((policy["lineno"], label + ": source/destination/application any, permit"))
        if not policy["logging"]:
            no_logging.append((policy["lineno"], label + ": permit with no session logging"))
    if permissive:
        findings.append(Finding("JUN-POL-001", device, "Overly permissive any/any/any permit policy", "High",
            "Firewall policy", "High", permissive[:25], "An unrestricted policy defeats zone segmentation.",
            "Constrain source, destination, application, users, and zone direction.", "juniper-policy", comp_map("PERMISSIVE_POLICY"),
            remediation_cmd="set security policies from-zone <Z1> to-zone <Z2> policy <P> match source-address <SRC> destination-address <DST> application <APP>"))
    if no_logging:
        findings.append(Finding("JUN-LOG-001", device, "Permit policies without session logging", "Medium",
            "Logging", "High", no_logging[:25], "Permitted traffic may not create investigation records.",
            "Add then log session-close where risk/policy requires; use session-init selectively.", "juniper-logging", comp_map("POLICY_LOGGING"),
            remediation_cmd="set security policies from-zone <Z1> to-zone <Z2> policy <P> then log session-close"))
    if inactive:
        findings.append(Finding("JUN-HYG-001", device, "Inactive security policies retained", "Info",
            "Rulebase hygiene", "High", inactive[:25], "Stale policies complicate review and may be activated.",
            "Confirm ownership and remove obsolete inactive policies.", "juniper-policy", comp_map("PERMISSIVE_POLICY"),
            remediation_cmd="delete security policies from-zone <Z1> to-zone <Z2> policy <P>"))

    weak_crypto = find(r"\b(?:des-cbc|3des-cbc|authentication-algorithm (?:hmac-)?(?:md5|sha1)|dh-group group(?:1|2|5))\b")
    if weak_crypto:
        findings.append(Finding("JUN-VPN-001", device, "Weak IPsec/IKE cryptography configured", "High",
            "Cryptography", "High", weak_crypto[:25], "Legacy algorithms weaken VPN confidentiality and integrity.",
            "Use AES-GCM/AES-256, SHA-256+, and DH group 14 or elliptic-curve groups.", "juniper-config", comp_map("WEAK_CRYPTO"),
            remediation_cmd="set security ike proposal <NAME> dh-group group14 authentication-algorithm hmac-sha-256-128 encryption-algorithm aes-256-cbc"))
    plaintext = find(r"\bplain-text-password\b")
    if plaintext:
        findings.append(Finding("JUN-AUTH-001", device, "Plain-text password statement detected", "High",
            "Authentication", "High", plaintext, "Anyone with config access can obtain the credential.",
            "Use encrypted-password/key workflows and rotate the exposed secret.", "juniper-config", comp_map("PWD_ENCR"),
            remediation_cmd="set system login user <USER> authentication encrypted-password <HASH>"))
    weak_hashes = find(r"\bencrypted-password\s+[\"']?\$1\$")
    if weak_hashes:
        findings.append(Finding("JUN-AUTH-002", device, "MD5-crypt password hashes detected", "Medium",
            "Authentication", "High", weak_hashes[:25],
            "MD5-crypt hashes have weak offline password-guessing resistance if the configuration is obtained.",
            "Replace affected passwords using a supported stronger hash and enforce long, unique credentials or MFA.", "juniper-config", comp_map("PWD_ENCR"),
            remediation_cmd="set system login password format sha-512"))
    type9_matches = []
    for n, l in lines:
        m = re.search(r"\b(?:encrypted-password|authentication-key|secret|simple-password)\s+[\"']?(\$9\$[^\s;\"]+)", l, re.I)
        if m:
            token = m.group(1).rstrip("\"'")
            dec = decode_juniper_type9(token)
            suffix = f" [Trivially decoded: \"{dec}\"]" if dec else ""
            type9_matches.append((n, l + suffix))
    if type9_matches:
        findings.append(Finding("JUN-AUTH-003", device, "Juniper $9$ reversible password encryption detected", "High",
            "Authentication", "High", type9_matches[:25],
            "Juniper $9$ uses a weak reversible obfuscation cipher rather than a one-way cryptographic hash. Anyone with configuration access can trivially recover plaintext passwords.",
            "Enforce SHA-512 ($6$) password format or configure master-password with Type 8 (AES256-GCM) encryption.", "juniper-config", comp_map("PWD_ENCR"),
            remediation_cmd="set system login password format sha-512"))
    weak_ntp_auth = find(r"^system ntp authentication-key\b.*\btype md5\b")
    if weak_ntp_auth:
        findings.append(Finding("JUN-TIME-002", device, "NTP authentication uses MD5", "Medium",
            "Time synchronization", "High", weak_ntp_auth,
            "Legacy MD5 authentication provides weaker integrity protection for time synchronization.",
            "Migrate to a stronger supported authenticated time design and rotate the existing NTP key.", "juniper-config", comp_map("TIME"),
            remediation_cmd="set system ntp authentication-key 1 type sha256"))

    host_inbound = find(r"^security zones security-zone \S+(?: interfaces \S+)? host-inbound-traffic "
                        r"(?:system-services (?:all|telnet|http)|protocols all)\b")
    if host_inbound:
        findings.append(Finding("JUN-ZONE-001", device, "Broad or insecure host-inbound services allowed", "High",
            "Management plane", "High", host_inbound[:25],
            "Broad host-inbound access exposes control-plane services to every reachable source.",
            "Permit only required services on specific interfaces and restrict sources.", "juniper-config", comp_map("TELNET"),
            remediation_cmd="set security zones security-zone <ZONE> interfaces <IF> host-inbound-traffic system-services ssh"))

    external_zones = set()
    for _, path, active in paths:
        match = re.match(r"^security zones security-zone (\S+)", path, re.I)
        if active and match and re.search(r"untrust|outside|internet|external|wan", match.group(1), re.I):
            external_zones.add(match.group(1))
    no_screen = []
    for zone in sorted(external_zones):
        if not find(rf"^security zones security-zone {re.escape(zone)} screen\b"):
            no_screen.append((0, f'external-looking zone "{zone}": no screen profile attached'))
    if no_screen:
        findings.append(Finding("JUN-SCR-001", device, "No screen profile found on external-looking zones", "Medium",
            "Threat prevention", "Medium", no_screen,
            "Common reconnaissance and protocol anomalies may lack early detection/dropping.",
            "Create a tested IDS screen option, attach it to untrusted zones, and tune thresholds.", "juniper-config", comp_map("UTM_INSPECTION"),
            remediation_cmd="set security screen ids-option untrust-screen icmp ping-death\nset security zones security-zone untrust screen untrust-screen"))

    communities = {}
    community_rx = re.compile(r"^snmp community (\S+)\s*(.*)$", re.I)
    for number, path, active in paths:
        match = community_rx.match(path)
        if active and match:
            data = communities.setdefault(match.group(1).strip('"'), {"lineno": number, "paths": []})
            data["paths"].append(match.group(2).lower())
    community_evidence, community_high = [], False
    for name, data in communities.items():
        combined, concerns = " ".join(data["paths"]), []
        if name.lower() in ("public", "private"):
            concerns.append("default name")
            community_high = True
        if "authorization read-write" in combined:
            concerns.append("read-write")
            community_high = True
        if "clients" not in combined and "client-list-name" not in combined:
            concerns.append("no client restriction evident")
        community_evidence.append((data["lineno"], "SNMP community <redacted>: " +
                                   ", ".join(concerns or ["v1/v2c community"])))
    if community_evidence:
        findings.append(Finding("JUN-SNMP-001", device, "SNMP v1/v2c community configuration present",
            "High" if community_high else "Medium", "Management plane", "High", community_evidence[:25],
            "Community SNMP lacks SNMPv3 authentication/privacy; unrestricted or write access increases impact.",
            "Migrate to SNMPv3 USM with SHA-2/AES; meanwhile use read-only and explicit clients.", "juniper-snmp", comp_map("SNMP"),
            remediation_cmd="delete snmp community <COMM>\nset snmp v3 usm local-engine user <USER> authentication-sha\nset snmp v3 usm local-engine user <USER> privacy-aes128"))

    if absence_checks:
        confidence = absence_confidence(info)
        if not find(r"^system ntp server\b"):
            findings.append(Finding("JUN-TIME-001", device, "NTP server not found", "Medium",
                "Time synchronization", confidence, [(0, "system ntp server not found")],
                "Unsynchronized timestamps undermine event correlation.",
                "Configure multiple trusted NTP servers and authentication where supported.", "juniper-config", comp_map("TIME"),
                remediation_cmd="set system ntp server <NTP_IP>"))
        if not find(r"^system syslog host\b"):
            findings.append(Finding("JUN-LOG-002", device, "Remote syslog host not found", "High",
                "Logging", confidence, [(0, "system syslog host not found")],
                "Local logs can be lost or altered during compromise or failure.",
                "Forward appropriate facilities/severities to redundant protected collectors/SIEM.", "juniper-config", comp_map("LOGGING"),
                remediation_cmd="set system syslog host <COLLECTOR_IP> any info"))
        if not (find(r"^system login message\b") or find(r"^system login announcement\b")):
            findings.append(Finding("JUN-BAN-001", device, "Login warning banner not found", "Info",
                "Legal notice", confidence, [(0, "system login message/announcement not found")],
                "An approved banner establishes authorized-use expectations.",
                "Configure the organization-approved warning without sensitive details.", "juniper-config", comp_map("BANNER"),
                remediation_cmd="set system login message \"Authorized access only.\""))
    return findings


# --- 4. CISCO ASA / PIX / FWSM ---
def check_cisco_asa(lines, device, info, absence_checks=True):
    findings = []

    def find(pattern):
        rx = re.compile(pattern, re.I)
        return [(number, text) for number, text in lines if rx.search(text)]

    telnet = [item for item in find(r"^\s*(?:telnet\s+|transport input .*\btelnet\b)")
              if not re.match(r"\s*no\s+", item[1], re.I)]
    if telnet:
        findings.append(Finding("ASA-MGT-001", device, "Telnet management enabled or permitted", "High",
            "Management plane", "High", telnet[:25], "Telnet exposes credentials and sessions in cleartext.",
            "Remove Telnet and permit SSHv2 only from dedicated management hosts.", "cisco-mgmt", comp_map("TELNET"),
            remediation_cmd="no telnet 0.0.0.0 0.0.0.0 <INTF>"))
    management_any = find(r"^\s*(?:ssh|http|telnet)\s+(?:0\.0\.0\.0\s+0\.0\.0\.0|any4?|::/0)\b")
    if management_any:
        findings.append(Finding("ASA-MGT-002", device, "Management access permitted from any source", "High",
            "Management plane", "High", management_any[:25],
            "Every reachable source can attempt management authentication.",
            "Restrict SSH/HTTPS to approved management subnets or jump hosts.", "cisco-mgmt", comp_map("TELNET"),
            remediation_cmd="no http 0.0.0.0 0.0.0.0 <INTF>\nhttp 10.0.0.0 255.255.0.0 <INTF>"))
    ssh_v1 = find(r"^\s*ssh version 1\b")
    if ssh_v1:
        findings.append(Finding("ASA-SSH-001", device, "SSHv1 explicitly configured", "High",
            "Management plane", "High", ssh_v1, "SSHv1 has obsolete cryptographic/protocol weaknesses.",
            "Configure SSH version 2 and supported strong algorithms.", "cisco-mgmt", comp_map("SSH"),
            remediation_cmd="ssh version 2"))

    communities = find(r"^\s*snmp-server community\s+\S+")
    if communities:
        default_name = any(re.search(r"community\s+(?:public|private)\b", text, re.I)
                           for _, text in communities)
        evidence = [(n, text + (" (default name detected)" if re.search(
            r"community\s+(?:public|private)\b", text, re.I) else "")) for n, text in communities]
        findings.append(Finding("ASA-SNMP-001", device, "Community-based SNMP configuration present",
            "High" if default_name else "Medium", "Management plane", "High", evidence[:25],
            "SNMPv1/v2c communities lack modern authentication and privacy.",
            "Migrate to SNMPv3 authPriv and restrict access with an ACL.", "cisco-mgmt", comp_map("SNMP"),
            remediation_cmd="no snmp-server community <COMM>\nsnmp-server user <USER> <GRP> v3 auth sha <KEY> priv aes 256 <KEY>"))
    snmp_v3_md5 = find(r"^\s*snmp-server user\b.*\bv3\b.*\bauth md5\b")
    if snmp_v3_md5:
        findings.append(Finding("ASA-SNMP-002", device, "SNMPv3 users configured with MD5 authentication", "Medium",
            "Management plane", "High", snmp_v3_md5[:25],
            "SNMPv3 privacy may be enabled, but MD5 authentication provides weaker integrity protection.",
            "Migrate affected SNMPv3 users to a supported SHA-family authentication algorithm and rotate keys.", "cisco-mgmt", comp_map("SNMP"),
            remediation_cmd="snmp-server user <USER> <GRP> v3 auth sha <KEY> priv aes 256 <KEY>"))

    acl_groups = defaultdict(list)
    for number, text in lines:
        match = re.match(r"^\s*access-list\s+(\S+)\s+(.*)$", text, re.I)
        if match:
            acl_groups[match.group(1)].append((number, match.group(2), text))
    permissive, missing_deny = [], []
    for acl_name, entries in acl_groups.items():
        for number, body, original in entries:
            if re.search(r"\bpermit\s+(?:ip|ip6)\s+(?:any|any4|any6)\s+(?:any|any4|any6)\b", body, re.I):
                permissive.append((number, original))
        extended = [entry for entry in entries if re.search(r"\bextended\b", entry[1], re.I)]
        has_deny = any(re.search(r"\bdeny\s+(?:ip|ip6)\s+(?:any|any4|any6)\s+(?:any|any4|any6)\b",
                                 body, re.I) for _, body, _ in extended)
        if extended and not has_deny:
            missing_deny.append((extended[-1][0], f"ACL {acl_name}: no explicit deny ip any any log found"))
    if permissive:
        findings.append(Finding("ASA-ACL-001", device, "Overly permissive any-to-any ACL entry", "High",
            "Firewall policy", "High", permissive[:25], "An unrestricted permit bypasses least privilege.",
            "Replace it with specific source, destination, protocol, and port entries.", "cisco-mgmt", comp_map("PERMISSIVE_POLICY"),
            remediation_cmd="no access-list <ACL> extended permit ip any any\naccess-list <ACL> extended permit tcp <SRC> <DST> eq <PORT>"))
    if missing_deny:
        findings.append(Finding("ASA-ACL-002", device, "ACLs rely on an unlogged implicit deny", "Low",
            "Firewall policy", "High", missing_deny[:25],
            "Implicit deny blocks traffic but lacks an explicit loggable rule for audit.",
            "Where operationally appropriate, end applied extended ACLs with an explicit logged deny.", "cisco-mgmt", comp_map("POLICY_LOGGING"),
            remediation_cmd="access-list <ACL> extended deny ip any any log"))

    # Legacy Cisco PIX conduit statement
    conduits = [item for item in find(r"^\s*conduit\s+permit\s+ip\s+any\b") if not re.match(r"\s*no\s+", item[1], re.I)]
    if conduits:
        findings.append(Finding("PIX-CON-001", device, "Legacy PIX conduit permits unrestricted inbound IP traffic", "Critical",
            "Firewall policy", "High", conduits[:10],
            "Unrestricted conduit rules permit inbound traffic directly into protected network segments.",
            "Migrate legacy conduit statements to stateful access-list rules scoped to specific hosts and services.",
            "cisco-mgmt", comp_map("PERMISSIVE_POLICY"),
            remediation_cmd="no conduit permit ip any any"))

    # Legacy Cisco PIX / FWSM EOL Hardware Advisory
    if info.model and any(m in info.model.upper() for m in ("PIX", "FWSM")):
        findings.append(Finding("PIX-EOL-001", device, f"Legacy Cisco hardware ({info.model}) is End-of-Life (EOL)", "Medium",
            "Lifecycle", "High", [(0, f"Hardware model: {info.model}")],
            "Cisco PIX and Catalyst 6500 FWSM hardware reached End-of-Life and do not receive firmware or security updates.",
            "Plan hardware migration to Cisco Secure Firewall (Firepower) or modern NGFW.",
            "cisco-mgmt", comp_map("PERMISSIVE_POLICY"),
            remediation_cmd="Plan migration to modern Cisco Secure Firewall"))

    weak_crypto = []
    for pattern in (r"\besp-(?:des|3des|md5-hmac)\b", r"\bencryption\s+(?:des|3des)\b",
                    r"\bhash\s+md5\b", r"\bgroup\s+[125]\b", r"\bsslv3\b",
                    r"\btlsv1(?:\.0|\.1)\b", r"\bssl encryption\b.*\b(?:des|3des|rc4)\b"):
        weak_crypto.extend(find(pattern))
    unique_crypto, seen = [], set()
    for item in weak_crypto:
        if item[0] not in seen:
            seen.add(item[0])
            unique_crypto.append(item)
    if unique_crypto:
        findings.append(Finding("ASA-CRY-001", device, "Weak VPN or management cryptography configured", "High",
            "Cryptography", "High", unique_crypto[:25],
            "Legacy ciphers, hashes, protocol versions, or small DH groups weaken confidentiality/integrity.",
            "Use AES-GCM/AES-256, SHA-256+, DH group 14/EC groups, and TLS 1.2+; coordinate VPN peers.", "cisco-mgmt", comp_map("WEAK_CRYPTO"),
            remediation_cmd="crypto ikev2 policy 10\n  encryption aes-256\n  integrity sha256\n  group 14\nexit"))
    aggressive_mode = find(r"^\s*crypto map\b.*\bset ikev1 phase1-mode aggressive\b")
    if aggressive_mode:
        findings.append(Finding("ASA-VPN-001", device, "IKEv1 aggressive mode configured", "Medium",
            "Cryptography", "High", aggressive_mode[:25],
            "IKEv1 aggressive mode can expose identity information and enables offline attacks against pre-shared keys.",
            "Migrate peers to IKEv2. Until migration, use strong unique keys and avoid aggressive mode where possible.", "cisco-mgmt", comp_map("WEAK_CRYPTO"),
            remediation_cmd="no crypto map <MAP> 10 set ikev1 phase1-mode aggressive"))

    weak_passwords = []
    for number, text in lines:
        stripped = text.strip()
        if (re.match(r"enable password\s+", stripped, re.I)
                and not re.search(r"\b(?:encrypted|pbkdf2)\b", stripped, re.I)):
            weak_passwords.append((number, text))
        elif re.search(r"\bpassword\s+(?:0|7)\s+\S+", stripped, re.I):
            weak_passwords.append((number, text))
        elif re.match(r"password\s+\S+$", stripped, re.I):
            weak_passwords.append((number, text))
    if weak_passwords:
        findings.append(Finding("ASA-AUTH-001", device, "Cleartext or reversibly encoded password detected", "High",
            "Authentication", "High", weak_passwords[:25],
            "Readable or type-7 credentials can be recovered from the configuration.",
            "Replace with strong hashes/centralized authentication and rotate exposed credentials.", "cisco-mgmt", comp_map("PWD_ENCR"),
            remediation_cmd="no enable password\nenable secret <STRONG_PASSWORD>"))

    idle_disabled = find(r"^\s*(?:exec-)?timeout\s+0\s+0\b|^\s*exec-timeout\s+0\s+0\b")
    if idle_disabled:
        findings.append(Finding("ASA-SES-001", device, "Administrative idle timeout disabled", "Medium",
            "Session management", "High", idle_disabled, "Unattended sessions remain available for hijacking.",
            "Set console and remote administration timeouts to an approved short interval.", "cisco-mgmt", comp_map("AAA_LOCKOUT"),
            remediation_cmd="timeout 10 0"))
    same_security = find(r"^\s*same-security-traffic permit inter-interface\b")
    if same_security:
        findings.append(Finding("ASA-SEG-001", device, "Traffic permitted between same-security interfaces", "Medium",
            "Segmentation", "High", same_security,
            "This changes default segmentation and can create lateral paths if ACLs are incomplete.",
            "Validate the need and govern every same-level path with least-privilege ACLs.", "cisco-mgmt", comp_map("PERMISSIVE_POLICY"),
            remediation_cmd="no same-security-traffic permit inter-interface"))

    if absence_checks:
        confidence = absence_confidence(info)
        if not find(r"^\s*aaa authentication (?:ssh|http|enable|serial) console\b"):
            findings.append(Finding("ASA-AAA-001", device, "AAA for administrative access not found", "Medium",
                "Authentication", confidence, [(0, "aaa authentication <management-method> console not found")],
                "Shared/local-only authentication reduces accountability and lifecycle control.",
                "Configure named-user AAA, preferably TACACS+/RADIUS with controlled local fallback/accounting.", "cisco-mgmt", comp_map("AAA_LOCKOUT"),
                remediation_cmd="aaa authentication ssh console TACACS LOCAL"))
        ntp = find(r"^\s*ntp server\b")
        if not ntp:
            findings.append(Finding("ASA-TIME-001", device, "NTP server not found", "Medium",
                "Time synchronization", confidence, [(0, "ntp server not found")],
                "Unsynchronized timestamps undermine event correlation.",
                "Configure multiple trusted NTP servers and authentication where supported.", "cisco-mgmt", comp_map("TIME"),
                remediation_cmd="ntp server <NTP_IP>"))
        elif len(ntp) == 1:
            findings.append(Finding("ASA-TIME-002", device, "Only one NTP server found", "Low",
                "Time synchronization", "High", ntp, "A single time source is an availability dependency.",
                "Configure an additional independent trusted NTP source.", "cisco-mgmt", comp_map("TIME"),
                remediation_cmd="ntp server <SECONDARY_NTP_IP>"))
        if not find(r"^\s*logging host\b"):
            findings.append(Finding("ASA-LOG-001", device, "Remote logging host not found", "High",
                "Logging", confidence, [(0, "logging host not found")],
                "Local logs can be lost or altered during compromise or failure.",
                "Enable logging and forward events to redundant protected collectors/SIEM.", "cisco-mgmt", comp_map("LOGGING"),
                remediation_cmd="logging enable\nlogging host <INTF> <SYSLOG_IP>"))
        if not find(r"^\s*threat-detection basic-threat\b"):
            findings.append(Finding("ASA-THR-001", device, "Basic threat detection not found", "Medium",
                "Threat prevention", confidence, [(0, "threat-detection basic-threat not found")],
                "Basic scanning and threat-rate visibility may be reduced.",
                "Enable/tune basic threat detection if supported by the release and monitoring design.", "cisco-mgmt", comp_map("UTM_INSPECTION"),
                remediation_cmd="threat-detection basic-threat"))
        if not find(r"^\s*banner (?:login|motd|exec)\b"):
            findings.append(Finding("ASA-BAN-001", device, "Login warning banner not found", "Info",
                "Legal notice", confidence, [(0, "banner login/motd/exec not found")],
                "An approved banner establishes authorized-use expectations.",
                "Configure the organization-approved warning without sensitive details.", "cisco-mgmt", comp_map("BANNER"),
                remediation_cmd="banner motd \"Authorized access only.\""))
    return findings


# --- 5. CISCO IOS & IOS-XE (ROUTERS & CATALYST SWITCHES) ---
def check_cisco_ios(lines, device, info, absence_checks=True):
    findings, text = [], joined(lines)

    # Telnet & VTY Transport
    vty_telnet = []
    vty_no_acl = []
    in_vty = False
    vty_lineno = 0
    transport_ssh_only = False
    has_acl = False

    for n, l in lines:
        raw = l.strip()
        if re.search(r"^line\s+vty\b", raw, re.I):
            in_vty = True
            vty_lineno = n
            transport_ssh_only = False
            has_acl = False
        elif in_vty and (raw.startswith("line ") or raw.startswith("!") or raw.startswith("router ")):
            if not transport_ssh_only:
                vty_telnet.append((vty_lineno, "line vty: telnet permitted or transport input ssh not enforced"))
            if not has_acl:
                vty_no_acl.append((vty_lineno, "line vty: no inbound access-class restriction configured"))
            in_vty = False
        elif in_vty:
            if re.search(r"transport\s+input\s+.*telnet\b|transport\s+input\s+all\b", raw, re.I):
                vty_telnet.append((n, raw))
            elif re.search(r"transport\s+input\s+ssh\b", raw, re.I):
                transport_ssh_only = True
            if re.search(r"access-class\s+\S+\s+in\b", raw, re.I):
                has_acl = True

    if in_vty:
        if not transport_ssh_only:
            vty_telnet.append((vty_lineno, "line vty: transport input ssh not enforced"))
        if not has_acl:
            vty_no_acl.append((vty_lineno, "line vty: no inbound access-class restriction"))

    if vty_telnet:
        findings.append(Finding("CISCO-TEL-001", device, "Cleartext Telnet permitted on administrative VTY lines", "High",
            "Management plane", "High", vty_telnet[:10],
            "Telnet sends credentials in plain-text, enabling sniffing and session interception.",
            "Enforce transport input ssh on all VTY lines.", "cisco-ios-hardening", comp_map("TELNET"),
            remediation_cmd="line vty 0 15\n  transport input ssh\nexit"))
    if vty_no_acl:
        findings.append(Finding("CISCO-MGT-001", device, "VTY lines without inbound access-class restriction", "High",
            "Management plane", "Medium", vty_no_acl[:10],
            "Unrestricted VTY access allows any network entity to attempt administrative logon.",
            "Apply an inbound access-class restricting management to authorized subnets.", "cisco-ios-hardening", comp_map("TELNET"),
            remediation_cmd="ip access-list standard MGT-ACL\n  permit 10.0.0.0 0.255.255.255\nexit\nline vty 0 15\n  access-class MGT-ACL in\nexit"))

    # Cleartext HTTP Server
    http_srv = [(n, l) for n, l in lines if re.search(r"^\s*ip\s+http\s+server\b", l, re.I) and not re.search(r"no\s+ip\s+http\s+server", l, re.I)]
    if http_srv:
        findings.append(Finding("CISCO-HTTP-001", device, "Cleartext HTTP administrative server enabled", "High",
            "Management plane", "High", http_srv,
            "The web administration server transmits plaintext data over port 80.",
            "Disable ip http server and enable ip http secure-server with TLS.", "cisco-ios-hardening", comp_map("HTTP"),
            remediation_cmd="no ip http server\nip http secure-server"))

    # SSH Configuration
    no_ssh2 = [(n, l) for n, l in lines if re.search(r"^\s*(?:no\s+ip\s+ssh\s+version|ip\s+ssh\s+version\s+1)\b", l, re.I)]
    if not re.search(r"^\s*ip\s+ssh\s+version\s+2\b", text, re.M | re.I):
        findings.append(Finding("CISCO-SSH-001", device, "SSH version 2 is not strictly enforced", "High",
            "Management plane", "High", no_ssh2 or [(0, "ip ssh version 2 missing")],
            "Without version 2 enforcement, devices may negotiate legacy SSHv1.",
            "Configure ip ssh version 2 and generate a >=2048-bit RSA key.", "cisco-ios-hardening", comp_map("SSH"),
            remediation_cmd="ip ssh version 2\ncrypto key generate rsa modulus 2048"))

    # Password Encryption & Storage
    enable_pwd = [(n, l) for n, l in lines if re.search(r"^\s*enable\s+password\b", l, re.I)]
    type7_pwd = []
    for n, l in lines:
        m = re.search(r"(?:password|secret)\s+7\s+([0-9a-fA-F]+)", l, re.I)
        if m:
            dec = decode_cisco_type7(m.group(1))
            suffix = f" [Trivially decoded: \"{dec}\"]" if dec else ""
            type7_pwd.append((n, l + suffix))
    type5_pwd = [(n, l) for n, l in lines if re.search(r"(?:password|secret)\s+5\s+\$1\$", l, re.I)]
    no_pw_enc = [(n, l) for n, l in lines if re.search(r"^\s*no\s+service\s+password-encryption\b", l, re.I)]
    plain_user_pwd = [(n, l) for n, l in lines if re.search(r"^\s*username\s+\S+\s+(?:privilege\s+\d+\s+)?password\s+(?:0\s+)?(?![5789]\b|pbkdf2|scrypt)\S+", l, re.I)]

    if enable_pwd:
        findings.append(Finding("CISCO-PWD-001", device, "Legacy enable password statement in use", "High",
            "Authentication", "High", enable_pwd,
            "The 'enable password' statement uses weak reversible or plaintext encryption.",
            "Replace enable password with enable secret using PBKDF2 (Type 8) or Scrypt (Type 9).", "cisco-ios-hardening", comp_map("PWD_ENCR"),
            remediation_cmd="no enable password\nenable secret <STRONG_PASSWORD>"))
    if type7_pwd:
        findings.append(Finding("CISCO-PWD-002", device, "Cisco Type 7 reversible password encryption detected", "High",
            "Authentication", "High", type7_pwd[:10],
            "Cisco Type 7 uses a trivial XOR Vigenere algorithm easily decrypted in seconds.",
            "Use 'secret' instead of 'password' statements with Type 8 or 9 hashing.", "cisco-ios-hardening", comp_map("PWD_ENCR"),
            remediation_cmd="service password-encryption\nenable secret <STRONG_PASSWORD>"))
    if type5_pwd:
        findings.append(Finding("CISCO-PWD-003", device, "Cisco Type 5 (MD5 crypt) password hashes detected", "Medium",
            "Authentication", "High", type5_pwd[:10],
            "Type 5 MD5 passwords can be rapidly cracked with standard dictionary hash tables.",
            "Enforce algorithm-type sha256 or scrypt for user secrets.", "cisco-ios-hardening", comp_map("PWD_ENCR"),
            remediation_cmd="username <USER> algorithm-type sha256 secret <STRONG_PASSWORD>"))
    if no_pw_enc or not re.search(r"^\s*service\s+password-encryption\b", text, re.M | re.I):
        findings.append(Finding("CISCO-PWD-004", device, "Service password-encryption is not enabled", "High",
            "Authentication", "High", no_pw_enc or [(0, "service password-encryption missing")],
            "Passwords displayed in cleartext expose administrative credentials to passersby.",
            "Enable service password-encryption.", "cisco-ios-hardening", comp_map("PWD_ENCR"),
            remediation_cmd="service password-encryption"))
    if plain_user_pwd:
        findings.append(Finding("CISCO-PWD-005", device, "Plaintext local user password statement detected", "High",
            "Authentication", "High", plain_user_pwd[:10],
            "Local user accounts configured with plaintext passwords expose administrative credentials in configuration exports.",
            "Replace plaintext password statements with 'algorithm-type sha256 secret' or 'secret' statements.", "cisco-ios-hardening", comp_map("PWD_ENCR"),
            remediation_cmd="username <USER> secret <STRONG_PASSWORD>"))

    # AAA & Lockout
    if not re.search(r"^\s*aaa\s+new-model\b", text, re.M | re.I):
        findings.append(Finding("CISCO-AAA-001", device, "Centralized AAA (aaa new-model) is not enabled", "High",
            "Authentication", "High", [(0, "aaa new-model not found")],
            "Devices without AAA lack role-based access control, accounting, and central authorization.",
            "Enable aaa new-model and configure RADIUS or TACACS+ authentication.", "cisco-ios-hardening", comp_map("AAA_LOCKOUT"),
            remediation_cmd="aaa new-model\naaa authentication login default group radius local"))
    if not re.search(r"^\s*login\s+block-for\b", text, re.M | re.I):
        findings.append(Finding("CISCO-AAA-002", device, "Administrative logon failure lockout not configured", "Medium",
            "Authentication", "Medium", [(0, "login block-for statement missing")],
            "Without lockout controls, attackers can brute-force administrative passwords indefinitely.",
            "Configure 'login block-for' to lock out consecutive failed login attempts.", "cisco-ios-hardening", comp_map("AAA_LOCKOUT"),
            remediation_cmd="login block-for 900 attempts 3 within 120\nlogin on-failure log\nlogin on-success log"))

    # SNMP
    snmp_comm = [(n, l) for n, l in lines if re.search(r"^\s*snmp-server\s+community\s+(\S+)", l, re.I)]
    snmp_default = [(n, l) for n, l in lines if re.search(r"^\s*snmp-server\s+community\s+(?:public|private)\b", l, re.I)]
    snmp_rw = [(n, l) for n, l in lines if re.search(r"^\s*snmp-server\s+community\s+\S+\s+RW\b", l, re.I)]

    if snmp_comm:
        findings.append(Finding("CISCO-SNMP-001", device, "SNMP v1/v2c community string configured", "High",
            "SNMP security", "High", snmp_comm[:10],
            "SNMPv1/v2c transmits management traffic and communities in cleartext.",
            "Migrate to SNMPv3 with authPriv security level.", "cisco-ios-hardening", comp_map("SNMP"),
            remediation_cmd="no snmp-server community <COMM>\nsnmp-server group MGT-GRP v3 priv\nsnmp-server user MGT-USR MGT-GRP v3 auth sha <KEY> priv aes 256 <KEY>"))
    if snmp_default:
        findings.append(Finding("CISCO-SNMP-002", device, "Default SNMP community string in use", "Critical",
            "SNMP security", "High", snmp_default,
            "Default community strings (public/private) allow immediate reconnaissance or modification.",
            "Remove default communities immediately.", "cisco-ios-hardening", comp_map("SNMP"),
            remediation_cmd="no snmp-server community public\nno snmp-server community private"))
    if snmp_rw:
        findings.append(Finding("CISCO-SNMP-003", device, "SNMP write access (RW) enabled", "High",
            "SNMP security", "High", snmp_rw,
            "Write community strings allow remote attackers to modify device configurations or reboot devices.",
            "Revoke write permissions and restrict SNMP to read-only with SNMPv3.", "cisco-ios-hardening", comp_map("SNMP"),
            remediation_cmd="no snmp-server community <COMM> RW"))

    # Insecure Legacy Services (Finger, PAD, Small Servers, BOOTP)
    insecure_svc = [(n, l) for n, l in lines if re.search(r"^\s*(?:service\s+finger|service\s+pad|service\s+udp-small-servers|service\s+tcp-small-servers|ip\s+bootp\s+server)\b", l, re.I)]
    if insecure_svc:
        findings.append(Finding("CISCO-SVC-001", device, "Insecure legacy network services running", "Medium",
            "Network services", "High", insecure_svc,
            "Legacy protocols like Finger, PAD, and Small Servers leak information or facilitate DoS attacks.",
            "Disable unnecessary legacy services.", "cisco-ios-hardening", comp_map("LEGACY_SERVICES"),
            remediation_cmd="no service finger\nno service pad\nno service udp-small-servers\nno service tcp-small-servers\nno ip bootp server"))

    # Layer 2 Switch Hardening (BPDU Guard)
    if re.search(r"(?:spanning-tree|Catalyst)", text, re.I):
        if not re.search(r"spanning-tree\s+portfast\s+bpduguard\s+default\b", text, re.I):
            findings.append(Finding("CISCO-STP-001", device, "Spanning Tree BPDU Guard not enabled globally on access ports", "Medium",
                "Switch security", "Medium", [(0, "spanning-tree portfast bpduguard default missing")],
                "Without BPDU guard, unauthorized rogue switches can alter STP topology and intercept traffic.",
                "Enable BPDU Guard globally across portfast edge access ports.", "cisco-ios-hardening", comp_map("SWITCH_SECURITY"),
                remediation_cmd="spanning-tree portfast bpduguard default\nspanning-tree loopguard default"))

    # Insecure Network Protocols (Proxy ARP, Source Routing, Directed Broadcast)
    src_route = [(n, l) for n, l in lines if re.search(r"^\s*ip\s+source-route\b", l, re.I)]
    if src_route:
        findings.append(Finding("CISCO-NET-001", device, "IP source routing is enabled", "Medium",
            "Network protocols", "High", src_route,
            "Source routing allows packets to specify their path, bypassing perimeter security filters.",
            "Disable IP source routing.", "cisco-ios-hardening", comp_map("SWITCH_SECURITY"),
            remediation_cmd="no ip source-route"))

    # Absence checks
    if absence_checks:
        conf = absence_confidence(info)
        if not re.search(r"^\s*logging\s+host\b", text, re.M | re.I):
            findings.append(Finding("CISCO-LOG-001", device, "Remote syslog host not configured", "High",
                "Logging", conf, [(0, "logging host missing")],
                "Local logs are volatile; off-box syslog is vital for incident investigation.",
                "Configure logging host to forward events to redundant SIEM collectors.", "cisco-ios-hardening", comp_map("LOGGING"),
                remediation_cmd="logging host <SYSLOG_IP>\nlogging trap informational\nservice timestamps log datetime msec show-timezone"))
        if not re.search(r"^\s*ntp\s+server\b", text, re.M | re.I):
            findings.append(Finding("CISCO-TIME-001", device, "NTP time synchronization not configured", "Medium",
                "Time synchronization", conf, [(0, "ntp server missing")],
                "Unsynchronized clocks impede correlation across security incident timelines.",
                "Configure redundant NTP servers with authentication.", "cisco-ios-hardening", comp_map("TIME"),
                remediation_cmd="ntp server <NTP_IP>\nntp authenticate"))
        if not re.search(r"^\s*banner\s+(?:motd|login)\b", text, re.M | re.I):
            findings.append(Finding("CISCO-BAN-001", device, "Login / MOTD warning banner not configured", "Info",
                "Legal notice", conf, [(0, "banner motd/login missing")],
                "A legal banner gives legal notice of monitoring and authorized access restrictions.",
                "Configure an approved login/MOTD banner.", "cisco-ios-hardening", comp_map("BANNER"),
                remediation_cmd="banner motd ^C Authorized Access Only ^C"))

    return findings


# --- 6. CISCO NX-OS (NEXUS DATA CENTER SWITCHES) ---
def check_cisco_nxos(lines, device, info, absence_checks=True):
    findings, text = [], joined(lines)

    # Feature Telnet
    telnet = [(n, l) for n, l in lines if re.search(r"^\s*feature\s+telnet\b", l, re.I)]
    if telnet:
        findings.append(Finding("NXOS-TEL-001", device, "Telnet feature enabled on Nexus switch", "High",
            "Management plane", "High", telnet,
            "Telnet sends unencrypted management credentials across the network.",
            "Disable feature telnet and enforce SSHv2.", "cisco-nxos-hardening", comp_map("TELNET"),
            remediation_cmd="no feature telnet"))

    # Password Strength Check Disabled
    no_pw_strength = [(n, l) for n, l in lines if re.search(r"^\s*no\s+password\s+strength-check\b", l, re.I)]
    if no_pw_strength:
        findings.append(Finding("NXOS-PWD-001", device, "Password strength checking is disabled", "Medium",
            "Authentication", "High", no_pw_strength,
            "Disabling password strength checking allows users to configure easily guessable passwords.",
            "Enable password strength checking.", "cisco-nxos-hardening", comp_map("AAA_LOCKOUT"),
            remediation_cmd="password strength-check"))

    # Reversible / Plaintext Passwords
    type7_pwd = []
    for n, l in lines:
        m = re.search(r"\b(?:password|secret)\s+7\s+([0-9a-fA-F]+)", l, re.I)
        if m:
            dec = decode_cisco_type7(m.group(1))
            suffix = f" [Trivially decoded: \"{dec}\"]" if dec else ""
            type7_pwd.append((n, l + suffix))
    if type7_pwd:
        findings.append(Finding("NXOS-PWD-002", device, "Cisco Type 7 reversible password encryption detected", "High",
            "Authentication", "High", type7_pwd[:10],
            "Type 7 encryption uses a trivial XOR cipher that is instantly reversible to cleartext.",
            "Enforce Type 8 (PBKDF2) or Type 9 (Scrypt) password hashing.", "cisco-nxos-hardening", comp_map("PWD_ENCR"),
            remediation_cmd="username <USER> passphrase <STRONG_PASSWORD>"))

    # DSA SSH Key
    dsa_key = [(n, l) for n, l in lines if re.search(r"^\s*ssh\s+key\s+dsa\b", l, re.I)]
    if dsa_key:
        findings.append(Finding("NXOS-SSH-001", device, "Legacy DSA SSH host key configured", "High",
            "Management plane", "High", dsa_key,
            "DSA keys are limited to 1024 bits and deprecated in modern SSH implementations.",
            "Generate RSA >=2048-bit or ECDSA host keys.", "cisco-nxos-hardening", comp_map("SSH"),
            remediation_cmd="ssh key rsa 2048"))

    # Absence checks
    if absence_checks:
        conf = absence_confidence(info)
        if not re.search(r"^\s*logging\s+server\b", text, re.M | re.I):
            findings.append(Finding("NXOS-LOG-001", device, "Remote logging server not configured", "High",
                "Logging", conf, [(0, "logging server missing")],
                "Central log collection is mandatory for audit trails and threat detection.",
                "Configure logging server.", "cisco-nxos-hardening", comp_map("LOGGING"),
                remediation_cmd="logging server <SYSLOG_IP> 6"))
        if not re.search(r"^\s*ntp\s+server\b", text, re.M | re.I):
            findings.append(Finding("NXOS-TIME-001", device, "NTP time server not configured", "Medium",
                "Time synchronization", conf, [(0, "ntp server missing")],
                "Without NTP synchronization, timestamps cannot be trusted for forensics.",
                "Configure redundant NTP servers.", "cisco-nxos-hardening", comp_map("TIME"),
                remediation_cmd="ntp server <NTP_IP> use-vrf management"))
        if not re.search(r"^\s*banner\s+motd\b", text, re.M | re.I):
            findings.append(Finding("NXOS-BAN-001", device, "MOTD legal banner not configured", "Info",
                "Legal notice", conf, [(0, "banner motd missing")],
                "Legal notice banner must notify users of authorized monitoring.",
                "Configure an approved MOTD login banner.", "cisco-nxos-hardening", comp_map("BANNER"),
                remediation_cmd="banner motd # Authorized Access Only #"))

    return findings


# --- 7. CHECK POINT (GAIA / R8X / SMARTCENTER) ---
def check_checkpoint(lines, device, info, absence_checks=True):
    findings, text = [], joined(lines)
    permissive = [(n, l) for n, l in lines if re.search(r":action\s+\(accept\).*?:src\s+\(Any\).*?:dst\s+\(Any\)", l, re.I) or re.search(r"permit\s+any\s+any", l, re.I)]
    if permissive:
        findings.append(Finding("CHK-POL-001", device, "Overly permissive Any-to-Any accept rule in policy", "High",
            "Firewall policy", "High", permissive[:10],
            "Broad allow rules undermine network segmentation.",
            "Scope the rule to specific sources, destinations, and services.", "checkpoint-hardening", comp_map("PERMISSIVE_POLICY"),
            remediation_cmd="Replace Any-to-Any rule with specific host/network objects in SmartConsole"))

    snmp_comm = [(n, l) for n, l in lines if re.search(r"set\s+snmp\s+community\s+(\S+)", l, re.I)]
    if snmp_comm:
        findings.append(Finding("CHK-SNMP-001", device, "SNMP community string configured", "High",
            "SNMP security", "High", snmp_comm[:10],
            "SNMP v1/v2c communities are sent in cleartext across the network.",
            "Use SNMPv3 with USM authentication and privacy.", "checkpoint-hardening", comp_map("SNMP"),
            remediation_cmd="set snmp usm user <USER> security-level authPriv"))

    plain_pwd = [(n, l) for n, l in lines if re.search(r"^\s*set\s+user\s+\S+\s+password\s+(?!-hash\b)\S+", l, re.I)]
    if plain_pwd:
        findings.append(Finding("CHK-PWD-001", device, "Plaintext local user password statement detected", "High",
            "Authentication", "High", plain_pwd[:10],
            "Configuring local users with cleartext passwords exposes credentials in Gaia Clish backups.",
            "Use password-hash with SHA-512 instead of plaintext password statements.", "checkpoint-hardening", comp_map("PWD_ENCR"),
            remediation_cmd="set user <USER> password-hash <SHA512_HASH>"))

    if absence_checks:
        conf = absence_confidence(info)
        if not re.search(r"set\s+ntp\s+server\b|ntp", text, re.I):
            findings.append(Finding("CHK-TIME-001", device, "NTP server configuration not found", "Medium",
                "Time synchronization", conf, [(0, "ntp server missing")],
                "Accurate time synchronization is required for SIC and audit logging.",
                "Configure NTP servers.", "checkpoint-hardening", comp_map("TIME"),
                remediation_cmd="set ntp server primary <IP> version 4\nset ntp active enable"))
        if not re.search(r"set\s+message\s+banner\b|banner", text, re.I):
            findings.append(Finding("CHK-BAN-001", device, "Login banner not configured", "Info",
                "Legal notice", conf, [(0, "message banner missing")],
                "A warning banner must be presented before administrative logon.",
                "Configure an approved login warning banner.", "checkpoint-hardening", comp_map("BANNER"),
                remediation_cmd="set message banner on\nset message banner text \"Authorized access only.\""))

    return findings


# --- 8. ARISTA EOS ---
def check_arista(lines, device, info, absence_checks=True):
    findings, text = [], joined(lines)
    http_api = [(n, l) for n, l in lines if re.search(r"^\s*protocol\s+http(?!\S)", l, re.I) and "http-commands" in text]
    if http_api:
        findings.append(Finding("ARISTA-HTTP-001", device, "Unencrypted HTTP management API enabled", "High",
            "Management plane", "High", http_api,
            "eAPI over unencrypted HTTP exposes tokens and administrative commands.",
            "Disable HTTP and restrict eAPI to HTTPS.", "arista-hardening", comp_map("HTTP"),
            remediation_cmd="management api http-commands\n  no protocol http\n  protocol https\nexit"))

    telnet = [(n, l) for n, l in lines if re.search(r"^\s*no\s+management\s+telnet\b", l, re.I) is None and re.search(r"management\s+telnet", l, re.I)]
    if telnet:
        findings.append(Finding("ARISTA-TEL-001", device, "Telnet management enabled", "High",
            "Management plane", "High", telnet,
            "Telnet transmits authentication credentials unencrypted.",
            "Disable telnet and use SSH exclusively.", "arista-hardening", comp_map("TELNET"),
            remediation_cmd="no management telnet"))

    snmp_comm = [(n, l) for n, l in lines if re.search(r"^\s*snmp-server\s+community\s+(\S+)", l, re.I)]
    if snmp_comm:
        findings.append(Finding("ARISTA-SNMP-001", device, "SNMP v1/v2c community string present", "High",
            "SNMP security", "High", snmp_comm[:10],
            "SNMPv1/v2c strings are transmitted in cleartext.",
            "Migrate to SNMPv3 authPriv.", "arista-hardening", comp_map("SNMP"),
            remediation_cmd="no snmp-server community <COMM>\nsnmp-server user <USER> <GRP> v3 auth sha <KEY> priv aes <KEY>"))

    type7_pwd = []
    for n, l in lines:
        m = re.search(r"\b(?:secret|password)\s+7\s+([0-9a-fA-F]+)", l, re.I)
        if m:
            dec = decode_cisco_type7(m.group(1))
            suffix = f" [Trivially decoded: \"{dec}\"]" if dec else ""
            type7_pwd.append((n, l + suffix))
    if type7_pwd:
        findings.append(Finding("ARISTA-PWD-001", device, "Type 7 reversible password encryption detected", "High",
            "Authentication", "High", type7_pwd[:10],
            "Type 7 encryption uses a trivial XOR cipher that is easily reversed to cleartext.",
            "Configure user secrets using SHA-512 (secret sha512) or modern hash algorithm.", "arista-hardening", comp_map("PWD_ENCR"),
            remediation_cmd="username <USER> secret sha512 <PASSWORD>"))

    if absence_checks:
        conf = absence_confidence(info)
        if not re.search(r"^\s*logging\s+host\b", text, re.M | re.I):
            findings.append(Finding("ARISTA-LOG-001", device, "Remote syslog host not configured", "High",
                "Logging", conf, [(0, "logging host missing")],
                "Remote logging is required for central security monitoring.",
                "Configure logging host.", "arista-hardening", comp_map("LOGGING"),
                remediation_cmd="logging host <SYSLOG_IP>"))
        if not re.search(r"^\s*ntp\s+server\b", text, re.M | re.I):
            findings.append(Finding("ARISTA-TIME-001", device, "NTP server not configured", "Medium",
                "Time synchronization", conf, [(0, "ntp server missing")],
                "Accurate time synchronization is essential for audit reliability.",
                "Configure NTP servers.", "arista-hardening", comp_map("TIME"),
                remediation_cmd="ntp server <NTP_IP>"))
        if not re.search(r"^\s*banner\s+login\b", text, re.M | re.I):
            findings.append(Finding("ARISTA-BAN-001", device, "Login banner not configured", "Info",
                "Legal notice", conf, [(0, "banner login missing")],
                "Display approved security warning banner before logon.",
                "Configure login banner.", "arista-hardening", comp_map("BANNER"),
                remediation_cmd="banner login\nAuthorized access only.\nEOF"))

    return findings


# --- 9. ARUBA / HPE PROCURVE ---
def check_aruba_hp(lines, device, info, absence_checks=True):
    findings, text = [], joined(lines)
    if not re.search(r"no\s+telnet-server\b", text, re.I):
        findings.append(Finding("ARUBA-TEL-001", device, "Telnet server is not disabled", "High",
            "Management plane", "High", [(0, "no telnet-server not found")],
            "Telnet transmits passwords in cleartext.",
            "Disable telnet server.", "aruba-hardening", comp_map("TELNET"),
            remediation_cmd="no telnet-server"))

    snmp_comm = [(n, l) for n, l in lines if re.search(r"^\s*snmp-server\s+community\s+(\S+)", l, re.I)]
    snmp_default = [(n, l) for n, l in lines if re.search(r"^\s*snmp-server\s+community\s+\"?public\"?", l, re.I)]
    if snmp_comm:
        findings.append(Finding("ARUBA-SNMP-001", device, "SNMP community strings configured", "High",
            "SNMP security", "High", snmp_comm[:10],
            "SNMPv1/v2c communicates without encryption.",
            "Upgrade to SNMPv3.", "aruba-hardening", comp_map("SNMP"),
            remediation_cmd="no snmp-server community <COMM>\nsnmpv3 user <USER> auth sha <KEY> priv aes <KEY>"))
    if snmp_default:
        findings.append(Finding("ARUBA-SNMP-002", device, "Default SNMP community string 'public' configured", "Critical",
            "SNMP security", "High", snmp_default,
            "Default community strings are easily exploitable.",
            "Remove public community string.", "aruba-hardening", comp_map("SNMP"),
            remediation_cmd="no snmp-server community public"))

    if absence_checks:
        conf = absence_confidence(info)
        if not re.search(r"^\s*(?:logging|syslog-server)\s+\S+", text, re.M | re.I):
            findings.append(Finding("ARUBA-LOG-001", device, "Remote syslog server not configured", "High",
                "Logging", conf, [(0, "logging server missing")],
                "Central log collection is necessary for monitoring.",
                "Configure remote syslog logging.", "aruba-hardening", comp_map("LOGGING"),
                remediation_cmd="logging <SYSLOG_IP>"))
        if not re.search(r"^\s*(?:sntp\s+server|ntp\s+server)\b", text, re.M | re.I):
            findings.append(Finding("ARUBA-TIME-001", device, "SNTP/NTP server not configured", "Medium",
                "Time synchronization", conf, [(0, "sntp server missing")],
                "Ensure clocks are synchronized across network switches.",
                "Configure SNTP/NTP servers.", "aruba-hardening", comp_map("TIME"),
                remediation_cmd="sntp server priority 1 <NTP_IP>"))
        if not re.search(r"^\s*banner\s+motd\b", text, re.M | re.I):
            findings.append(Finding("ARUBA-BAN-001", device, "MOTD banner not configured", "Info",
                "Legal notice", conf, [(0, "banner motd missing")],
                "Display approved legal warning notice.",
                "Configure authorized-use warning banner.", "aruba-hardening", comp_map("BANNER"),
                remediation_cmd="banner motd \"Authorized access only.\""))

    return findings


# --- 10. BROCADE / FOUNDRY / RUCKUS ---
def check_brocade(lines, device, info, absence_checks=True):
    findings, text = [], joined(lines)
    super_pw = [(n, l) for n, l in lines if re.search(r"^\s*enable\s+super-user-password\s+\S+", l, re.I)]
    if super_pw:
        findings.append(Finding("BROC-PWD-001", device, "Super-user-password configured in plaintext", "High",
            "Authentication", "High", super_pw,
            "Plaintext administrative passwords risk exposure during backups.",
            "Encrypt super-user-password with modern hash.", "brocade-hardening", comp_map("PWD_ENCR"),
            remediation_cmd="enable super-user-password ....."))

    snmp_comm = [(n, l) for n, l in lines if re.search(r"^\s*snmp-server\s+community\s+(\S+)", l, re.I)]
    if snmp_comm:
        findings.append(Finding("BROC-SNMP-001", device, "SNMP community strings configured", "High",
            "SNMP security", "High", snmp_comm[:10],
            "SNMP v1/v2c communities are unencrypted.",
            "Upgrade to SNMPv3.", "brocade-hardening", comp_map("SNMP"),
            remediation_cmd="no snmp-server community <COMM>"))

    if absence_checks:
        conf = absence_confidence(info)
        if not re.search(r"^\s*logging\s+host\b", text, re.M | re.I):
            findings.append(Finding("BROC-LOG-001", device, "Remote syslog host not configured", "High",
                "Logging", conf, [(0, "logging host missing")],
                "Forward switch logs to central storage.",
                "Configure remote syslog host.", "brocade-hardening", comp_map("LOGGING"),
                remediation_cmd="logging host <SYSLOG_IP>"))
        if not re.search(r"^\s*ntp\s+server\b", text, re.M | re.I):
            findings.append(Finding("BROC-TIME-001", device, "NTP server not configured", "Medium",
                "Time synchronization", conf, [(0, "ntp server missing")],
                "Ensure accurate timestamping for event logs.",
                "Configure NTP servers.", "brocade-hardening", comp_map("TIME"),
                remediation_cmd="ntp server <NTP_IP>"))
        if not re.search(r"^\s*banner\s+motd\b", text, re.M | re.I):
            findings.append(Finding("BROC-BAN-001", device, "MOTD banner not configured", "Info",
                "Legal notice", conf, [(0, "banner motd missing")],
                "Configure authorized-use warning banner.",
                "Configure an approved login/MOTD banner.", "brocade-hardening", comp_map("BANNER"),
                remediation_cmd="banner motd ^C Authorized access only ^C"))

    return findings


# --- 11. EXTREME NETWORKS (EXTREMEXOS) ---
def check_extreme(lines, device, info, absence_checks=True):
    findings, text = [], joined(lines)
    telnet = [(n, l) for n, l in lines if re.search(r"enable\s+telnet\b", l, re.I) and not re.search(r"disable\s+telnet", l, re.I)]
    if telnet:
        findings.append(Finding("EXT-TEL-001", device, "Telnet service is enabled on ExtremeXOS", "High",
            "Management plane", "High", telnet,
            "Telnet exposes management passwords over cleartext.",
            "Disable telnet and enforce SSH2.", "extreme-hardening", comp_map("TELNET"),
            remediation_cmd="disable telnet\nenable ssh2"))

    snmp_comm = [(n, l) for n, l in lines if re.search(r"configure\s+snmp\s+add\s+community", l, re.I)]
    if snmp_comm:
        findings.append(Finding("EXT-SNMP-001", device, "SNMP v1/v2c community configured", "High",
            "SNMP security", "High", snmp_comm[:10],
            "SNMP community strings are unencrypted.",
            "Use SNMPv3.", "extreme-hardening", comp_map("SNMP"),
            remediation_cmd="configure snmpv3 add user <USER> authentication sha <KEY> privacy aes <KEY>"))

    if absence_checks:
        conf = absence_confidence(info)
        if not re.search(r"configure\s+syslog\s+add\b", text, re.I):
            findings.append(Finding("EXT-LOG-001", device, "Remote syslog collector not configured", "High",
                "Logging", conf, [(0, "configure syslog add missing")],
                "Forward switch logs to central SIEM.",
                "Configure remote syslog collector.", "extreme-hardening", comp_map("LOGGING"),
                remediation_cmd="configure syslog add <SYSLOG_IP>:514 local0"))
        if not re.search(r"configure\s+sntp\s+add\b", text, re.I):
            findings.append(Finding("EXT-TIME-001", device, "SNTP/NTP server not configured", "Medium",
                "Time synchronization", conf, [(0, "configure sntp add missing")],
                "Maintain accurate switch timestamps.",
                "Configure SNTP servers.", "extreme-hardening", comp_map("TIME"),
                remediation_cmd="configure sntp add server <NTP_IP>"))
        if not re.search(r"configure\s+banner\b", text, re.I):
            findings.append(Finding("EXT-BAN-001", device, "Logon banner not configured", "Info",
                "Legal notice", conf, [(0, "configure banner missing")],
                "Configure authorized-use login notice.",
                "Configure login banner.", "extreme-hardening", comp_map("BANNER"),
                remediation_cmd="configure banner before-login \"Authorized access only.\""))

    return findings


# --- 12. F5 NETWORKS BIG-IP (TMOS) ---
def check_f5(lines, device, info, absence_checks=True):
    findings, text = [], joined(lines)
    open_mgmt = [(n, l) for n, l in lines if re.search(r"allow\s*\{\s*all\s*\}", l, re.I) and ("httpd" in text or "sshd" in text)]
    if open_mgmt:
        findings.append(Finding("F5-MGT-001", device, "Management services (httpd/sshd) allow unrestricted network access", "High",
            "Management plane", "High", open_mgmt[:10],
            "Allowing 'all' sources to access BIG-IP management interfaces increases exposure.",
            "Restrict allow list to authorized administrative management subnets.", "f5-hardening", comp_map("TELNET"),
            remediation_cmd="modify sys httpd allow replace-all-with { 10.0.0.0/8 }\nmodify sys sshd allow replace-all-with { 10.0.0.0/8 }"))

    if not re.search(r"auth\s+password-policy\b", text, re.I):
        findings.append(Finding("F5-PWD-001", device, "Password policy enforcement is not configured", "Medium",
            "Authentication", "Medium", [(0, "auth password-policy block missing")],
            "Without password policies, accounts may use weak or short passwords.",
            "Configure password-policy with minimum length and complexity.", "f5-hardening", comp_map("AAA_LOCKOUT"),
            remediation_cmd="modify auth password-policy min-length 14 policy-enforcement enabled"))

    if absence_checks:
        conf = absence_confidence(info)
        if not re.search(r"sys\s+syslog\b.*remote-servers", text, re.DOTALL | re.I):
            findings.append(Finding("F5-LOG-001", device, "Remote syslog servers not configured", "High",
                "Logging", conf, [(0, "sys syslog remote-servers missing")],
                "Forward BIG-IP audit and traffic logs to remote collectors.",
                "Configure remote syslog servers.", "f5-hardening", comp_map("LOGGING"),
                remediation_cmd="modify sys syslog remote-servers add { mysyslog { host <SYSLOG_IP> } }"))
        if not re.search(r"sys\s+ntp\b.*servers", text, re.DOTALL | re.I):
            findings.append(Finding("F5-TIME-001", device, "NTP servers not configured", "Medium",
                "Time synchronization", conf, [(0, "sys ntp servers missing")],
                "Ensure BIG-IP system time is synchronized.",
                "Configure NTP servers.", "f5-hardening", comp_map("TIME"),
                remediation_cmd="modify sys ntp servers add { <NTP_IP> }"))
        if not re.search(r"banner\s+text\b", text, re.I):
            findings.append(Finding("F5-BAN-001", device, "Pre-login banner not configured", "Info",
                "Legal notice", conf, [(0, "sys sshd/httpd banner text missing")],
                "Configure warning banner for administrative access.",
                "Configure pre-login banner.", "f5-hardening", comp_map("BANNER"),
                remediation_cmd="modify sys sshd banner enabled banner-text \"Authorized access only.\""))

    return findings


# --- 13. WATCHGUARD FIREBOX (XML & CLI) ---
def check_watchguard(lines, device, info, absence_checks=True):
    findings, text = [], joined(lines)
    snmp_pub = [(n, l) for n, l in lines if re.search(r"<snmp-comm-string>\s*public\s*</snmp-comm-string>", l, re.I)]
    if snmp_pub:
        findings.append(Finding("WG-SNMP-001", device, "Default SNMP community string 'public' configured", "Critical",
            "SNMP security", "High", snmp_pub,
            "Default community strings allow unauthorized status monitoring.",
            "Change SNMP community string to a strong secret or use SNMPv3.", "watchguard-hardening", comp_map("SNMP"),
            remediation_cmd="Change SNMP community string in Fireware Web UI / Policy Manager"))

    any_filter = [(n, l) for n, l in lines if "<from-alias-list>" in text and "<to-alias-list>" in text and "Any" in l]
    if any_filter:
        findings.append(Finding("WG-POL-001", device, "Unrestricted Any-to-Any policy rule detected", "High",
            "Firewall policy", "Medium", any_filter[:5],
            "Broad packet filter rules undermine firewall protection.",
            "Replace with specific proxy policies (HTTP-proxy, HTTPS-proxy, etc.).", "watchguard-hardening", comp_map("PERMISSIVE_POLICY"),
            remediation_cmd="Configure granular proxies in WatchGuard Policy Manager"))

    if absence_checks:
        conf = absence_confidence(info)
        if not re.search(r"<log-server\b|<syslog-server\b", text, re.I):
            findings.append(Finding("WG-LOG-001", device, "Remote WatchGuard Log Server / Syslog not configured", "High",
                "Logging", conf, [(0, "log-server / syslog-server missing")],
                "Forward logs to WatchGuard Dimension or central SIEM.",
                "Configure Log Server or syslog in Fireware.", "watchguard-hardening", comp_map("LOGGING"),
                remediation_cmd="Add Log Server / Syslog in Fireware System Parameters"))
        if not re.search(r"<ntp-server\b", text, re.I):
            findings.append(Finding("WG-TIME-001", device, "NTP server not configured", "Medium",
                "Time synchronization", conf, [(0, "ntp-server missing")],
                "Configure trusted NTP time sources.",
                "Configure NTP synchronization.", "watchguard-hardening", comp_map("TIME"),
                remediation_cmd="Enable NTP in Fireware System Parameters"))

    return findings


# --- 14. HUAWEI VRP ---
def check_huawei(lines, device, info, absence_checks=True):
    findings, text = [], joined(lines)
    telnet = [(n, l) for n, l in lines if re.search(r"^\s*telnet\s+server\s+enable\b", l, re.I)]
    if telnet:
        findings.append(Finding("HUA-TEL-001", device, "Telnet server is enabled", "High",
            "Management plane", "High", telnet,
            "Telnet sends administrative credentials in cleartext.",
            "Disable telnet and enforce Stelnet (SSH).", "huawei-hardening", comp_map("TELNET"),
            remediation_cmd="undo telnet server enable\nstelnet server enable"))

    snmp_comm = [(n, l) for n, l in lines if re.search(r"^\s*snmp-agent\s+community\s+", l, re.I)]
    if snmp_comm:
        findings.append(Finding("HUA-SNMP-001", device, "SNMP community string configured", "High",
            "SNMP security", "High", snmp_comm[:10],
            "SNMPv1/v2c communicates without encryption.",
            "Upgrade to SNMPv3.", "huawei-hardening", comp_map("SNMP"),
            remediation_cmd="undo snmp-agent community\nsnmp-agent group v3 <GRP> privacy"))

    simple_pwd = [(n, l) for n, l in lines if re.search(r"^\s*(?:set\s+super\s+password|local-user\s+\S+\s+password)\s+simple\b", l, re.I)]
    if simple_pwd:
        findings.append(Finding("HUA-PWD-001", device, "Plaintext simple password configured", "High",
            "Authentication", "High", simple_pwd[:10],
            "Huawei simple password parameter stores credentials in unencrypted plaintext.",
            "Use the cipher parameter or modern irreversibly hashed authentication.", "huawei-hardening", comp_map("PWD_ENCR"),
            remediation_cmd="local-user <USER> password cipher <STRONG_PASSWORD>"))

    if absence_checks:
        conf = absence_confidence(info)
        if not re.search(r"info-center\s+loghost\b", text, re.I):
            findings.append(Finding("HUA-LOG-001", device, "Remote syslog host not configured", "High",
                "Logging", conf, [(0, "info-center loghost missing")],
                "Forward switch logs to central log collector.",
                "Configure info-center loghost.", "huawei-hardening", comp_map("LOGGING"),
                remediation_cmd="info-center loghost <SYSLOG_IP>"))
        if not re.search(r"ntp-service\s+unicast-server\b", text, re.I):
            findings.append(Finding("HUA-TIME-001", device, "NTP server not configured", "Medium",
                "Time synchronization", conf, [(0, "ntp-service unicast-server missing")],
                "Configure authoritative NTP time synchronization.",
                "Configure NTP unicast servers.", "huawei-hardening", comp_map("TIME"),
                remediation_cmd="ntp-service unicast-server <NTP_IP>"))

    return findings


# --- 15. JUNIPER SCREENOS / NETSCREEN (SSG, ISG, NETSCREEN - EOL) ---
def check_screenos(lines, device, info, absence_checks=True):
    findings, text = [], joined(lines)

    any_policy = [(n, l) for n, l in lines if re.search(r"^\s*set\s+policy\s+id\s+\d+.*?(?:\"Any\"|any)\s+(?:\"Any\"|any)\s+(?:\"ANY\"|any)\s+permit", l, re.I)]
    if any_policy:
        findings.append(Finding("SCREEN-POL-001", device, "Overly permissive Any-to-Any permit policy rule detected", "High",
            "Firewall policy", "High", any_policy[:10],
            "Unrestricted Any-to-Any permit rules allow uncontrolled traffic across security zones.",
            "Scope the policy to authorized source/destination addresses and services.",
            "screenos-hardening", comp_map("PERMISSIVE_POLICY"),
            remediation_cmd="set policy id <ID> from <SRC_ZONE> to <DST_ZONE> <SRC_ADDR> <DST_ADDR> <SVC> permit"))

    unlogged = [(n, l) for n, l in lines if re.search(r"^\s*set\s+policy\s+id\s+\d+.*?permit\s*$", l, re.I) and "log" not in l.lower()]
    if unlogged:
        findings.append(Finding("SCREEN-LOG-001", device, "Permit policy rules without session logging", "Medium",
            "Logging", "High", unlogged[:10],
            "Permitted sessions that are not logged hinder security audit trails and forensic investigations.",
            "Enable logging on all permit policies.",
            "screenos-hardening", comp_map("LOGGING"),
            remediation_cmd="set policy id <ID> log"))

    cleartext_mgt = [(n, l) for n, l in lines if re.search(r"^\s*set\s+admin\s+(?:telnet|http)\b|^\s*set\s+interface\s+\S+\s+manage\s+(?:telnet|http)\b", l, re.I)]
    if cleartext_mgt:
        findings.append(Finding("SCREEN-MGT-001", device, "Cleartext Telnet or HTTP management enabled", "High",
            "Management plane", "High", cleartext_mgt,
            "Cleartext protocols transmit administrative passwords unencrypted across the network.",
            "Disable Telnet and HTTP; enforce SSH and SSL exclusively.",
            "screenos-hardening", comp_map("TELNET"),
            remediation_cmd="unset admin telnet\nunset admin http"))

    plain_pw = [(n, l) for n, l in lines if re.search(r"^\s*set\s+admin\s+password\s+\"[^\"]+\"", l, re.I)]
    if plain_pw:
        findings.append(Finding("SCREEN-PWD-001", device, "Administrator password configured in cleartext format", "High",
            "Authentication", "High", plain_pw,
            "Passwords saved in cleartext can be read from configuration files and backups.",
            "Configure strong encrypted passwords with MD5 or modern hashes.",
            "screenos-hardening", comp_map("PWD_ENCR"),
            remediation_cmd="set admin password <STRONG_PASSWORD>"))

    snmp_comm = [(n, l) for n, l in lines if re.search(r"^\s*set\s+snmp\s+community\s+\"?(\S+?)\"?", l, re.I)]
    snmp_pub = [(n, l) for n, l in lines if re.search(r"^\s*set\s+snmp\s+community\s+\"?(?:public|private)\"?", l, re.I)]
    if snmp_pub:
        findings.append(Finding("SCREEN-SNMP-002", device, "Default SNMP community string configured", "Critical",
            "SNMP security", "High", snmp_pub,
            "Default community strings are known to attackers and allow unauthorized information gathering.",
            "Remove default community strings.",
            "screenos-hardening", comp_map("SNMP"),
            remediation_cmd="unset snmp community public"))
    elif snmp_comm:
        findings.append(Finding("SCREEN-SNMP-001", device, "SNMP v1/v2c community string configured", "High",
            "SNMP security", "High", snmp_comm[:10],
            "SNMP v1/v2c queries and community strings are sent unencrypted.",
            "Disable SNMPv1/v2c or migrate to SNMPv3.",
            "screenos-hardening", comp_map("SNMP"),
            remediation_cmd="unset snmp community <COMM>"))

    weak_crypto = [(n, l) for n, l in lines if re.search(r"^\s*set\s+(?:ike|ipsec)\s+proposal\s+.*?enc (?:des|3des)\b|auth md5\b", l, re.I)]
    if weak_crypto:
        findings.append(Finding("SCREEN-CRY-001", device, "Weak DES/3DES or MD5 VPN cryptography configured", "High",
            "Cryptography", "High", weak_crypto,
            "Legacy cryptographic algorithms are vulnerable to practical cryptanalysis and eavesdropping.",
            "Configure AES-GCM or AES-256 with SHA-256 and DH Group 14 or higher.",
            "screenos-hardening", comp_map("SSH"),
            remediation_cmd="set ike proposal <NAME> enc aes-256 auth sha2-256 dh-group group14"))

    findings.append(Finding("SCREEN-EOL-001", device, "ScreenOS platform is officially End-of-Life (EOL)", "Medium",
        "Lifecycle", "High", [(0, "ScreenOS firmware detected: " + info.os_version)],
        "End-of-Life devices no longer receive security patches, firmware updates, or bug fixes.",
        "Plan hardware refresh to modern supported platforms (e.g. Juniper SRX).",
        "screenos-hardening", comp_map("PERMISSIVE_POLICY"),
        remediation_cmd="Replace device with modern supported firewall hardware"))

    if absence_checks:
        conf = absence_confidence(info)
        if not re.search(r"^\s*set\s+syslog\s+config\b", text, re.M | re.I):
            findings.append(Finding("SCREEN-LOG-002", device, "Remote syslog collector not configured", "High",
                "Logging", conf, [(0, "set syslog config missing")],
                "Without remote syslog forwarding, local security logs are vulnerable to tampering or loss.",
                "Configure remote syslog logging.",
                "screenos-hardening", comp_map("LOGGING"),
                remediation_cmd="set syslog config <SYSLOG_IP> facilities local0 local0"))
        if not re.search(r"^\s*set\s+ntp\s+server\b", text, re.M | re.I):
            findings.append(Finding("SCREEN-TIME-001", device, "NTP time server not configured", "Medium",
                "Time synchronization", conf, [(0, "set ntp server missing")],
                "Synchronized clocks are essential for security correlation and incident investigation.",
                "Configure authoritative NTP servers.",
                "screenos-hardening", comp_map("TIME"),
                remediation_cmd="set ntp server <NTP_IP>"))
        if not re.search(r"^\s*set\s+banner\b", text, re.M | re.I):
            findings.append(Finding("SCREEN-BAN-001", device, "Pre-login security warning banner not configured", "Info",
                "Legal notice", conf, [(0, "set banner missing")],
                "An approved legal banner gives legal notice of monitoring and unauthorized access restrictions.",
                "Configure authorized-use warning banner.",
                "screenos-hardening", comp_map("BANNER"),
                remediation_cmd="set banner \"Authorized access only. All activities are monitored and logged.\""))

    return findings


# --- 16. NOKIA IPSO (IP390, IP560, IP1280, IP2450 - EOL) ---
def check_nokia_ipso(lines, device, info, absence_checks=True):
    findings, text = [], joined(lines)

    telnet = [(n, l) for n, l in lines if re.search(r"^\s*set\s+telnet\s+active\s+on\b|^\s*set\s+interface\s+\S+\s+telnet\s+on\b", l, re.I)]
    if telnet:
        findings.append(Finding("IPSO-TEL-001", device, "Telnet administrative management enabled", "High",
            "Management plane", "High", telnet,
            "Telnet transmits authentication credentials in cleartext over the network.",
            "Disable Telnet and enforce SSHv2.",
            "nokia-ipso-hardening", comp_map("TELNET"),
            remediation_cmd="set telnet active off"))

    snmp_comm = [(n, l) for n, l in lines if re.search(r"^\s*set\s+snmp\s+community\s+(\S+)", l, re.I)]
    if snmp_comm:
        findings.append(Finding("IPSO-SNMP-001", device, "SNMP community string configured", "High",
            "SNMP security", "High", snmp_comm[:10],
            "SNMPv1/v2c communicates without encryption.",
            "Disable SNMPv1/v2c communities and use secure management protocols.",
            "nokia-ipso-hardening", comp_map("SNMP"),
            remediation_cmd="set snmp community <COMM> active off"))

    plain_pwd = [(n, l) for n, l in lines if re.search(r"^\s*(?:add\s+user\s+\S+\s+password|set\s+user\s+\S+\s+password)\s+(?!hash\b)\S+", l, re.I)]
    if plain_pwd:
        findings.append(Finding("IPSO-PWD-001", device, "Plaintext local user password configured", "High",
            "Authentication", "High", plain_pwd[:10],
            "Plaintext user passwords in Nokia IPSO configuration files expose administrator credentials.",
            "Use hashed credentials or central authentication.",
            "nokia-ipso-hardening", comp_map("PWD_ENCR"),
            remediation_cmd="set user <USER> password-hash <HASH>"))

    findings.append(Finding("IPSO-EOL-001", device, "Nokia IPSO operating system is End-of-Life (EOL)", "Medium",
        "Lifecycle", "High", [(0, "Nokia IPSO detected")],
        "Nokia IPSO platforms have been replaced by Check Point Gaia OS and no longer receive security updates.",
        "Migrate to supported Check Point Quantum hardware running Gaia OS.",
        "nokia-ipso-hardening", comp_map("PERMISSIVE_POLICY"),
        remediation_cmd="Upgrade to Check Point Gaia OS on supported hardware"))

    if absence_checks:
        conf = absence_confidence(info)
        if not re.search(r"^\s*set\s+syslog\b", text, re.M | re.I):
            findings.append(Finding("IPSO-LOG-001", device, "Remote syslog collector not configured", "High",
                "Logging", conf, [(0, "set syslog missing")],
                "Remote audit logging is required for central security monitoring.",
                "Configure remote syslog logging.",
                "nokia-ipso-hardening", comp_map("LOGGING"),
                remediation_cmd="set syslog host <SYSLOG_IP> active on"))
        if not re.search(r"^\s*set\s+ntp\s+server\b", text, re.M | re.I):
            findings.append(Finding("IPSO-TIME-001", device, "NTP server not configured", "Medium",
                "Time synchronization", conf, [(0, "set ntp server missing")],
                "Accurate time synchronization is required for audit records.",
                "Configure authoritative NTP servers.",
                "nokia-ipso-hardening", comp_map("TIME"),
                remediation_cmd="set ntp server <NTP_IP> active on"))
        if not re.search(r"^\s*set\s+banner\b", text, re.M | re.I):
            findings.append(Finding("IPSO-BAN-001", device, "Login warning banner not configured", "Info",
                "Legal notice", conf, [(0, "set banner missing")],
                "Display approved security warning banner before logon.",
                "Configure login banner.",
                "nokia-ipso-hardening", comp_map("BANNER"),
                remediation_cmd="set banner \"Authorized access only.\""))

    return findings


# --- 17. DELL POWERCONNECT (CLASSIC SWITCHES - EOL) ---
def check_dell_powerconnect(lines, device, info, absence_checks=True):
    findings, text = [], joined(lines)

    telnet = [(n, l) for n, l in lines if re.search(r"^\s*ip\s+telnet\s+server\b", l, re.I)]
    if telnet:
        findings.append(Finding("DELL-TEL-001", device, "Telnet server is enabled on Dell PowerConnect", "High",
            "Management plane", "High", telnet,
            "Telnet communicates without encryption, exposing administrative credentials.",
            "Disable Telnet server and enforce SSHv2.",
            "dell-hardening", comp_map("TELNET"),
            remediation_cmd="no ip telnet server"))

    snmp_comm = [(n, l) for n, l in lines if re.search(r"^\s*snmp-server\s+community\s+(\S+)", l, re.I)]
    if snmp_comm:
        findings.append(Finding("DELL-SNMP-001", device, "SNMP community string configured", "High",
            "SNMP security", "High", snmp_comm[:10],
            "SNMPv1/v2c communicates without encryption.",
            "Upgrade to SNMPv3 with authPriv.",
            "dell-hardening", comp_map("SNMP"),
            remediation_cmd="no snmp-server community <COMM>"))

    plain_pw = [(n, l) for n, l in lines if re.search(r"^\s*username\s+\S+\s+password\s+(?:0\s+)?(\S+)", l, re.I)]
    if plain_pw:
        findings.append(Finding("DELL-PWD-001", device, "Plaintext local user password detected", "High",
            "Authentication", "High", plain_pw,
            "Plaintext passwords in configuration files can be compromised during reviews or backups.",
            "Configure encrypted passwords or use centralized RADIUS/TACACS.",
            "dell-hardening", comp_map("PWD_ENCR"),
            remediation_cmd="username <USER> password encrypted <HASH>"))

    findings.append(Finding("DELL-EOL-001", device, "Dell PowerConnect switch is End-of-Life (EOL)", "Medium",
        "Lifecycle", "High", [(0, "PowerConnect model detected: " + info.model)],
        "Legacy Dell PowerConnect switches no longer receive firmware security patches.",
        "Plan migration to modern Dell PowerSwitch (OS10) or supported platforms.",
        "dell-hardening", comp_map("PERMISSIVE_POLICY"),
        remediation_cmd="Upgrade to current Dell Networking PowerSwitch hardware"))

    if absence_checks:
        conf = absence_confidence(info)
        if not re.search(r"^\s*logging\s+\d+\.\d+\.\d+\.\d+", text, re.M | re.I):
            findings.append(Finding("DELL-LOG-001", device, "Remote syslog collector not configured", "High",
                "Logging", conf, [(0, "logging <IP> missing")],
                "Central log collection is necessary for monitoring.",
                "Configure remote syslog logging.",
                "dell-hardening", comp_map("LOGGING"),
                remediation_cmd="logging <SYSLOG_IP>"))
        if not re.search(r"^\s*sntp\s+server\b", text, re.M | re.I):
            findings.append(Finding("DELL-TIME-001", device, "SNTP time server not configured", "Medium",
                "Time synchronization", conf, [(0, "sntp server missing")],
                "Ensure clocks are synchronized across network switches.",
                "Configure SNTP servers.",
                "dell-hardening", comp_map("TIME"),
                remediation_cmd="sntp server <NTP_IP>"))
        if not re.search(r"^\s*banner\s+motd\b", text, re.M | re.I):
            findings.append(Finding("DELL-BAN-001", device, "MOTD banner not configured", "Info",
                "Legal notice", conf, [(0, "banner motd missing")],
                "Display approved legal warning notice.",
                "Configure authorized-use warning banner.",
                "dell-hardening", comp_map("BANNER"),
                remediation_cmd="banner motd ^C Authorized access only ^C"))

    return findings


# --- 18. ALTEON OS / NORTEL SWITCHED FIREWALL (EOL) ---
def check_alteon_os(lines, device, info, absence_checks=True):
    findings, text = [], joined(lines)

    telnet = [(n, l) for n, l in lines if re.search(r"(?:/cfg/sys/telnet|/c/sys/telnet)\s+on\b", l, re.I)]
    if telnet:
        findings.append(Finding("ALT-TEL-001", device, "Telnet management service enabled", "High",
            "Management plane", "High", telnet,
            "Telnet transmits administrative credentials in cleartext.",
            "Disable Telnet and enforce SSHv2.",
            "alteon-hardening", comp_map("TELNET"),
            remediation_cmd="/cfg/sys/telnet off"))

    snmp_comm = [(n, l) for n, l in lines if re.search(r"(?:/cfg/sys/snmp/comm|/c/sys/snmp/comm)\s+(\S+)", l, re.I)]
    if snmp_comm:
        findings.append(Finding("ALT-SNMP-001", device, "SNMP community string configured", "High",
            "SNMP security", "High", snmp_comm[:10],
            "SNMPv1/v2c communicates without encryption.",
            "Disable SNMP communities or migrate to SNMPv3.",
            "alteon-hardening", comp_map("SNMP"),
            remediation_cmd="/cfg/sys/snmp/comm off"))

    plain_pwd = [(n, l) for n, l in lines if re.search(r"(?:/cfg/sys/access/user|/c/sys/access/user)\s+\S+\s+(?:pass|password)\s+\S+", l, re.I)]
    if plain_pwd:
        findings.append(Finding("ALT-PWD-001", device, "Plaintext user password configured", "High",
            "Authentication", "High", plain_pwd[:10],
            "Alteon access user passwords stored in cleartext expose administrative credentials.",
            "Enforce RADIUS/TACACS+ centralized authentication or encrypted passwords.",
            "alteon-hardening", comp_map("PWD_ENCR"),
            remediation_cmd="/cfg/sys/access/radius on"))

    findings.append(Finding("ALT-EOL-001", device, "Alteon OS / Nortel platform is End-of-Life (EOL)", "Medium",
        "Lifecycle", "High", [(0, "Alteon/Nortel OS detected")],
        "Alteon application switches and Nortel firewalls are legacy End-of-Life platforms.",
        "Migrate services to modern supported application delivery controllers (ADCs) or firewalls.",
        "alteon-hardening", comp_map("PERMISSIVE_POLICY"),
        remediation_cmd="Migrate application switching to modern ADC"))

    if absence_checks:
        conf = absence_confidence(info)
        if not re.search(r"(?:/cfg/sys/syslog|/c/sys/syslog)\b", text, re.I):
            findings.append(Finding("ALT-LOG-001", device, "Remote syslog collector not configured", "High",
                "Logging", conf, [(0, "syslog config missing")],
                "Central log collection is necessary for monitoring.",
                "Configure remote syslog logging.",
                "alteon-hardening", comp_map("LOGGING"),
                remediation_cmd="/cfg/sys/syslog on\n/cfg/sys/syslog/host <SYSLOG_IP>"))
        if not re.search(r"(?:/cfg/sys/ntp|/c/sys/ntp)\b", text, re.I):
            findings.append(Finding("ALT-TIME-001", device, "NTP time server not configured", "Medium",
                "Time synchronization", conf, [(0, "ntp config missing")],
                "Ensure clocks are synchronized across network switches.",
                "Configure NTP servers.",
                "alteon-hardening", comp_map("TIME"),
                remediation_cmd="/cfg/sys/ntp/server <NTP_IP>"))
        if not re.search(r"(?:/cfg/sys/banner|/c/sys/banner)\b", text, re.I):
            findings.append(Finding("ALT-BAN-001", device, "Login banner not configured", "Info",
                "Legal notice", conf, [(0, "banner config missing")],
                "Display approved legal warning notice.",
                "Configure authorized-use warning banner.",
                "alteon-hardening", comp_map("BANNER"),
                remediation_cmd="/cfg/sys/banner \"Authorized access only.\""))

    return findings


# ----------------------------------------------------------------------
# AUDIT DISPATCHER
# ----------------------------------------------------------------------
def audit_lines(lines, source_name, forced_vendor=None, forced_model=None, absence_checks=True):
    info = detect_device(lines, source_name, forced_vendor, forced_model)
    device = info.hostname if info.hostname != "Unknown" else os.path.basename(source_name)

    if info.vendor == "fortigate":
        findings = check_fortigate(lines, device, info, absence_checks)
    elif info.vendor == "paloalto":
        findings = check_paloalto(lines, device, info, absence_checks)
    elif info.vendor == "juniper":
        findings = check_juniper(lines, device, info, absence_checks)
    elif info.vendor == "cisco-asa":
        findings = check_cisco_asa(lines, device, info, absence_checks)
    elif info.vendor == "cisco-ios":
        findings = check_cisco_ios(lines, device, info, absence_checks)
    elif info.vendor == "cisco-nxos":
        findings = check_cisco_nxos(lines, device, info, absence_checks)
    elif info.vendor == "cisco-xr":
        findings = check_cisco_ios(lines, device, info, absence_checks)
    elif info.vendor == "checkpoint":
        findings = check_checkpoint(lines, device, info, absence_checks)
    elif info.vendor == "arista":
        findings = check_arista(lines, device, info, absence_checks)
    elif info.vendor == "aruba-hp":
        findings = check_aruba_hp(lines, device, info, absence_checks)
    elif info.vendor == "brocade-ruckus":
        findings = check_brocade(lines, device, info, absence_checks)
    elif info.vendor == "extreme":
        findings = check_extreme(lines, device, info, absence_checks)
    elif info.vendor == "f5-bigip":
        findings = check_f5(lines, device, info, absence_checks)
    elif info.vendor == "watchguard":
        findings = check_watchguard(lines, device, info, absence_checks)
    elif info.vendor == "huawei":
        findings = check_huawei(lines, device, info, absence_checks)
    elif info.vendor == "screenos":
        findings = check_screenos(lines, device, info, absence_checks)
    elif info.vendor == "nokia-ipso":
        findings = check_nokia_ipso(lines, device, info, absence_checks)
    elif info.vendor == "dell-powerconnect":
        findings = check_dell_powerconnect(lines, device, info, absence_checks)
    elif info.vendor == "alteon-os":
        findings = check_alteon_os(lines, device, info, absence_checks)
    else:
        findings = [Finding("GEN-DET-001", device, "Vendor platform could not be identified reliably", "Info",
            "Input quality", "High", [(0, "No unambiguous supported vendor signature was recognized")],
            "Vendor-specific checks were not run, preventing misleading results.",
            "Supply a native configuration file or force a known parser with --vendor.", "cisco-mgmt",
            comp_map("PERMISSIVE_POLICY"))]

    return AuditResult(source_name, info, findings)


def audit_file(path, forced_vendor=None, forced_model=None, absence_checks=True):
    return audit_lines(read_text_file(path), path, forced_vendor, forced_model, absence_checks)


def collect_inputs(config, directory=None, recursive=False, excluded_paths=None):
    excluded = {os.path.abspath(path) for path in (excluded_paths or [])}
    candidates = []
    if directory:
        if not os.path.isdir(directory):
            raise ValueError(f"not a folder: {directory}")
        if recursive:
            for root, _, files in os.walk(directory):
                candidates.extend(os.path.join(root, name) for name in sorted(files))
        else:
            candidates.extend(os.path.join(directory, name) for name in sorted(os.listdir(directory)))
    elif config:
        if not os.path.isfile(config):
            raise ValueError(f"file not found: {config}")
        candidates.append(config)
    else:
        raise ValueError("provide a config file/ZIP or --dir")

    inputs = []
    for path in candidates:
        if not os.path.isfile(path) or os.path.abspath(path) in excluded:
            continue
        lower_path = path.lower()
        extension = os.path.splitext(path)[1].lower()
        if lower_path.endswith(".zip"):
            with zipfile.ZipFile(path) as archive:
                total_size = 0
                for member in archive.infolist()[:500]:
                    member_ext = os.path.splitext(member.filename)[1].lower()
                    if member.is_dir() or member_ext not in TEXT_EXTENSIONS or member.file_size > 25 * 1024 * 1024:
                        continue
                    total_size += member.file_size
                    if total_size > 100 * 1024 * 1024:
                        break
                    inputs.append((f"{os.path.basename(path)}::{member.filename}",
                                   lines_from_bytes(archive.read(member))))
        elif any(lower_path.endswith(suffix) for suffix in ARCHIVE_EXTENSIONS - {".zip"}):
            with tarfile.open(path, mode="r:*") as archive:
                total_size = 0
                for member in archive.getmembers()[:500]:
                    member_ext = os.path.splitext(member.name)[1].lower()
                    if not member.isfile() or member_ext not in TEXT_EXTENSIONS or member.size > 25 * 1024 * 1024:
                        continue
                    total_size += member.size
                    if total_size > 100 * 1024 * 1024:
                        break
                    stream = archive.extractfile(member)
                    if stream is not None:
                        inputs.append((f"{os.path.basename(path)}::{member.name}",
                                       lines_from_bytes(stream.read())))
        elif extension in TEXT_EXTENSIONS:
            inputs.append((path, read_text_file(path)))
    return inputs


def counts(findings):
    result = {severity: 0 for severity in SEV}
    for finding in findings:
        result[finding.severity] = result.get(finding.severity, 0) + 1
    return result


# ----------------------------------------------------------------------
# REPORTING: CONSOLE, CSV, JSON, HTML
# ----------------------------------------------------------------------
def console(results):
    for result in results:
        info, summary = result.info, counts(result.findings)
        print("\n" + "=" * 96)
        print(f" [DEVICE AUDIT] {os.path.basename(result.source)}")
        print(f" Vendor: {info.vendor:<14} ({info.vendor_confidence:<6}) | Model: {info.model:<18} ({info.model_confidence:<7}) | Host: {info.hostname}")
        print(f" Format: {info.config_format:<14} | OS: {info.os_version:<10} | Scope: {info.scope:<14} | Risk: {result.risk_score}/100")
        print(" Findings: " + "  ".join(f"{s}:{summary[s]}" for s in SEV))
        print(" Compliance: " + "  ".join(f"{k}:{v}" for k, v in result.compliance_summary.items() if v > 0))
        print("=" * 96)
        for warning in info.warnings:
            print(" [inventory note] " + warning)
        for index, finding in enumerate(result.findings, 1):
            print(f"[{index:02d}] {finding.severity:<8} {finding.rule_id:<14} {finding.title} [confidence: {finding.confidence}]")
            for number, text in finding.evidence[:3]:
                print(f"      {('L' + str(number)) if number else '-'}: {text.strip()[:150]}")
            if len(finding.evidence) > 3:
                print(f"      ... +{len(finding.evidence) - 3} more lines")
            if finding.remediation_cmd:
                first_line = finding.remediation_cmd.splitlines()[0]
                print(f"      CLI Fix: {first_line[:120]}")


def write_csv(results, output):
    with open(output, "w", newline="", encoding="utf-8-sig") as fh:
        writer = csv.writer(fh)
        writer.writerow([
            "Source", "Hostname", "Vendor", "Vendor Confidence", "Model", "Model Confidence",
            "OS Version", "Config Format", "Config Scope", "Risk Score", "Rule ID", "Severity",
            "Category", "Finding Confidence", "Finding", "Evidence", "Impact", "Recommendation",
            "Remediation CLI", "CIS", "DISA STIG", "NIST 800-53", "NIST 800-171", "PCI-DSS",
            "Reference", "Reference URL"
        ])
        for result in results:
            info = result.info
            for finding in result.findings:
                evidence = " | ".join(f"L{n}: {t.strip()}" if n else t.strip() for n, t in finding.evidence[:25])
                writer.writerow([
                    result.source, info.hostname, info.vendor, info.vendor_confidence, info.model,
                    info.model_confidence, info.os_version, info.config_format, info.scope, result.risk_score,
                    finding.rule_id, finding.severity, finding.category, finding.confidence, finding.title,
                    evidence, finding.impact, finding.recommendation, finding.remediation_cmd,
                    finding.compliance.get("cis", ""), finding.compliance.get("stig", ""),
                    finding.compliance.get("nist_53", ""), finding.compliance.get("nist_171", ""),
                    finding.compliance.get("pci_dss", ""), finding.reference, finding.reference_url
                ])


def write_json(results, output):
    all_findings = [f for r in results for f in r.findings]
    total_compliance = {"CIS": 0, "DISA_STIG": 0, "NIST_800_53": 0, "NIST_800_171": 0, "PCI_DSS": 0, "CMMC": 0}
    for f in all_findings:
        if f.compliance.get("cis"): total_compliance["CIS"] += 1
        if f.compliance.get("stig"): total_compliance["DISA_STIG"] += 1
        if f.compliance.get("nist_53"): total_compliance["NIST_800_53"] += 1
        if f.compliance.get("nist_171"): total_compliance["NIST_800_171"] += 1
        if f.compliance.get("pci_dss"): total_compliance["PCI_DSS"] += 1
        if f.compliance.get("cmmc"): total_compliance["CMMC"] += 1

    payload = {
        "tool": TOOL_NAME,
        "subtitle": TOOL_SUBTITLE,
        "version": TOOL_VERSION,
        "generated": datetime.now().astimezone().isoformat(timespec="seconds"),
        "metrics": {
            "total_devices": len(results),
            "total_findings": len(all_findings),
            "severity_summary": counts(all_findings),
            "compliance_summary": total_compliance,
        },
        "results": [result.as_dict() for result in results]
    }
    with open(output, "w", encoding="utf-8") as fh:
        json.dump(payload, fh, indent=2, ensure_ascii=False)


def write_html(results, output):
    colors = {
        "Critical": "#dc2626", "High": "#ea580c", "Medium": "#d97706",
        "Low": "#2563eb", "Info": "#475569"
    }
    all_findings = [f for r in results for f in r.findings]
    total = counts(all_findings)
    total_compliance = {"CIS": 0, "DISA STIG": 0, "NIST SP 800-53": 0, "PCI-DSS v4.0": 0, "CMMC 2.0": 0}
    for f in all_findings:
        if f.compliance.get("cis"): total_compliance["CIS"] += 1
        if f.compliance.get("stig"): total_compliance["DISA STIG"] += 1
        if f.compliance.get("nist_53"): total_compliance["NIST SP 800-53"] += 1
        if f.compliance.get("pci_dss"): total_compliance["PCI-DSS v4.0"] += 1
        if f.compliance.get("cmmc"): total_compliance["CMMC 2.0"] += 1

    summary_rows, details = [], []
    for result in results:
        info, summary = result.info, counts(result.findings)
        severity_cells = "".join(f'<td class="center" style="background:{colors[s]}15;font-weight:600;color:{colors[s]}">{summary[s] or ""}</td>' for s in SEV)
        summary_rows.append(
            f"<tr><td><b>{html.escape(os.path.basename(result.source))}</b></td>"
            f"<td>{html.escape(info.hostname)}</td>"
            f"<td><b>{html.escape(info.vendor)}</b><br><small>{html.escape(info.vendor_confidence)}</small></td>"
            f"<td>{html.escape(info.model)}<br><small>{html.escape(info.model_confidence)}</small></td>"
            f"<td>{html.escape(info.os_version)}</td>"
            f"<td>{html.escape(info.scope)}</td>"
            f'<td class="center"><span class="risk-badge" style="background:{"#dc2626" if result.risk_score>=70 else ("#ea580c" if result.risk_score>=40 else "#16a34a")}">{result.risk_score}/100</span></td>'
            f"{severity_cells}"
            f'<td class="center"><b>{len(result.findings)}</b></td></tr>'
        )

        rows = []
        for index, finding in enumerate(result.findings, 1):
            evidence = "<br>".join(
                f"<code>{'L' + str(n) + ': ' if n else ''}{html.escape(t.strip())}</code>"
                for n, t in finding.evidence[:20]
            )
            ref = html.escape(finding.reference)
            if finding.reference_url:
                ref = f'<a href="{html.escape(finding.reference_url)}" target="_blank">{ref}</a>'

            comp_tags = []
            if finding.compliance.get("cis"): comp_tags.append(f'<span class="tag-comp tag-cis">CIS</span> {html.escape(finding.compliance["cis"])}')
            if finding.compliance.get("stig"): comp_tags.append(f'<span class="tag-comp tag-stig">STIG</span> {html.escape(finding.compliance["stig"])}')
            if finding.compliance.get("nist_53"): comp_tags.append(f'<span class="tag-comp tag-nist">NIST 800-53</span> {html.escape(finding.compliance["nist_53"])}')
            if finding.compliance.get("pci_dss"): comp_tags.append(f'<span class="tag-comp tag-pci">PCI-DSS</span> {html.escape(finding.compliance["pci_dss"])}')
            comp_block = f'<div class="comp-box">{"<br>".join(comp_tags)}</div>' if comp_tags else ""

            remed_block = ""
            if finding.remediation_cmd:
                remed_block = f'<details class="remed-box"><summary><b>CLI Remediation Script</b></summary><pre><code>{html.escape(finding.remediation_cmd)}</code></pre></details>'

            rows.append(
                f'<tr class="finding-row severity-{finding.severity.lower()}"><td>{index}</td>'
                f'<td><span class="badge" style="background:{colors[finding.severity]}">{finding.severity}</span></td>'
                f'<td><b>{html.escape(finding.rule_id)}</b> — {html.escape(finding.title)}'
                f'<br><small>{html.escape(finding.category)} | Confidence: {html.escape(finding.confidence)}</small>'
                f'<br><small>{ref}</small>{comp_block}</td>'
                f'<td class="evidence">{evidence}</td>'
                f'<td>{html.escape(finding.impact)}</td>'
                f'<td>{html.escape(finding.recommendation)}{remed_block}</td></tr>'
            )

        warnings = "".join(f'<div class="note"><b>Inventory note:</b> {html.escape(w)}</div>' for w in info.warnings)
        details.append(
            f'<div class="device-card"><h2>{html.escape(os.path.basename(result.source))} — {html.escape(info.hostname)}</h2>'
            f'<p class="meta">Vendor: <b>{html.escape(info.vendor)}</b> ({html.escape(info.vendor_confidence)}) | '
            f'Model: <b>{html.escape(info.model)}</b> ({html.escape(info.model_confidence)}) | '
            f'Format: {html.escape(info.config_format)} | OS: {html.escape(info.os_version)} | Scope: {html.escape(info.scope)} | '
            f'Risk: <b>{result.risk_score}/100</b></p>{warnings}'
            f'<details class="meta"><summary>Detection Evidence</summary><p>{html.escape("; ".join(info.evidence))}</p></details>'
            f'<table><tr><th style="width:30px">#</th><th style="width:85px">Severity</th><th>Finding & Compliance</th><th>Evidence</th><th>Impact</th><th>Remediation Guidance</th></tr>{"".join(rows)}</table></div>'
        )

    generated = datetime.now().astimezone().strftime("%Y-%m-%d %H:%M %Z")
    kpi_badges = " ".join(f'<span class="kpi-pill" style="border-left: 4px solid {colors[s]}"><b>{s}</b> {total[s]}</span>' for s in SEV)
    comp_kpi = " ".join(f'<span class="kpi-pill" style="border-left: 4px solid #4f46e5"><b>{k}</b> {v}</span>' for k, v in total_compliance.items())

    document = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>{TOOL_NAME} - Enterprise Audit Report</title>
<style>
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, Helvetica, Arial, sans-serif; margin: 24px 36px; background: #f8fafc; color: #1e293b; }}
  header {{ background: #0f172a; color: #fff; padding: 24px 32px; border-radius: 8px; margin-bottom: 24px; box-shadow: 0 4px 6px -1px rgba(0,0,0,0.1); }}
  h1 {{ font-size: 26px; margin: 0 0 6px 0; font-weight: 700; letter-spacing: -0.5px; }}
  .subtitle {{ color: #94a3b8; font-size: 14px; margin: 0; }}
  .meta-bar {{ margin-top: 16px; font-size: 13px; color: #cbd5e1; display: flex; gap: 24px; flex-wrap: wrap; }}
  .kpi-section {{ display: flex; gap: 12px; margin: 16px 0 24px 0; flex-wrap: wrap; }}
  .kpi-pill {{ background: #fff; border: 1px solid #e2e8f0; padding: 8px 14px; border-radius: 6px; font-size: 13px; box-shadow: 0 1px 2px rgba(0,0,0,0.05); }}
  .kpi-pill b {{ margin-right: 4px; color: #0f172a; }}
  h2 {{ font-size: 18px; margin: 28px 0 12px 0; color: #0f172a; border-bottom: 2px solid #e2e8f0; padding-bottom: 6px; }}
  table {{ border-collapse: collapse; width: 100%; margin-top: 10px; background: #fff; border-radius: 6px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }}
  th, td {{ border: 1px solid #e2e8f0; padding: 10px 12px; vertical-align: top; text-align: left; font-size: 13px; }}
  th {{ background: #1e293b; color: #f8fafc; font-weight: 600; text-transform: uppercase; font-size: 11px; letter-spacing: 0.5px; }}
  tr:nth-child(even) {{ background: #f8fafc; }}
  .center {{ text-align: center; }}
  .badge {{ color: #fff; padding: 3px 8px; border-radius: 4px; font-weight: 600; font-size: 11px; text-transform: uppercase; display: inline-block; }}
  .risk-badge {{ color: #fff; padding: 4px 8px; border-radius: 12px; font-weight: 700; font-size: 12px; }}
  .evidence {{ max-width: 360px; font-family: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace; }}
  code {{ background: #f1f5f9; color: #0f172a; padding: 2px 5px; border-radius: 4px; font-size: 11.5px; display: inline-block; margin-bottom: 2px; border: 1px solid #e2e8f0; }}
  pre code {{ display: block; background: #0f172a; color: #38bdf8; padding: 10px; border-radius: 6px; overflow-x: auto; font-size: 12px; border: none; }}
  .note {{ background: #fffbeb; border-left: 4px solid #f59e0b; padding: 8px 12px; margin: 8px 0; font-size: 12.5px; color: #92400e; }}
  .device-card {{ background: #fff; border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; margin-top: 24px; box-shadow: 0 1px 3px rgba(0,0,0,0.05); }}
  .device-card h2 {{ margin-top: 0; }}
  .tag-comp {{ font-size: 9.5px; font-weight: 700; padding: 2px 5px; border-radius: 3px; color: #fff; display: inline-block; margin-right: 4px; }}
  .tag-cis {{ background: #2563eb; }}
  .tag-stig {{ background: #dc2626; }}
  .tag-nist {{ background: #059669; }}
  .tag-pci {{ background: #d97706; }}
  .comp-box {{ margin-top: 6px; font-size: 11.5px; line-height: 1.4; color: #475569; background: #f8fafc; padding: 6px 8px; border-radius: 4px; border: 1px dashed #cbd5e1; }}
  .remed-box {{ margin-top: 8px; font-size: 12px; cursor: pointer; }}
  .remed-box summary {{ color: #2563eb; font-weight: 600; outline: none; }}
  a {{ color: #2563eb; text-decoration: none; }}
  a:hover {{ text-decoration: underline; }}
  .filter-bar {{ margin: 16px 0; display: flex; gap: 10px; align-items: center; }}
  .filter-input {{ padding: 8px 12px; border: 1px solid #cbd5e1; border-radius: 6px; font-size: 13px; width: 300px; }}
</style>
</head>
<body>
<header>
  <h1>{TOOL_NAME}</h1>
  <p class="subtitle">{TOOL_SUBTITLE} (Version {TOOL_VERSION})</p>
  <div class="meta-bar">
    <div><b>Generated:</b> {html.escape(generated)}</div>
    <div><b>Devices Audited:</b> {len(results)}</div>
    <div><b>Total Findings:</b> {len(all_findings)}</div>
  </div>
</header>

<div class="kpi-section">
  {kpi_badges}
</div>
<div class="kpi-section">
  {comp_kpi}
</div>

<h2>Fleet Devices Summary</h2>
<table>
  <tr>
    <th>Source Configuration</th><th>Hostname</th><th>Vendor Platform</th><th>Hardware Model</th>
    <th>OS Version</th><th>Config Scope</th><th>Risk Index</th>
    {''.join(f'<th>{s}</th>' for s in SEV)}<th>Total</th>
  </tr>
  {''.join(summary_rows)}
</table>

{''.join(details)}

<p class="meta" style="margin-top:32px;font-size:12px;color:#64748b;">
  <i>Automated static configuration review engine. Always validate findings against operational requirements, network architecture, and business change authorization.</i>
</p>
</body>
</html>"""

    with open(output, "w", encoding="utf-8") as fh:
        fh.write(document)


# ----------------------------------------------------------------------
# CLI COMMANDS: SUPPORTED MATRIX & SELF TEST
# ----------------------------------------------------------------------
def print_supported():
    print_banner()
    print("\nSupported Active Enterprise Platforms & Asset Models:")
    active = ["cisco-asa", "cisco-ios", "cisco-nxos", "cisco-xr", "fortigate", "paloalto", "juniper", "checkpoint", "arista", "aruba-hp", "brocade-ruckus", "extreme", "f5-bigip", "watchguard", "huawei"]
    for v in active:
        models = SUPPORTED_MODELS[v]
        print(f"  * {v:<18}: {', '.join(models[:6])}{'...' if len(models)>6 else ''}")
    print("\nSupported Legacy & End-of-Life (EOL) Platforms:")
    eol = ["screenos", "nokia-ipso", "dell-powerconnect", "alteon-os"]
    for v in eol:
        models = SUPPORTED_MODELS[v]
        print(f"  * {v + ' (EOL)':<18}: {', '.join(models[:6])}{'...' if len(models)>6 else ''}")
    print("\nSupported Security & Compliance Frameworks:")
    print("  * Center for Internet Security (CIS) Benchmarks & Controls v8")
    print("  * DoD DISA STIGs (Cisco ASA, IOS-XE, NX-OS, Junos SRX, FortiGate, PAN-OS, F5)")
    print("  * NIST SP 800-53 Rev 5 & NIST SP 800-171 Rev 3")
    print("  * Payment Card Industry Data Security Standard (PCI-DSS) v4.0")
    print("  * Cybersecurity Maturity Model Certification (CMMC) 2.0")
    print("\nSupported File & Archive Formats:")
    print("  * Text / CLI outputs (.conf, .cfg, .set, .txt, .xml, .backup, .log, .c, .fws, .ndb)")
    print("  * Archives: .zip, .tar, .tgz, .tar.gz, .tar.bz2, .tar.xz")
    print("=" * 80)


def self_test():
    cases = {
        "asa5525.conf": "ASA Version 9.8\nhostname ASA-5525-01\naccess-list X extended permit ip any any\n",
        "fgt-3301e.conf": "#config-version=FGT3301E-7.4.0-FW-build1\nconfig system global\n set hostname FGT3301E-1\nend\n",
        "pa5220.set": "set deviceconfig system hostname PA-5220-1\nset rulebase security rules r1 from any to any source any destination any application any service any action allow\n",
        "srx300.set": "set system host-name SRX300-1\nset security policies from-zone trust to-zone untrust policy p then permit\nset system login user test9 authentication encrypted-password \"$9$7YdwgGDkTz6oJz69A1INdb\"\n",
        "cisco_catalyst.cfg": "version 15.0\nhostname Cat3550-Core\nservice password-encryption\nusername testadmin password 7 045802150C2E\nline vty 0 4\n transport input telnet\n",
        "nexus5010.conf": "version 4.1(3)N2(1)\nhostname Nexus-DC01\nfeature telnet\npassword strength-check\n",
        "arista.cfg": "! device: Arista-Leaf01 (vEOS, EOS-4.20.1F)\nhostname Arista-Leaf01\nmanagement api http-commands\n protocol http\n",
        "aruba_hp.cfg": "; J9086A Configuration Editor; Created on release #R.11.107\nhostname HP-Switch-2610\nsntp server priority 1 10.0.0.1\n",
        "brocade.cfg": "ver 07.4.00T311\nhostname Brocade-ICX\nenable super-user-password clearpass\n",
        "extreme.cfg": "# Module devmgr configuration.\nconfigure snmp sysName \"Extreme-Summit-X460\"\nenable telnet\n",
        "f5_bigip.conf": "auth password-policy {\n  min-length 14\n}\nsys httpd {\n  allow { all }\n}\n",
        "checkpoint.cfg": "(rulebase\n  :rule_num (1)\n  :action (accept)\n  :src (Any)\n  :dst (Any)\n)\n",
        "watchguard.xml": "<profile>\n  <for-version>11.7.3</for-version>\n  <for-model>XTM 5 Series</for-model>\n  <snmp-comm-string>public</snmp-comm-string>\n</profile>\n",
        "huawei.cfg": "display current-configuration\nsysname Huawei-Core\ntelnet server enable\n",
        "unknown.txt": "this is not a network configuration\n",
        "legacy-forti.conf": "#conf_file_ver=123456\nconfig system global\n set hostname edge-fw\nend\n",
        "screenos_ssg.cfg": "set hostname SSG5-Edge\nset admin password \"clearpass\"\nset policy id 1 from Trust to Untrust Any Any ANY permit\n",
        "nokia_ipso.cfg": "set hostname Nokia-IP390\nset ipforwarding on\nset telnet active on\n",
        "dell_powerconnect.cfg": "hostname Dell-Switch-5524\nip telnet server\nsnmp-server community public ro\n",
        "alteon.cfg": "/cfg/sys/name Alteon-LB01\n/cfg/sys/telnet on\n/cfg/sys/snmp/comm public\n",
        "pix.conf": "PIX Version 6.3(5)\nhostname PIX-Firewall\nconduit permit ip any any\n",
    }
    expected = {
        "asa5525.conf": ("cisco-asa", "ASA 5525-X"),
        "fgt-3301e.conf": ("fortigate", "FortiGate 3301E"),
        "pa5220.set": ("paloalto", "PA-5220"),
        "srx300.set": ("juniper", "SRX300"),
        "cisco_catalyst.cfg": ("cisco-ios", "Catalyst 3550"),
        "nexus5010.conf": ("cisco-nxos", "Nexus 5010"),
        "arista.cfg": ("arista", "vEOS"),
        "aruba_hp.cfg": ("aruba-hp", "ProCurve 2600"),
        "brocade.cfg": ("brocade-ruckus", "ICX"),
        "extreme.cfg": ("extreme", "Summit X460"),
        "f5_bigip.conf": ("f5-bigip", "Unknown"),
        "checkpoint.cfg": ("checkpoint", "Unknown"),
        "watchguard.xml": ("watchguard", "XTM 5 Series"),
        "huawei.cfg": ("huawei", "Unknown"),
        "unknown.txt": ("unknown", "Unknown"),
        "legacy-forti.conf": ("fortigate", "Unknown"),
        "screenos_ssg.cfg": ("screenos", "SSG-5"),
        "nokia_ipso.cfg": ("nokia-ipso", "IP390"),
        "dell_powerconnect.cfg": ("dell-powerconnect", "PowerConnect 5500"),
        "alteon.cfg": ("alteon-os", "Unknown"),
        "pix.conf": ("cisco-asa", "Unknown"),
    }

    failures = []
    for name, content in cases.items():
        lines = [(i + 1, line) for i, line in enumerate(content.splitlines())]
        result = audit_lines(lines, name)
        actual = (result.info.vendor, result.info.model)
        # Check vendor match
        if actual[0] != expected[name][0]:
            failures.append(f"{name}: expected vendor {expected[name][0]}, got {actual[0]}")
        if actual[1] != expected[name][1]:
            failures.append(f"{name}: expected model {expected[name][1]}, got {actual[1]}")
        if name == "pa5220.set" and not any(f.rule_id == "PAN-POL-001" for f in result.findings):
            failures.append("PAN-OS combined set-line rule parsing failed")
        if name == "cisco_catalyst.cfg" and not any(f.rule_id == "CISCO-TEL-001" for f in result.findings):
            failures.append("Cisco IOS VTY Telnet check failed")
        if name == "cisco_catalyst.cfg" and not any(f.rule_id == "CISCO-PWD-002" for f in result.findings):
            failures.append("Cisco IOS Type 7 password check failed")
        if name == "srx300.set" and not any(f.rule_id == "JUN-AUTH-003" for f in result.findings):
            failures.append("Junos $9$ reversible password check failed")
        if name == "nexus5010.conf" and not any(f.rule_id == "NXOS-TEL-001" for f in result.findings):
            failures.append("Cisco NX-OS Telnet feature check failed")
        if name == "pix.conf" and not any(f.rule_id == "PIX-CON-001" for f in result.findings):
            failures.append("Legacy Cisco PIX conduit check failed")
        if name == "screenos_ssg.cfg" and not any(f.rule_id == "SCREEN-POL-001" for f in result.findings):
            failures.append("Juniper ScreenOS any-any policy check failed")

    # Password decoding algorithm checks
    if decode_cisco_type7("045802150C2E") != "cisco":
        failures.append("Cisco Type 7 password decoding failed")
    if decode_juniper_type9("$9$7YdwgGDkTz6oJz69A1INdb") != "juniper":
        failures.append("Juniper Type 9 password decoding failed")
    if decode_reversible_password("045802150C2E") != ("Cisco Type 7", "cisco"):
        failures.append("Generic decoder for Cisco Type 7 failed")
    if decode_reversible_password("$9$7YdwgGDkTz6oJz69A1INdb") != ("Juniper $9$", "juniper"):
        failures.append("Generic decoder for Juniper $9$ failed")

    # Redaction checks
    if "public" in redact_evidence("snmp-server community public RO"):
        failures.append("SNMP evidence redaction failed")
    ntp_secret = redact_evidence('authentication-key 254 type md5 value "$9$secret"')
    if "$9$secret" in ntp_secret:
        failures.append("Junos NTP key redaction failed")
    snmp_secret = redact_evidence("snmp-server user alice group v3 encrypted auth md5 AUTHKEY priv aes 256 PRIVKEY")
    if "AUTHKEY" in snmp_secret or "PRIVKEY" in snmp_secret:
        failures.append("SNMPv3 key redaction failed")
    decoded_redacted = redact_evidence('username test password 7 045802150C2E [Trivially decoded: "cisco"]')
    if "cisco" in decoded_redacted or "045802150C2E" in decoded_redacted:
        failures.append("Decoded password evidence redaction failed")

    if failures:
        print("SELF-TEST FAILED")
        for failure in failures:
            print(" - " + failure)
        return 1
    print(f"SELF-TEST PASSED ({len(cases)} multi-vendor detection cases + rule verification + password decoding + evidence redaction)")
    return 0


def output_paths(base, output_format):
    selected = ("html", "csv", "json") if output_format == "all" else (output_format,)
    return [base + "." + extension for extension in selected]


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Offline Multi-Vendor Network & Firewall Security Review",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="Use --list-supported to view supported platforms, assets, and compliance frameworks."
    )
    parser.add_argument("config", nargs="?", help="single config file or ZIP/TAR/TGZ bundle")
    parser.add_argument("--dir", help="directory containing configurations")
    parser.add_argument("--recursive", action="store_true", help="recurse below --dir")
    parser.add_argument("--vendor", choices=[
        "fortigate", "juniper", "paloalto", "cisco-asa", "cisco-ios", "cisco-nxos",
        "cisco-xr", "checkpoint", "arista", "aruba-hp", "brocade-ruckus", "extreme",
        "f5-bigip", "watchguard", "huawei", "screenos", "nokia-ipso", "dell-powerconnect", "alteon-os"
    ], help="force a vendor parser")
    parser.add_argument("--model", help="force/inventory-label the hardware model")
    parser.add_argument("--no-absence-checks", action="store_true",
                        help="skip findings based only on a setting not appearing")
    parser.add_argument("-o", "--out", help="output basename; extension is added (.html, .csv, .json)")
    parser.add_argument("--format", choices=["all", "html", "csv", "json"], default="all")
    parser.add_argument("--fail-on", choices=["critical", "high", "medium", "low", "info"],
                        help="exit 2 if a finding at or above this severity exists")
    parser.add_argument("--decode-password", help="decode a reversible password hash (Cisco Type 7 or Juniper $9$)")
    parser.add_argument("--show-passwords", "--no-redact", action="store_true",
                        help="disable evidence redaction to reveal decoded and cleartext credentials in reports")
    parser.add_argument("--quiet", action="store_true", help="suppress console findings")
    parser.add_argument("--list-supported", action="store_true")
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--version", action="version", version=f"%(prog)s {TOOL_VERSION}")
    args = parser.parse_args(argv)

    if args.list_supported:
        print_supported()
        return 0
    if args.self_test:
        return self_test()
    if args.decode_password:
        fmt, dec = decode_reversible_password(args.decode_password)
        if dec:
            print(f"Algorithm        : {fmt}")
            print(f"Decoded Plaintext: {dec}")
            return 0
        else:
            print(f"Error: Unable to decode '{args.decode_password}' as Cisco Type 7 or Juniper $9$.")
            return 1
    if args.show_passwords:
        global REDACT_SECRETS
        REDACT_SECRETS = False
    if not args.config and not args.dir:
        parser.error("provide a config file/archive or --dir")
    if args.config and args.dir:
        parser.error("use either a positional config/ZIP or --dir")

    if not args.quiet:
        print_banner()

    report_paths = output_paths(args.out, args.format) if args.out else []
    try:
        inputs = collect_inputs(args.config, args.dir, args.recursive, report_paths)
    except (ValueError, OSError, zipfile.BadZipFile, tarfile.TarError) as exc:
        parser.error(str(exc))
    if not inputs:
        parser.error("no supported text configuration files found")

    results = [
        audit_lines(lines, source, args.vendor, args.model, not args.no_absence_checks)
        for source, lines in inputs
    ]

    if not args.quiet:
        console(results)

    if args.out:
        writers = {"html": write_html, "csv": write_csv, "json": write_json}
        for path in report_paths:
            writers[os.path.splitext(path)[1].lstrip(".").lower()](results, path)
        print("\n[+] wrote " + ", ".join(report_paths))

    if args.fail_on:
        threshold = SEV[args.fail_on.capitalize()]
        if any(SEV.get(f.severity, 99) <= threshold for result in results for f in result.findings):
            return 2

    return 0


if __name__ == "__main__":
    sys.exit(main())
