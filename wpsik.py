#!/usr/bin/env python
# -*- coding: utf-8 -*-
# WPS scan and pwn tool
#
# Based on:
#   WPSIG by CoreSecurity http://www.coresecurity.com/corelabs-research/open-source-tools/wpsig
#   devttys0 wps scripts https://github.com/devttys0/wps
#

import click
import logging
import os
import sys
import re
import random
import signal
import struct
import subprocess
import time

# external dependencies
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.all import RandMAC, sendp, sniff, wrpcap, hexdump, get_if_list, mac2str, send
from scapy.layers.dot11 import RadioTap, Dot11, Dot11ProbeReq, Dot11Elt, Dot11Beacon
from impacket import dot11
from impacket.ImpactDecoder import RadioTapDecoder
import netaddr

import coloredlogs
from colorama import Fore, init

init()

from prettytable import PrettyTable

frequencies_dict = {
    # 2.4 GHZ channels
    2412: 1, 2417: 2, 2422: 3,
    2427: 4, 2432: 5, 2437: 6,
    2442: 7, 2447: 8, 2452: 9,
    2457: 10, 2462: 11, 2467: 12,
    2472: 13, 2484: 14,
    # 5GHz channelshandler
    5170: 34, 5180: 36, 5190: 38,
    5200: 40, 5210: 42, 5220: 44,
    5230: 46, 5240: 48, 5260: 52,
    5280: 56, 5300: 58, 5320: 60,
    5500: 100, 5520: 104, 5540: 108,
    5560: 112, 5580: 116, 5600: 120,
    5620: 124, 5640: 128, 5660: 132,
    5680: 136, 5700: 140, 5745: 149,
    5765: 153, 5785: 157, 5805: 161,
    5825: 165
}
frequencies_list = [k for k in frequencies_dict.keys()]

channels_dict = dict((v, k) for k, v in frequencies_dict.iteritems())
channels_list = [k for k in channels_dict.keys()]

# channels = {
#     # 2.4ghz channel list
#     '2.4GHz': [x for x in xrange(1, 15)],
#     # 5ghz channel list
#     '5GHz': [34, 36, 38,
#              40, 42, 44, 46, 52, 56,
#              58, 60, 100, 104, 108, 112,
#              116, 120, 124, 128, 132, 136,
#              140, 149, 153, 157, 161, 165]}

channel_hop_list = [1, 6, 11, 13, 2, 7, 3, 8, 4, 9, 5, 10]


# channel_hop_list_full = [1, 6, 11, 14, 2, 7, 3, 8, 4, 9, 5, 10,
#                          36, 38, 40, 42, 44, 46, 52, 56, 58, 60, 100, 104, 108, 112,
#                          116, 120, 124, 128, 132, 136, 140, 149, 153, 157, 161, 165]


def query_yes_no(question, default="yes"):
    valid = {"yes": True, "y": True, "ye": True,
             "no": False, "n": False}
    if default is None:
        prompt = " [y/n] "
    elif default == "yes":
        prompt = " [Y/n] "
    elif default == "no":
        prompt = " [y/N] "
    else:
        raise ValueError("invalid default answer: '%s'" % default)

    while True:
        sys.stdout.write(question + prompt)
        choice = raw_input().lower()
        if default is not None and choice == '':
            return valid[default]
        elif choice in valid:
            return valid[choice]
        else:
            sys.stdout.write("Please respond with 'yes' or 'no' "
                             "(or 'y' or 'n').\n")


def enum(*sequential, **named):
    enums = dict(zip(sequential, range(len(sequential))), **named)
    return type('Enum', (), enums)


def _colorize(data, color):
    return color + str(data) + Fore.RESET


def _green(text):
    return _colorize(text, Fore.GREEN)


def _red(text):
    return _colorize(text, Fore.RED)


def _yellow(text):
    return _colorize(text, Fore.YELLOW)


def _colorize_security(enc):
    if enc == 'OPEN' or enc == 'WEP':
        return _red(enc)
    elif enc == 'WPA2':
        return _green(enc)
    else:
        return _yellow(enc)


def _colorize_wps(wps):
    return _red('ON') if wps else _green('OFF')
    # return _red('Enabled') if wps else _green('Disabled')


def get_addr_from_list(bytes_list):
    "Return a string of a MAC address on a bytes list."
    return ":".join(map(lambda x: "%02X" % x, bytes_list))


def get_list_from_addr(address):
    "Return a list from a MAC address string."
    return map(lambda x: int(x, 16), address.split(":"))


def is_valid_mac_address(address):
    "Return True if it is a valid mac address."
    return False if address is None else re.compile("^((?:[0-9a-fA-F]{2}[:]){5}[0-9a-fA-F]{2})$").match(address)


def mac_to_int(address):
    return int(address.replace('-', '').replace(':', ''), 16)


def get_vendor(addr):
    try:
        return netaddr.OUI(addr[:8].replace(':', '-')).registration().org
    except netaddr.core.NotRegisteredError:
        return 'UNKNOW'


class WPSParser(object):
    WPS_DATA_ELEMENTS = {
        0x1001: "AP Channel",
        0x1002: "Association State",
        0x1003: "Authentication Type",
        0x1004: "Authentication Type Flags",
        0x1005: "Authenticator",
        0x1008: "Config Methods",
        0x1009: "Configuration Error",
        0x100A: "Confirmation URL4",
        0x100B: "Confirmation URL6",
        0x100C: "Connection Type",
        0x100D: "Connection Type Flags",
        0x100E: "Credential",
        0x1011: "Device Name",
        0x1012: "Device Password ID",
        0x1014: "E-Hash1",
        0x1015: "E-Hash2",
        0x1016: "E-SNonce1",
        0x1017: "E-SNonce2",
        0x1018: "Encrypted Settings",
        0x100F: "Encryption Type",
        0x1010: "Encryption Type Flags",
        0x101A: "Enrollee Nonce",
        0x101B: "Feature ID",
        0x101C: "Identity",
        0x101D: "Identity Proof",
        0x101E: "Key Wrap Authenticator",
        0x101F: "Key Identifier",
        0x1020: "MAC Address",
        0x1021: "Manufacturer",
        0x1022: "Message Type",
        0x1023: "Model Name",
        0x1024: "Model Number",
        0x1026: "Network Index",
        0x1027: "Network Key",
        0x1028: "Network Key Index",
        0x1029: "New Device Name",
        0x102A: "New Password",
        0x102C: "OOB Device Password",
        0x102D: "OS Version",
        0x102F: "Power Level",
        0x1030: "PSK Current",
        0x1031: "PSK Max",
        0x1032: "Public Key",
        0x1033: "Radio Enabled",
        0x1034: "Reboot",
        0x1035: "Registrar Current",
        0x1036: "Registrar Established",
        0x1037: "Registrar List",
        0x1038: "Registrar Max",
        0x1039: "Registrar Nonce",
        0x103A: "Request Type",
        0x103B: "Response Type",
        0x103C: "RF Bands",
        0x103D: "R-Hash1",
        0x103E: "R-Hash2",
        0x103F: "R-SNonce1",
        0x1040: "R-SNonce2",
        0x1041: "Selected Registrar",
        0x1042: "Serial Number",
        0x1044: "Wi-Fi Protected Setup State",
        0x1045: "SSID",
        0x1046: "Total Networks",
        0x1047: "UUID-E",
        0x1048: "UUID-R",
        0x1049: "Vendor Extension",
        0x104A: "Version",
        0x104B: "X.509 Certificate Request",
        0x104C: "X.509 Certificate",
        0x104D: "EAP Identity",
        0x104E: "Message Counter",
        0x104F: "Public Key Hash",
        0x1050: "Rekey Key",
        0x1051: "Key Lifetime",
        0x1052: "Permitted Config Methods",
        0x1053: "Selected Registrar Config Methods",
        0x1054: "Primary Device Type",
        0x1055: "Secondary Device Type List",
        0x1056: "Portable Device",
        0x1057: "AP Setup Locked",
        0x1058: "Application Extension",
        0x1059: "EAP Type",
        0x1060: "Initialization Vector",
        0x1061: "Key Provided Automatically",
        0x1062: "802.1X Enabled",
        0x1063: "AppSessionKey",
        0x1064: "WEPTransmitKey"
    }

    # Information element tags
    elTags = {
        'SSID': 0,
        'Vendor': 221
    }

    # Dictionary of relevent WPS tags and values
    wpsTags = {
        'APLocked': {'id': 0x1057, 'desc': None},
        'WPSUUID-E': {'id': 0x1047, 'desc': None},
        'WPSRFBands': {'id': 0x103C, 'desc': None},
        'WPSRegistrar': {'id': 0x1041, 'desc': None},
        'WPSState': {'id': 0x1044, 'desc': {
            0x01: 'Not Configured',
            0x02: 'Configured'
        }
                     },
        'WPSVersion': {'id': 0x104a, 'desc': {
            0x10: '1.0',
            0x11: '1.1'
        }
                       },
        'WPSRegConfig': {'id': 0x1053, 'desc': {
            0x0001: 'USB',
            0x0002: 'Ethernet',
            0x0004: 'Label',
            0x0008: 'Display',
            0x0010: 'External NFC',
            0x0020: 'Internal NFC',
            0x0040: 'NFC Interface',
            0x0080: 'Push Button',
            0x0100: 'Keypad'
        },
                         'action': 'or'
                         },
        'WPSPasswordID': {'id': 0x1012, 'desc': {
            0x0000: 'Pin',
            0x0004: 'PushButton'
        }
                          }

    }

    WPS_ID = "\x00\x50\xF2\x04"

    wps_attributes = {
        0x104A: {'name': 'Version                          ', 'type': 'hex'},
        0x1044: {'name': 'WPS State                        ', 'type': 'hex'},
        0x1057: {'name': 'AP Setup Locked                  ', 'type': 'hex'},
        0x1041: {'name': 'Selected Registrar               ', 'type': 'hex'},
        0x1012: {'name': 'Device Password ID               ', 'type': 'hex'},
        0x1053: {'name': 'Selected Registrar Config Methods', 'type': 'hex'},
        0x103B: {'name': 'Response Type                    ', 'type': 'hex'},
        0x1047: {'name': 'UUID-E                           ', 'type': 'hex'},
        0x1021: {'name': 'Manufacturer                     ', 'type': 'str'},
        0x1023: {'name': 'Model Name                       ', 'type': 'str'},
        0x1024: {'name': 'Model Number                     ', 'type': 'str'},
        0x1042: {'name': 'Serial Number                    ', 'type': 'str'},
        0x1054: {'name': 'Primary Device Type              ', 'type': 'hex'},
        0x1011: {'name': 'Device Name                      ', 'type': 'str'},
        0x1008: {'name': 'Config Methods                   ', 'type': 'hex'},
        0x103C: {'name': 'RF Bands                         ', 'type': 'hex'},
        0x1045: {'name': 'SSID                             ', 'type': 'str'},
        0x102D: {'name': 'OS Version                       ', 'type': 'str'}
    }

    # def __init__(self):
    #     pass

    def parse_wps(self, IEs):
        "Returns dictionary with WPS Information."
        ret = {}

        # TODO: improve parsing
        try:
            for element in IEs:
                offset = 0
                data = element[1]
                offset += 1

                dataLength = len(data)
                # print('dataLength %s' % dataLength)
                while offset < dataLength:
                    tagType = struct.unpack("!H", data[offset:offset + 2])[0]
                    offset += 2
                    tagLen = struct.unpack("!H", data[offset:offset + 2])[0]
                    offset += 2
                    tagData = data[offset:offset + tagLen]
                    offset += tagLen

                    # Get the Tag Type
                    if self.WPS_DATA_ELEMENTS.has_key(tagType):
                        tagType = self.WPS_DATA_ELEMENTS[tagType]
                    else:
                        tagType = None

                    if tagType == "Wi-Fi Protected Setup State":
                        if tagData == '\x01':
                            tagData = "Not Configured"
                        elif tagData == '\x02':
                            tagData = "Configured"
                        else:
                            tagData = 'Reserved'

                    if tagType == "UUID-E":
                        aux = ''
                        for c in tagData:
                            aux += "%02X" % ord(c)
                        tagData = aux

                    if tagType == "Response Type":
                        if tagData == '\x00':
                            tagData = 'Enrollee, Info Only'
                        elif tagData == '\x01':
                            tagData = 'Enrollee, open 802.1X'
                        elif tagData == '\x02':
                            tagData = 'Registrar'
                        elif tagData == '\x03':
                            tagData = 'AP'
                        else:
                            tagData = '<unkwon>'

                    if tagType == "Primary Device Type":
                        category = struct.unpack("!H", tagData[0:2])[0]
                        subCategory = struct.unpack("!H", tagData[6:8])[0]
                        if category == 1:
                            category = "Computer"
                            if subCategory == 1:
                                subCategory = "PC"
                            elif subCategory == 2:
                                subCategory = "Server"
                            elif subCategory == 3:
                                subCategory = "Media Center"
                            else:
                                subCategory = "<unkwon>"
                        elif category == 2:
                            category = "Input Device"
                            subCategory = "<unkwon>"
                        elif category == 3:
                            category = "Printers, Scanners, Faxes and Copiers"
                            if subCategory == 1:
                                subCategory = "Printer"
                            elif subCategory == 2:
                                subCategory = "Scanner"
                            else:
                                subCategory = "<unkwon>"
                        elif category == 4:
                            category = "Camera"
                            if subCategory == 1:
                                subCategory = "Digital Still Camera"
                            else:
                                subCategory = "<unkwon>"
                        elif category == 5:
                            category = "Storage"
                            if subCategory == 1:
                                subCategory = "NAS"
                            else:
                                subCategory = "<unkwon>"
                        elif category == 6:
                            category = "Network Infrastructure"
                            if subCategory == 1:
                                subCategory = "AP"
                            elif subCategory == 2:
                                subCategory = "Router"
                            elif subCategory == 3:
                                subCategory = "Switch"
                            else:
                                subCategory = "<unkwon>"
                        elif category == 7:
                            category = "Display"
                            if subCategory == 1:
                                subCategory = "Television"
                            elif subCategory == 2:
                                subCategory = "Electronic Picture Frame"
                            elif subCategory == 3:
                                subCategory = "Projector"
                            else:
                                subCategory = "<unkwon>"
                        elif category == 8:
                            category = "Multimedia Devices"
                            if subCategory == 1:
                                subCategory = "DAR"
                            elif subCategory == 2:
                                subCategory = "PVR"
                            elif subCategory == 3:
                                subCategory = "MCX"
                            else:
                                subCategory = "<unkwon>"
                        elif category == 9:
                            category = "Gaming Devices"
                            if subCategory == 1:
                                subCategory = "Xbox"
                            elif subCategory == 2:
                                subCategory = "Xbox360"
                            elif subCategory == 3:
                                subCategory = "Playstation"
                            else:
                                subCategory = "<unkwon>"
                        elif category == 10:
                            category = "Telephone"
                            if subCategory == 1:
                                subCategory = "Windows Mobile"
                            else:
                                subCategory = "<unkwon>"
                        else:
                            category = "<unkwon>"
                            subCategory = "<unkwon>"
                        tagData = "%s - %s" % (category, subCategory)

                        if tagType == "Version":
                            tagData = struct.unpack("B", tagData)[0]
                            major = tagData >> 4
                            minor = tagData & 0x0F
                            tagData = "%d.%d" % (major, minor)

                        if tagType == "Config Methods":
                            methods = {
                                0x0001: "USB",
                                0x0002: "Ethernet",
                                0x0004: "Label",
                                0x0008: "Display",
                                0x0010: "External NFC Token",
                                0x0020: "Integrated NFC Token",
                                0x0040: "NFC Interface",
                                0x0080: "PushButton",
                                0x0100: "Keypad"
                            }
                            result = []
                            tagData = struct.unpack("!H", tagData)[0]
                            for key, value in methods.items():
                                if key & tagData:
                                    result.append(value)
                            tagData = ", ".join(result)

                    if tagType:
                        ret[tagType] = tagData

            return ret
        except:
            print('Error parsing vendor specific fields!')
            hexdump(IEs)
            return None

    def has_wps(self, IEs):
        "Returns True if WPS Information Element is present."
        for element in IEs:
            oui = element[0]
            data = element[1]
            if oui == "\x00\x50\xF2" and data[0] == "\x04":  # WPS IE
                return True
        return False

    # Converts an array of bytes ('\x01\x02\x03...') to an integer value
    def strToInt(self, string):
        intval = 0
        shift = (len(string) - 1) * 8;

        for byte in string:
            try:
                intval += int(ord(byte)) << shift
                shift -= 8
            except Exception, e:
                print 'Caught exception converting string to int:', e
                return False
        return intval

    # Parse a particular ELT layer from a packet looking for WPS info
    def get_wps_info(self, elt):
        data = None
        tagNum = elt.ID
        wpsInfo = {}
        minSize = offset = 4
        typeSize = versionSize = 2

        # ELTs must be this high to ride!
        if elt.len > minSize:
            # Loop through the entire ELT
            while offset < elt.len:
                key = ''
                val = ''

                try:
                    # Get the ELT type code
                    eltType = self.strToInt(elt.info[offset:offset + typeSize])
                    offset += typeSize
                    # Get the ELT data length
                    eltLen = self.strToInt(elt.info[offset:offset + versionSize])
                    offset += versionSize
                    # Pull this ELT's data out
                    data = elt.info[offset:offset + eltLen]
                    data = self.strToInt(data)
                except:
                    return False

                # Check if we got a WPS-related ELT type
                for (key, tinfo) in self.wpsTags.iteritems():
                    if eltType == tinfo['id']:
                        if tinfo.has_key('action') and tinfo['action'] == 'or':
                            for method, name in tinfo['desc'].iteritems():
                                if (data | method) == data:
                                    val += name + ' | '
                            val = val[:-3]
                        else:
                            try:
                                val = tinfo['desc'][data]
                            except Exception, e:
                                val = str(hex(data))
                        break

                if key and val:
                    wpsInfo[key] = val
                offset += eltLen
        return wpsInfo

    # Check if an element is a WPS element
    def is_wps_elt(self, elt):
        WPS_ID = "\x00\x50\xF2\x04"
        if elt.ID == 221:
            if elt.info.startswith(WPS_ID):
                return True
        return False

    # Parse a WPS element
    def parse_wps_elt(self, elt):
        data = []
        # tagname = None
        # tagdata = None
        # datatype = None
        # tag = 0
        # tlen = 0
        i = len(self.WPS_ID)

        try:
            if self.is_wps_elt(elt):
                while i < elt.len:
                    # Get tag number and length
                    tag = int((ord(elt.info[i]) * 0x100) + ord(elt.info[i + 1]))
                    i += 2
                    tlen = int((ord(elt.info[i]) * 0x100) + ord(elt.info[i + 1]))
                    i += 2

                    # Get the tag data
                    tagdata = elt.info[i:i + tlen]
                    i += tlen

                    # Lookup the tag name and type
                    try:
                        tagname = self.wps_attributes[tag]['name']
                        datatype = self.wps_attributes[tag]['type']
                    except Exception, e:
                        tagname = 'Unknown'
                        datatype = 'hex'

                    # Append to array
                    data.append((tagname, tagdata, datatype))
        except Exception, e:
            print 'Exception processing WPS element:', e

        return data

    def parse_beacon(self, packet):
        # Parse captured packets looking for 802.11 WPS-related packets

        wpsInfo = False
        essid = False
        bssid = False

        # Check if the packet is a 802.11 beacon with an ELT layer
        if packet.haslayer(Dot11Beacon) and packet.haslayer(Dot11Elt):
            bssid = packet[Dot11].addr3.upper()
            # if self.bssid and self.bssid != bssid:
            #     return
            pkt = packet

            # Loop through all of the ELT layers in the packet
            while Dot11Elt in pkt:
                pkt = pkt[Dot11Elt]
                # Check the ELT layer. Is it a vendor? If so, try to get the WPS info.
                if pkt.ID == self.elTags['Vendor']:
                    wpsInfo = self.get_wps_info(pkt)
                    if wpsInfo:
                        break

                pkt = pkt.payload

        return wpsInfo

    # Display collected WPS data
    def printwpsinfo(self, wpsdata, bssid, essid):
        textlen = 33
        filler = ' '
        if wpsdata:
            # print ''
            print 'BSSID:', bssid
            print 'ESSID:', essid
            print '----------------------------------------------------------'
            for (header, data, datatype) in wpsdata:
                if datatype != 'str':
                    tdata = data
                    data = '0x'
                    for i in tdata:
                        byte = str(hex(ord(i)))[2:]
                        if len(byte) == 1:
                            byte = '0' + byte
                        data += byte
                header = header + (filler * (textlen - len(header)))
                print '%s : %s' % (header, data)
            # print ''

    def parse_probe_response(self, pkt):
        # Probe response packet handler
        wpsdata = []
        eltcount = 1
        elt = None

        # Loop through all information elements
        while elt != pkt.lastlayer(Dot11Elt):
            elt = pkt.getlayer(Dot11Elt, nb=eltcount)
            eltcount += 1

            if self.is_wps_elt(elt):
                wpsdata = self.parse_wps_elt(elt)

        return wpsdata


class WpsScanner(object):

    def __init__(self, interface, channel=None, timeout=5, output=None, passive=False, mac=None, logfile=None):
        self.interface = interface
        self.channel = channel
        self.timeout = timeout
        self.output = output
        self.passive = passive
        self.mac = mac if is_valid_mac_address(mac) else None
        self.logfile = logfile
        #
        self.aps = {}
        self.wps_aps = {}
        self.captured = []
        self.probes_sent = []
        self._stop = False
        #
        self.wps_parser = WPSParser()
        self.rtDecoder = RadioTapDecoder()

        # Initialize logger
        self.logger = logging.getLogger('airlog')
        self.logger.setLevel(logging.INFO)

        # Console logging
        ch = logging.StreamHandler()
        ch.setLevel(logging.INFO)
        formatter = coloredlogs.ColoredFormatter('[%(asctime)s] - %(levelname)s - %(message)s',
                                                 datefmt='%d.%m.%Y %H:%M:%S')
        ch.setFormatter(formatter)
        self.logger.addHandler(ch)

        # Logging to file
        if logfile is None:
            return
        fh = logging.FileHandler(logfile)
        fh.setLevel(logging.DEBUG)
        formatter = logging.Formatter('[%(asctime)s] - %(message)s', datefmt='%d.%m.%Y %H:%M:%S')
        fh.setFormatter(formatter)
        self.logger.addHandler(fh)

    def set_mode(self, mode):
        self.logger.debug('Enabling %s mode on %s' % (mode, self.interface))
        os.system('ifconfig %s down' % self.interface)
        os.system('iwconfig %s mode %s' % (self.interface, mode))
        os.system('ifconfig %s up' % self.interface)

    def enable_monitor(self):
        self.set_mode('monitor')
        # return subprocess.Popen('ifconfig %s down && iw %s set type monitor && ifconfig %s up' %
        #                         (self.interface, self.interface, self.interface), shell=True).communicate()

    def set_channel(self, channel):
        os.system('iwconfig %s channel %s' % (self.interface, channel))

    def signal_handler(self, frame, code):
        # print("Ctrl+C caught. Exiting..")
        # sys.exit(-1)
        try:
            if query_yes_no("\nReally quit?"):
                self.logger.info('Trying to quit correctly. Be patient please...')
                self._stop = True
                # self.save()
        except KeyboardInterrupt:
            self.logger.warning("Ok ok... Quitting without saving!")
            sys.exit(1)

    def get_security(self, pkt):
        # Check for encrypted networks
        capability = pkt.sprintf("{Dot11Beacon:%Dot11Beacon.cap%}\
                {Dot11ProbeResp:%Dot11ProbeResp.cap%}")
        p = pkt[Dot11Elt]
        crypto = set()
        while isinstance(p, Dot11Elt):
            if p.ID == 48:
                crypto.add("WPA2")
            elif p.ID == 221 and p.info.startswith('\x00P\xf2\x01\x01\x00'):
                crypto.add("WPA")
            p = p.payload

        if not crypto:
            if 'privacy' in capability:
                crypto.add("WEP")
            else:
                crypto.add("OPEN")

        return '/'.join(crypto)

    def handle_beacon(self, pkt):
        """Process 802.11 Beacon Frame for WPS IE."""
        try:
            rt = self.rtDecoder.get_protocol(dot11.RadioTap)
            mgt = self.rtDecoder.get_protocol(dot11.Dot11ManagementFrame)
            beacon = self.rtDecoder.get_protocol(dot11.Dot11ManagementBeacon)
            bssid = get_addr_from_list(mgt.get_bssid())
            essid = str(beacon.get_ssid())
            freq = rt.get_channel()[0]
            channel = frequencies_dict[freq]
            enc = self.get_security(pkt)
            vendor = get_vendor(bssid)
            wps = self.wps_parser.has_wps(beacon.get_vendor_specific())

            # Display and save discovered AP
            if bssid in self.aps:
                return

            self.logger.info("[+] AP found! Channel: %02d ESSID: %s BSSID: %s Encryption: %s Vendor: %s WPS: %s" %
                             (int(channel), essid, bssid, enc, vendor, wps))
            self.aps[bssid] = (int(channel), essid, enc, wps)

            #
            wi = self.wps_parser.parse_beacon(pkt)
            print('WPSINFO', wi)

            # ACTIVE MODE
            if wps and not self.passive and bssid not in self.probes_sent:
                self.send_probe_req(essid)
                # self.send_probe_req_2(essid)
                self.probes_sent.append(bssid)

        except Exception as e:
            print('Error while parsing beacon')
            print(str(sys.exc_info()))
            return None

    def handle_probe_response(self, pkt):
        """Process 802.11 Probe Response Frame for WPS IE."""
        try:
            mgt = self.rtDecoder.get_protocol(dot11.Dot11ManagementFrame)
            probe = self.rtDecoder.get_protocol(dot11.Dot11ManagementProbeResponse)
            bssid = get_addr_from_list(mgt.get_bssid())
            essid = probe.get_ssid()

            # If null byte in the SSID IE, its cloacked.
            if essid.find("\x00") != -1:
                essid = "<No ssid>"

            if bssid in self.aps:
                return

            rt = self.rtDecoder.get_protocol(dot11.RadioTap)
            freq = rt.get_channel()[0]
            channel = frequencies_dict[freq]
            vendor = get_vendor(bssid)
            vendorIEs = probe.get_vendor_specific()
            wps = self.wps_parser.has_wps(vendorIEs)

            # print 'checking wps info'
            if self.wps_parser.has_wps(vendorIEs):
                hexdump(vendorIEs)
                # wpsInfo = self.wps_parser.parse_wps(vendorIEs)

                if wpsInfo:
                    self.wps_aps[bssid] = wpsInfo
                    print("[%s] - [%s]\t%s'\nWPS Information" % (bssid, essid, vendor))
                    for key, value in wpsInfo.items():
                        print("[WPSINFO]  * %s: %s" % (key, repr(value)))

                self.wps_parser.parse_probe_response(pkt)

            enc = self.get_security(pkt)
            self.aps[bssid] = (channel, essid, enc, wps)
            self.logger.info(
                '[+] AP discovered! ProbeResponse channel: %s ESSID: %s Encryption: %s WPS: %s Vendor: %s' %
                (channel, _green(essid), _colorize_security(enc), _colorize_wps(wps), _green(get_vendor(bssid))))

        except Exception:
            print('Error while parsing probe responsse')
            print(str(sys.exc_info()))
            return

    @property
    def scan_table(self):
        x = PrettyTable(['Channel', 'BSSID', 'ESSID', 'Security', 'Vendor', 'WPS', 'WPS Info'])
        x.align["ESSID"] = "l"
        x.align["Vendor"] = "l"
        for bssid in sorted(self.aps, key=lambda k: self.aps[k][0]):
            channel, essid, enc, wps= self.aps[bssid]
            wps_text = ''
            wpsinfo = self.wps_aps[bssid] if bssid in self.wps_aps else None
            if wpsinfo:
                for key, value in wpsinfo.items():
                    wps_text += " %s: %s" % (key, repr(value))
            x.add_row([channel, bssid, essid, _colorize_security(enc), get_vendor(bssid), _colorize_wps(wps), wps_text])
        return x

    def pkt_handler(self, pkt):
        try:
            self.rtDecoder.decode(str(pkt))
        except Exception:
            self.logger.error('Error while decoding packet..')
            print(sys.exc_info())
            return

        # Management frames
        if pkt.type == 0:

            # Probe response
            if pkt.subtype == 5:
                self.handle_probe_response(pkt)

            # Beacon
            elif pkt.subtype == 8:
                self.handle_beacon(pkt)

    def send_probe_req(self, bssid, essid):
        """Send a probe request to the specified AP"""
        src = RandMAC() if self.mac is None else self.mac
        self.logger.info('[!] Sending Broadcast Probe Request: SRC=[%s] -> BSSID: %s ESSID: %s' % (src, bssid, essid))
        param = Dot11ProbeReq()
        essid = Dot11Elt(ID='SSID', info=essid)
        rates = Dot11Elt(ID='Rates', info="\x03\x12\x96\x18\x24\x30\x48\x60")
        dsset = Dot11Elt(ID='DSset', info='\x01')
        pkt = RadioTap() / Dot11(type=0, subtype=4, addr1='ff:ff:ff:ff:ff:ff', addr2=src,
                      addr3='ff:ff:ff:ff:ff:ff') / param / essid / rates / dsset

        try:
            sendp(pkt, verbose=0)
        except:
            return
            # raise

    #
        print ("Probing network '%s (%s)'\n" % (bssid, essid))

        try:
            # Build a probe request packet with a SSID and a WPS information element
            dst = mac2str(bssid)
            src = mac2str("ff:ff:ff:ff:ff:ff")
            packet = Dot11(addr1=dst, addr2=src, addr3=dst) / Dot11ProbeReq()
            packet = packet / Dot11Elt(ID=0, len=len(essid), info=essid) / Dot11Elt(ID=221, len=9,
                                                                                    info="%s\x10\x4a\x00\x01\x10" % self.wps_parser.WPS_ID)

            # Send it!
            send(packet, verbose=0)
            # self.probedNets[bssid] = None
        except Exception, e:
            print 'Failure sending probe request to', essid, ':', e

    # def send_probe_req_2(self, ssid):
    #     """Return 802.11 Probe Request Frame."""
    #     src = RandMAC() if self.mac is None else self.mac
    #     self.logger.info('[!] Sending broadcast probe request: SRC=[%s] -> ESSID=[%s]' % (src, ssid))
    #     src = get_list_from_addr(src)
    #
    #     # Frame Control
    #     frameControl = dot11.Dot11()
    #     frameControl.set_version(0)
    #     frameControl.set_type_n_subtype(dot11.Dot11Types.DOT11_TYPE_MANAGEMENT_SUBTYPE_PROBE_REQUEST)
    #     # Frame Control Flags
    #     frameControl.set_fromDS(0)
    #     frameControl.set_toDS(0)
    #     frameControl.set_moreFrag(0)
    #     frameControl.set_retry(0)
    #     frameControl.set_powerManagement(0)
    #     frameControl.set_moreData(0)
    #     frameControl.set_protectedFrame(0)
    #     frameControl.set_order(0)
    #     # Management Frame
    #     sequence = random.randint(0, 4096)
    #     broadcast = [0xff, 0xff, 0xff, 0xff, 0xff, 0xff]
    #     mngtFrame = dot11.Dot11ManagementFrame()
    #     mngtFrame.set_duration(0)
    #     mngtFrame.set_destination_address(broadcast)
    #     mngtFrame.set_source_address(src)
    #     mngtFrame.set_bssid(broadcast)
    #     mngtFrame.set_fragment_number(0)
    #     mngtFrame.set_sequence_number(sequence)
    #     # Probe Request Frame
    #     probeRequestFrame = dot11.Dot11ManagementProbeRequest()
    #     probeRequestFrame.set_ssid(ssid)
    #     probeRequestFrame.set_supported_rates([0x02, 0x04, 0x0b, 0x16])
    #     # How is your daddy?802.11 B
    #     mngtFrame.contains(probeRequestFrame)
    #     frameControl.contains(mngtFrame)
    #
    #     return sendp(frameControl.get_packet(), iface=self.interface, verbose=0)

    def sniff(self, channel=None, timeout=None):
        if self._stop:
            return

        self.logger.info('Sniffing with %s on channel %s' % (self.interface, channel,))
        if channel is not None:
            self.set_channel(channel)

        self.captured.extend(
            sniff(self.interface,
                  prn=self.pkt_handler,
                  lfilter=lambda p: p.haslayer(Dot11) and p.type == 0,
                  timeout=timeout,
                  stop_filter=lambda x: self._stop,
                  store=self.output is not None))

    def scan(self):
        if self.channel is None:
            self.logger.info('Channel not specified. Scanning on ALL channels')
            for c in channel_hop_list:
                # if self._stop:
                #     break
                self.sniff(c, timeout=self.timeout)

        else:
            self.logger.info('Scanning on channel %s' % self.channel)
            self.sniff(self.channel, timeout=self.timeout)

    def save(self):
        # Check if saving is required
        if self.output is None:
            return

        # Check if we have captureed simething
        if self.captured is None or len(self.captured) == 0:
            self.logger.error("[!] Nothing to save to PCAP file")
            return

        # Save captured packets to PCAP file
        self.logger.info("Saving %i captured packets to %s" % (len(self.captured), self.output))
        wrpcap(self.output, self.captured)

    def run(self):
        # Set signal handler
        signal.signal(signal.SIGINT, self.signal_handler)

        # Enable monitor
        if 'mon' not in self.interface:
            print("Monitor mode not enabled! Enabling monitor interface on " + self.interface)
            self.enable_monitor()

        # Scan
        self.scan()


@click.group()
def cli1():
    pass


@cli1.command()
@click.option("-i", "--interface", help="wireless interface to use")
@click.option("-c", "--channel", type=int, help="WiFi channel, if not specified search on ALL channels")
@click.option("-t", "--timeout", type=int, default=5, help="Timeoumac2strt for channel hopping")
@click.option("-o", "--output", help="pcap file to save captured packets")
@click.option("-p", "--passive", is_flag=True, help="do not send probe request")
@click.option("-m", "--mac", help="spoof source mac address.")
@click.option("-l", "--logfile", help="write to logfile")
def scan(interface, channel, timeout, output, passive, mac, logfile):
    """Perform scan for WPS enabled access points"""
    if interface not in get_if_list():
        click.secho('Wrong interface specified: %s' % interface, fg='red')
        return

    click.echo('Perfoming WPS scan on interface ' + interface)
    wpscan = WpsScanner(interface, channel, timeout, output, passive, mac, logfile)
    wpscan.run()

    click.secho('WPS scan results', fg='cyan')
    print(wpscan.scan_table)


@click.group()
def cli2():
    pass


@cli2.command()
@click.option("-i", "--interface", help="wireless interface to use")
@click.option("-c", "--channel", type=int, help="WiFi channel, if not specified search on ALL channels")
@click.option("-b", "--bssid", type=int, help="target BSSID")
@click.option("-e", "--essid", type=int, help="Wtarget ESSID")
@click.option("-t", "--timeout", type=int, default=5, help="Timeout for channel hopping")
@click.option("-o", "--output", help="pcap file to save captured packets")
@click.option("-p", "--passive", is_flag=True, help="do not send probe request")
@click.option("-m", "--mac", help="spoof source mac address.")
@click.option("-l", "--logfile", help="write to logfile")
def pwn(interface, channel, timeout, output, passive, mac, logfile):
    """Try to pwn WPS enabled access points"""
    click.echo('Perfoming WPS scan on interface ' + interface)
    wpscan = WpsScanner(interface, channel, timeout, output, passive, mac, logfile)
    wpscan.run()


cli = click.CommandCollection(sources=[cli1, cli2])
cli.context_settings = dict(help_option_names=['-h', '--help'])

if __name__ == '__main__':
    cli()
