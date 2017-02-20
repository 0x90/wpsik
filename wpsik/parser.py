import struct
from scapy.layers.dot11 import Dot11Beacon, Dot11Elt, Dot11
from scapy.utils import hexdump


class WpsParser(object):

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

