import logging
import os
import signal
import subprocess
import sys
from sys import platform

# external dependencies
logging.getLogger("scapy.runtime").setLevel(logging.ERROR)
from scapy.sendrecv import sendp, sniff, wrpcap, send
from scapy.utils import hexdump, mac2str
from scapy.volatile import RandMAC
from scapy.layers.dot11 import RadioTap, Dot11, Dot11ProbeReq, Dot11Elt
#
from impacket import dot11
from impacket.ImpactDecoder import RadioTapDecoder
#
from prettytable import PrettyTable
import coloredlogs
#
from .channels import frequencies_dict, channel_hop_list
from .parser import WpsParser
from .helper import is_valid_mac_address, get_vendor, query_yes_no,get_addr_from_list
from .helper import _green, _colorize_security, _colorize_wps

LINUX = False
OSX = False
AIRPORT = "/System/Library/PrivateFrameworks/Apple80211.framework/Versions/Current/Resources/airport"

# Detect platform
if platform == "linux" or platform == "linux2":
    LINUX = True
elif platform == "darwin":
    OSX = True
elif platform == "win32":
    print('Windows is not supported!')
    raise NotImplemented


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
        self.wps_parser = WpsParser()
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
        if OSX:
            return

        self.logger.debug('Enabling %s mode on %s' % (mode, self.interface))
        os.system('ifconfig %s down' % self.interface)
        os.system('iwconfig %s mode %s' % (self.interface, mode))
        os.system('ifconfig %s up' % self.interface)

    def enable_monitor(self):
        self.set_mode('monitor')
        # return subprocess.Popen('ifconfig %s down && iw %s set type monitor && ifconfig %s up' %
        #                         (self.interface, self.interface, self.interface), shell=True).communicate()

    def set_channel(self, channel):
        if LINUX:
            os.system('iwconfig %s channel %s' % (self.interface, channel))
        elif OSX:
            subprocess.call(['sudo', AIRPORT, '--channel=' + str(channel)])
            # os.system('%s %s --channel=%s' % (AIRPORT ,self.interface, channel))

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
            # wi = self.wps_parser.parse_beacon(pkt)
            # print('WPSINFO', wi)

            # ACTIVE MODE
            # if wps and not self.passive and bssid not in self.probes_sent:
            #     self.send_probe_req(essid)
            #     # self.send_probe_req_2(essid)
            #     self.probes_sent.append(bssid)

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
            if essid is None or essid.find("\x00") != -1:
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
                wpsInfo = self.wps_parser.parse_wps(vendorIEs)

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
            #
            self.logger.info('Channel not specified. Scanning on ALL channels')
            for c in channel_hop_list:
                self.sniff(c, timeout=self.timeout)

        else:
            #
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
