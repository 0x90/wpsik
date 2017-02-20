#!/usr/bin/env python
# -*- coding: utf-8 -*-
# WPS scan and pwn tool
#
# Based on:
#   WPSIG by CoreSecurity http://www.coresecurity.com/corelabs-research/open-source-tools/wpsig
#   devttys0 wps scripts https://github.com/devttys0/wps
#

import click
from colorama import init

init()

from wpsik.scanner import WpsScanner

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
    # if interface not in get_if_list():
    #     click.secho('Wrong interface specified: %s' % interface, fg='red')
    #     return

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
