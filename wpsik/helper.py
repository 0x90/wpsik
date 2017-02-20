import re
import sys
import netaddr
from colorama import Fore


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
