#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Setup script for wpsik
from setuptools import setup, find_packages
from sys import platform

requirements =[
        'Click',
        'scapy',
        'pcapy',
        'netaddr',
        'impacket',
        'prettytable',
        'coloredlogs',
        'colorama']

if platform == "linux" or platform == "linux2":
    requirements.append('pyric')
elif platform == "darwin":
    requirements.append('pyobjc')
elif platform == "win32":
    raise NotImplemented

setup(
    name='wpsik',
    version='0.2',
    license='GPL',
    author='0x90',
    packages=find_packages(),
    install_requires=requirements,
    entry_points='''
        [console_scripts]
        wpsik=wpsik.cli:cli
    ''',
)
