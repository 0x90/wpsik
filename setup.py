#!/usr/bin/env python
# -*- coding: utf-8 -*-
# Setup script for wpsik
from setuptools import setup

setup(
    name='wpsik',
    version='0.1',
    py_modules=['wpsik'],
    install_requires=[
        'Click',
        'scapy',
        'impacket',
        'prettytable',
        'coloredlogs',
        'colorama',
    ],
    entry_points='''
        [console_scripts]
        wpsik=wpsik:cli
    ''',
)
