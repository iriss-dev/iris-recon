"""Backward-compatibility CLI wrapper forwarding to inmap."""
import argparse
import ipaddress
import json
from pathlib import Path
import re
import shutil
import subprocess
import sys
import sqlite3
import http.client
import ssl
import xml.etree.ElementTree as ET

import inmap

parse_xml = inmap.parse_xml
compare = inmap.compare
render_html = inmap.render_html
save_report = inmap.save_report
validate_ports = inmap.validate_ports
scan_command = inmap.scan_command
bounded_rate = inmap.bounded_rate
__version__ = inmap.__version__


def main(argv=None):
    orig_shutil = inmap.shutil
    orig_subprocess = inmap.subprocess
    inmap.shutil = shutil
    inmap.subprocess = subprocess
    try:
        return inmap.main(argv)
    finally:
        inmap.shutil = orig_shutil
        inmap.subprocess = orig_subprocess


if __name__ == '__main__':
    sys.exit(main())
