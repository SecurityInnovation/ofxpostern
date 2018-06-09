#!/usr/bin/env python3

"""
Script to...
"""

import argparse
import logging
import os
import sys

#
# Defines
#

#
# Globals
#

PROGRAM_NAME = 'postern'
DATA_DIR = "{}/.{}".format(os.environ['HOME'], PROGRAM_NAME)

# Logging
logger = logging.getLogger()

#
# Helper Functions
#

def init():
    '''
    Initialize environment
    '''

    # Create directory to cache data
    os.makedirs(DATA_DIR, mode=0o770, exist_ok=True)

#
# Core Logic
#

def main():

    init()

    parser = argparse.ArgumentParser(description='Fingerprint an OFX server.')
    parser.add_argument('ofx-url', help='URL of OFX server to test')
    args = parser.parse_args()

    # Options Parsing
    # postern http://foo.bar/ofx.dll
    #         -c clear cache
    #
    # postern
    # Enter name of financial institution
    # > Cit
    # 1) Citi Bank
    # 2) Citi Bank Financial
    # Select a financial institution:
    # > 2

    # Output
    # 1) Connection Methods
    #    * DirectConnect (OFX)
    #    * Express Web Connect (Intuit API)
    #    * Web Connect (File download)
    # 2) Capabilities
    #    * Checking
    #    * Savings
    #    * Bill Pay
    #    * etc...
    # 3) Connection Info
    #    * URL
    #    * SSL Certificate expiration date
    # 4) Fingerprint
    #    * Service Provider?
    #    * HTTP Server
    #    * Application Framework
    #    * OFX Server
    #      - Company
    #      - Product
    #      - Version
    # 5) Tests
    #    * Information Disclosure
    #    * Zombie Server
    #    * Null values returned
    #    * Long lived session keys
    #    * XSS
    #    * TLS

    # Download FI list
    # - cache it
    # - create .postern in homedir

    # Search
    # - read FI data file
    # - pull capabilities from FI file

    # Send Requests
    # - cache the results
    # - determine TLS issues

    # Capabilities
    # - pull from PROFILE request
    # - else pull from fidata

    # Fingerprint
    # - review responses
    # - print results

    # Test
    # - review responses
    # - print results


if __name__ == '__main__':
    file_handler = logging.FileHandler(os.getcwd() + os.sep + "unittest" +
            ".log")
    file_handler.setFormatter(logging.Formatter(
            '%(asctime)s [%(levelname)s][%(name)s][%(lineno)d] %(message)s'))
    logger = logging.getLogger()
    logger.addHandler(file_handler)
    logger.setLevel(logging.WARNING)

    main()
