#!/usr/bin/env python3

'''
Fingerprint an OFX server.
'''

# Options Parsing
# ofx-postern <url> [fid] [org]
#             -c clear cache
#
# ofx-postern
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
# 2) Connection Info
#    * URL
#    * SSL Certificate expiration date
# 3) Capabilities
#    * Checking
#    * Savings
#    * Bill Pay
#    * etc...
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

import argparse
import os
import sys

#
# Defines
#

PROGRAM_DESCRIPTION = 'Fingerprint an OFX server.'
PROGRAM_NAME = 'ofx-postern'
DATA_DIR = "{}/.{}".format(os.environ['HOME'], PROGRAM_NAME)

#
# Globals
#

debug = True

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

    parser = argparse.ArgumentParser(description=PROGRAM_DESCRIPTION)
    parser.add_argument('url',
            help='URL of OFX server to test')
    parser.add_argument('-f', '--fid',
            help='Financial ID of Institution',
            required=False)
    parser.add_argument('-o', '--org',
            help='Organization within the Institution',
            required=False)
    args = parser.parse_args()

    if debug: print(args)

    # Send Requests
    # - cache the results
    # - determine TLS issues


if __name__ == '__main__':
    main()
