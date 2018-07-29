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
import time

import testofx

#
# Defines
#

PROGRAM_DESCRIPTION = 'Fingerprint an OFX server.'
PROGRAM_NAME = 'ofx-postern'
VERSION = '0.0.1'

DATA_DIR = '{}/.{}'.format(os.environ['HOME'], PROGRAM_NAME)
FIS_DIR = '{}/{}'.format(DATA_DIR, 'fi')
FI_DIR_FMT = '{}/{}'.format(FIS_DIR, '{}-{}-{}')


#
# Globals
#

debug = True

fi_dir = ''

#
# Helper Functions
#

def init(server):
    '''
    Initialize environment
    '''

    global fi_dir

    # Convert URL into usable filename
    url_fname = server.ofxurl.partition('/')[2][1:].replace('/','_').replace('&','+')
    fi_dir = FI_DIR_FMT.format(url_fname, server.fid, server.org)

    # Create directory to store cached data
    os.makedirs(DATA_DIR, mode=0o770, exist_ok=True)
    os.makedirs(FIS_DIR, mode=0o770, exist_ok=True)
    os.makedirs(fi_dir, mode=0o770, exist_ok=True)


def print_debug(msg):
    if debug: print('DEBUG: {}'.format(msg))

#
# Core Logic
#

def send_profile_req(server):
    '''
    Send profile request to the OFX server.
    '''

    otc = testofx.OFXTestClient(output=debug)
    res = otc.send_req(testofx.REQ_NAME_OFX_PROFILE, server)

    # Store in cache


def main():

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

    print_debug(args)

    # TODO: validate input
    server = testofx.OFXServerInstance(args.url, args.fid, args.org)

    # Initialize Persistent Cache
    init(server)

    # Display work in progress
    print('{}: version {}'.format(parser.prog, VERSION))
    print()
    print('Start: {}'.format(time.asctime()))
    print('  Sending <PROFRQ>')
    send_profile_req(server)
    print('End:   {}'.format(time.asctime()))

    # Send Requests
    # - cache the results
    # - determine TLS issues


if __name__ == '__main__':
    main()
