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
import json
import os
import pickle
import sys
import time

import testofx

#
# Defines
#

PROGRAM_DESCRIPTION = 'Fingerprint an OFX server.'
PROGRAM_NAME = 'ofxpostern'
VERSION = '0.1.0'

DATA_DIR = '{}/.{}'.format(os.environ['HOME'], PROGRAM_NAME)
FIS_DIR = '{}/{}'.format(DATA_DIR, 'fi')
FI_DIR_FMT = '{}/{}'.format(FIS_DIR, '{}-{}-{}')

STR_HEADERS = 'headers'
STR_BODY    = 'body'
STR_OBJ     = 'object'

#
# Globals
#

debug = True
cache = True

fi_dir = ''

req_results = dict()

#
# Helper Functions
#

def init(server):
    '''
    Initialize environment
    '''

    global fi_dir

    if cache:
        # Convert URL into usable filename
        url_fname = server.ofxurl.partition('/')[2][1:].replace('/','_').replace('&','+')
        fi_dir = FI_DIR_FMT.format(url_fname, server.fid, server.org)

        # Create directory to store cached data
        os.makedirs(DATA_DIR, mode=0o770, exist_ok=True)
        os.makedirs(FIS_DIR, mode=0o770, exist_ok=True)
        os.makedirs(fi_dir, mode=0o770, exist_ok=True)


def print_debug(msg):
    if debug: print('DEBUG: {}'.format(msg))


def print_header(msg, lvl):
    '''
    Print a header with underline on 2nd line

    Similar to <H1>, <H2>
    '''
    under_char = ''

    if lvl == 1: under_char = '#'
    elif lvl == 2: under_char = '='
    elif lvl == 3: under_char = '-'
    else: raise ValueError('Unknown lvl: {}'.format(lvl))

    print(msg)
    print(under_char * len(msg))


def print_kv_list(kv_list):
    '''
    Print key:value list with pretty formatting

    kv_list: list[tuples]
    '''

    k_width = 0
    for k, v in kv_list:
        if len(k) > k_width:
            k_width = len(k)

    for k, v in kv_list:
        separator = ':' if len(k) > 0 else ' '
        print('{:{}} {}'.format(k+separator, k_width+1, v))


def print_tree(tree, lvl=1):
    '''
    Print embedded lists as an indented text tree

    Recursive to depth 3

    tree: list[val, list[]...]
    '''
    indent = 2
    bullet = ''

    if lvl == 1: bullet = '*'
    elif lvl == 2: bullet = '+'
    elif lvl == 3: bullet = '-'
    else: raise ValueError('Unknown lvl: {}'.format(lvl))

    for i in tree:
        if type(i) is list:
            print_tree(i, lvl+1)
        else:
            print('{}{} {}'.format(' '*(indent*(lvl-1)), bullet, i))


def print_list(lst, indent=0):
    '''
    Print list with option intent

    lst: list[]
    indent: int, number of spaces
    '''
    bullet = '*'

    for i in lst:
        print('{}{} {}'.format(' '*indent, bullet, i))

#
# Core Logic
#

def send_req(server, req_name):
    '''
    Send request to the OFX server.
    '''

    cached = True
    res_name_base = req_name.replace('/', '+').replace(' ', '_')
    res_obj_path = '{}/{}-{}'.format(fi_dir, res_name_base, STR_OBJ)
    res_hdr_path = '{}/{}-{}'.format(fi_dir, res_name_base, STR_HEADERS)
    res_body_path = '{}/{}-{}'.format(fi_dir, res_name_base, STR_BODY)

    # Pull results out of cache if they exist
    if cache:
        try:
            with open(res_obj_path, 'rb') as fd:
                print_debug('Reading res from cache')
                req_results[req_name] = pickle.loads(fd.read())
        except FileNotFoundError:
            cached = False

    if not cache or not cached:
        otc = testofx.OFXTestClient(output=debug)
        res = otc.send_req(req_name, server)

        # Store result for analysis
        req_results[req_name] = res

        if cache:
            # Store persistently for debugging
            with open(res_obj_path, 'wb') as fd:
                fd.write(pickle.dumps(res))
            with open(res_hdr_path, 'w') as fd:
                fd.write(json.dumps(dict(res.headers)))
            with open(res_body_path, 'w') as fd:
                fd.write(res.text)


def report_cli_fi(profrs):
    '''
    Print Financial Institution information
    '''

    print_header('Financial Institution', 2)
    print()

    fi_list = []
    output = (
            ('FINAME', 'Name'),
            ('ADDR1', 'Address'),
            ('ADDR2', ''),
            ('ADDR3', ''),
            )

    for tup in output:
        try:
            val = profrs.profile[tup[0]]
            fi_list.append((tup[1], val))
        except KeyError: pass

    city = ''
    state = ''
    postalcode = ''

    try:
        city = profrs.profile['CITY']
        state = profrs.profile['STATE']
        postalcode = profrs.profile['POSTALCODE']
    except KeyError: pass

    fi_list.append(('', '{}, {} {}'.format(city, state, postalcode)))

    country = ''

    try:
        country = profrs.profile['COUNTRY']
    except KeyError: pass

    fi_list.append(('', country))

    print_kv_list(fi_list)

    print()


def report_cli_server(profrs):
    '''
    Print server information
    '''
    print_header('OFX Server', 2)
    print()

    fi_list = []

    fi_list.append(('OFX Version', profrs.get_version()))

    try:
        val = profrs.signon['FID']
        fi_list.append(('FID', val))
    except KeyError: pass

    try:
        val = profrs.signon['ORG']
        fi_list.append(('ORG', val))
    except KeyError: pass

    try:
        val = profrs.profile['OFXURL']
        fi_list.append(('URL', val))
    except KeyError: pass

    print_kv_list(fi_list)

    print()


def report_cli_capabilities(profrs):
    '''
    Print server capabilities
    '''
    print_header('Capabilities', 2)
    print()

    cap_tree = []

    try:
        v1 = profrs.profile['BANKING']
        cap_tree.append('Banking')
        sub_tree = []
        try:
            if v1['INTRAXFR']:
                sub_tree.append('Intrabank Transfer')
        except KeyError: pass
        cap_tree.append(sub_tree)
    except KeyError: pass

    try:
        v1 = profrs.profile['INVESTMENT']
        cap_tree.append('Investment')
        sub_tree = []
        try:
            if v1['TRANSACTIONS']:
                sub_tree.append('Transactions')
        except KeyError: pass
        try:
            if v1['OPENORDERS']:
                sub_tree.append('Open Orders')
        except KeyError: pass
        try:
            if v1['POSITIONS']:
                sub_tree.append('Positions')
        except KeyError: pass
        try:
            if v1['BALANCES']:
                sub_tree.append('Balances')
        except KeyError: pass
        try:
            if v1['QUOTES']:
                sub_tree.append('Quotes')
        except KeyError: pass
        cap_tree.append(sub_tree)
    except KeyError: pass

    print_tree(cap_tree)

    print()


def report_cli_fingerprint(server):
    '''
    Print info about service framework and software
    '''
    print_header('Fingerprint', 2)
    print()

    fng_list = [
            ('HTTP Server', server.httpserver),
            ('Web Framework', server.webframework)
            ]

    print_kv_list(fng_list)

    print()

    print_header('OFX Software', 3)
    print()

    svr_list = [
            ('Company', server.software['Company']),
            ('Product', server.software['Product']),
            ('Version', server.software['Version'])
            ]

    print_kv_list(svr_list)

    print()


def report_cli_tests(tests):
    '''
    Print info about security tests
    '''
    print_header('Tests', 2)
    print()

    for tres in tests.results:
        title = (tres['Title'], 'PASS' if tres['Passed'] else 'FAIL')
        print_kv_list([title])
        print_list(tres['Messages'], 2)
        print ()


def report_cli(server, profrs, tests):
    '''
    Print human readable report of all results to stdout
    '''
    report_cli_fi(profrs)
    report_cli_server(profrs)
    report_cli_capabilities(profrs)
    report_cli_fingerprint(server)
    report_cli_tests(tests)


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

    requests = [
        testofx.REQ_NAME_GET_ROOT,
        testofx.REQ_NAME_GET_OFX,
        testofx.REQ_NAME_POST_OFX,
        testofx.REQ_NAME_OFX_EMPTY,
        testofx.REQ_NAME_OFX_PROFILE
    ]

    # Display work in progress
    print('{}: version {}'.format(parser.prog, VERSION))
    print()
    print('Start: {}'.format(time.asctime()))
    for req_name in requests:
        print('  Sending {}'.format(req_name))
        send_req(server, req_name)
    print('  Analysing Server')
    profrs = testofx.OFXFile(req_results[testofx.REQ_NAME_OFX_PROFILE].text)
    print('  Fingerprinting')
    server.fingerprint(req_results)
    print('  Running Tests')
    tests = testofx.OFXServerTests(server)
    tests.run_tests(req_results)
    print('End:   {}'.format(time.asctime()))
    time.sleep(1)
    print()

    # Print Report
    report_cli(server, profrs, tests)

if __name__ == '__main__':
    main()
