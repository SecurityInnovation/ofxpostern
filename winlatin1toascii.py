#!/usr/bin/env python3

'''
Script to convert Windows Latin 1 characters to ASCII equivalent

See: http://jkorpela.fi/www/windows-chars.html
'''

import os
import sys

#
# Defines
#

#
# Globals
#

#
# Helper Functions
#

def usage():
    '''
    Print usage statement.
    '''
    cmd = os.path.basename(sys.argv[0])
    indent = ' ' * 4

    print('Usage:')
    print('{}{} <filename>'.format(indent * 1, cmd))
    print('{}Write to stdout file with Windows Latin 1 characters converted'.format(indent * 2, cmd))

#
# Core Logic
#

def convert(buf):
#    import ipdb; ipdb.set_trace()
    out = bytearray()
    for b in buf:
        if b == 0x92: out.append(ord("'"))
        elif b == 0x93: out.append(ord('"'))
        elif b == 0x94: out.append(ord('"'))
        elif b == 0x96: out.append(ord('-'))
        elif b == 0x97: out.append(ord('-'))
        elif b == 0xA0: continue
        else: out.append(b)

    return out.decode('ascii')


def main(args):

    if len(args) != 1:
        usage()
        sys.exit(1)

    with open(args[0], 'rb') as in_file:
        buf = convert(in_file.read())
        print(buf, end='')


if __name__ == '__main__':

    try:
        main(sys.argv[1:])
    except KeyboardInterrupt:
        pass
