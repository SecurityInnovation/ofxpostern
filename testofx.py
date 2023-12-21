#!/usr/bin/env python

"""
OFX Test Client
"""

import json
import re
import requests
import time
from urllib.parse import urlparse
from uuid import uuid4
from xmltodict import parse as xmlparse

#
# Defines
#
USER_AGENT   = 'InetClntApp/3.0'
CONTENT_TYPE = 'application/x-ofx'

HDR_OFXHEADER   = 'OFXHEADER'
HDR_DATA        = 'DATA'
HDR_VERSION     = 'VERSION'
HDR_SECURITY    = 'SECURITY'
HDR_ENCODING    = 'ENCODING'
HDR_CHARSET     = 'CHARSET'
HDR_COMPRESSION = 'COMPRESSION'
HDR_OLDFILEUID  = 'OLDFILEUID'
HDR_NEWFILEUID  = 'NEWFILEUID'

HDR_FIELDS_V1 = [HDR_OFXHEADER, HDR_DATA, HDR_VERSION, HDR_SECURITY,
        HDR_ENCODING, HDR_CHARSET, HDR_COMPRESSION, HDR_OLDFILEUID,
        HDR_NEWFILEUID]

HDR_FIELDS_V2 = [HDR_OFXHEADER, HDR_VERSION, HDR_SECURITY, HDR_OLDFILEUID,
        HDR_NEWFILEUID]

OFX_HEADER_100 = \
'''OFXHEADER:100
DATA:OFXSGML
VERSION:{version}
SECURITY:NONE
ENCODING:USASCII
CHARSET:1252
COMPRESSION:NONE
OLDFILEUID:NONE
NEWFILEUID:NONE
'''

OFX_HEADER_200 = \
'''<?xml version="1.0" encoding="UTF-8" standalone="no"?>
<?OFX OFXHEADER="200" VERSION="{version}" SECURITY="NONE" OLDFILEUID="NONE"
NEWFILEUID="NONE"?>
'''

REQ_NAME_GET_ROOT     = 'GET /'
REQ_NAME_GET_OFX      = 'GET OFX Path'
REQ_NAME_POST_OFX     = 'POST OFX Path'
REQ_NAME_OFX_EMPTY    = 'OFX Empty'
REQ_NAME_OFX_PROFILE  = 'OFX PROFILE'
REQ_NAME_OFX_ACCTINFO = 'OFX ACCTINFO'

REQ_NAMES = [
    REQ_NAME_GET_ROOT,
    REQ_NAME_GET_OFX,
    REQ_NAME_POST_OFX,
    REQ_NAME_OFX_EMPTY,
    REQ_NAME_OFX_PROFILE,
    REQ_NAME_OFX_ACCTINFO
]

REQ_METHODS = {
    REQ_NAME_GET_ROOT:     'GET',
    REQ_NAME_GET_OFX:      'GET',
    REQ_NAME_POST_OFX:     'POST',
    REQ_NAME_OFX_EMPTY:    'POST',
    REQ_NAME_OFX_PROFILE:  'POST',
    REQ_NAME_OFX_ACCTINFO: 'POST'
}

#
# Helper Functions
#

def print_http_response(res):
    print("===Request Headers===")
    print(dict(res.request.headers))
    print("===Request Body===")
    print(res.request.body)
    print("=== Response Status ===")
    print(res.status_code)
    print("=== Response Headers ===")
    print(dict(res.headers))
    print("=== Response Body ===")
    print(res.text)

#
# Public Functions
#

def dt_now():
    # Example: 20170616141327.123[-7:MST]
    return time.strftime("%Y%m%d%H%M%S.123[-7:MST]", time.localtime())


def uid():
    # Example: C1B7C870-7CB2-1000-BD91-E1E23E560026
    return str(uuid4()).upper()


def is_ofx_response(resp_body):
    ret = False

    # Version 1 Header
    if resp_body.startswith('OFXHEADER'):
        ret = True

    # Version 2 Header
    if resp_body.find('<?OFX OFXHEADER') != -1:
        ret = True

    return ret


class OFXServerInstance():
    '''
    Representation of an OFX server
    '''

    httpserver = ''
    webframework = ''
    software = dict([
        ('Company', ''),
        ('Product', ''),
        ('Version', '')
        ])
    serviceprovider = ''
    tls = dict()

    def __init__(self, ofxurl, fid, org):
        self.ofxurl = ofxurl
        self.fid = fid if fid else ''
        self.org = org if org else ''

    def _extract_http_header(self, res, header, field, exclude, nooverwrite):
        '''
        Find and store header in HTTP response.

        nooverwrite: list[str] - set if nothing, but don't change exsiting
                                    entry with these values
        '''
        val = None
        try:
            val = res.headers[header]
        except KeyError:
            return

        # Skip if header value is in exclusion list
        if val in exclude:
            return

        cur_val = getattr(self, field)
        # Skip if we've already recorded the same header value
        if cur_val == val:
            return

        # Store the header value in the ServerInstance
        if cur_val == '':
            setattr(self, field, val)
        else:
            if val in nooverwrite:
                return
            else:
                setattr(self, field, val)

    def _fingerprint_httpserver(self, req_results):

        def _check_resp_body(res):
            html = res.text
            if html:
                # Quick and dirty regex of <title> tag
                prog = re.compile('<title>(.*)</title>')
                match = prog.search(html)
                if match:
                    title = match.group(1)
                    if title == 'IIS Windows Server':
                        if self.httpserver == '':
                            self.httpserver = 'Microsoft-IIS/8.5'
                    elif title == 'APACHE OFX APP':
                        if self.httpserver == '':
                            self.httpserver = 'Apache/2.2.23'
                    elif title == 'IBM HTTP Server 8.5':
                        if self.httpserver == '':
                            self.httpserver = 'IBM HTTP Server/8.5'
                    elif title.startswith('Apache Tomcat/'):
                        if self.httpserver in ['', 'Apache', 'Apache-Coyote/1.1']:
                            # Removing trailing " - Error Report"
                            self.httpserver = title[0:-15]
                    elif title.startswith('VMware vFabric tc Runtime'):
                        if self.httpserver == '':
                            # Removing trailing " - Error Report"
                            self.httpserver = title[0:-15]
                    elif title.startswith('JBoss'):
                        if self.httpserver in ['', 'Apache', 'Apache-Coyote/1.1']:
                            # Removing trailing " - Error Report"
                            self.httpserver = title[0:-15]
                    elif title.startswith('JBWEB'):
                        if self.httpserver in ['', 'Apache', 'Apache-Coyote/1.1']:
                            self.httpserver = 'JBoss'

        # Extract OFX "Server" header from OFX requests
        # The HTTP server on the root of the path can be different
        exclude = ['', 'not_available', 'Unspecified']
        nooverwrite = [
                'Apache-Coyote/1.1',
                'Apache',
                'USAA-Service',
                'USAA-Integrity'
                ]

        for req_name in [
                REQ_NAME_OFX_PROFILE,
                REQ_NAME_OFX_EMPTY,
                REQ_NAME_POST_OFX
                ]:
            res = req_results[req_name]
            self._extract_http_header(
                    res,
                    'Server',
                    'httpserver',
                    exclude,
                    nooverwrite)

        # Extract Server out of error body
        for req_name in [
                REQ_NAME_POST_OFX,
                REQ_NAME_GET_OFX,
                REQ_NAME_GET_ROOT
                ]:

            res = req_results[req_name]
            _check_resp_body(res)

    def _fingerprint_webframework(self, req_results):

        def _check_resp_body(res):
            body = res.text
            if body:
                first_line = body.splitlines()[0]
                if first_line.startswith('Error 404: SRVE0190E:'):
                    if self.webframework == '':
                        self.webframework = 'WebSphere'

        # Extract Web Framework from successful OFX requests
        # The web framework on the root of the path can be different
        exclude = ['DI - An Intuit Company']
        for req_name in [
                REQ_NAME_OFX_PROFILE
                ]:
            res = req_results[req_name]
            self._extract_http_header(
                    res,
                    'X-Powered-By',
                    'webframework',
                    exclude,
                    [])

            if self.webframework == 'ASP.NET':
                # Check for extra ASP.NET version headers
                val = None
                try:
                    val = res.headers['X-AspNet-Version']
                except KeyError:
                    continue
                self.webframework += '/{}'.format(val)

        # Extract framework out of error body
        for req_name in [
                REQ_NAME_GET_ROOT
                ]:

            res = req_results[req_name]
            _check_resp_body(res)

    def _fingerprint_software(self, req_results):

        # Determine software based off URL path
        # URL Path: Company, Product
        path_map = {
            '/cmr/cmr.ofx': ('Enterprise Engineering','EnterpriseFTX'),
            '/ofx/servlet/Teller': ('Finastra','Cavion'),
            '/ofx/OFXServlet': ('FIS','Metavante'),
            '/piles/ofx.pile/': ('First Data Corporation','FundsXPress'),
            '/scripts/serverext.dll': ('Fiserv', 'Corillian'),
            '/OROFX16Listener': ('Fiserv',''),
            '/ofx/process.ofx': ('Fiserv','Corillian'),
            '/eftxweb/access.ofx': ('Enterprise Engineering','EnterpriseFTX',),
            '/scripts/isaofx.dll': ('Fiserv', ''),
            '/scripts/serverext.dll': ('Fiserv','Corillian'),
            '/ofx/ofx.dll': ('ULTRADATA Corporation', ''),
            '/ofxserver/ofxsrvr.dll': ('Access Softek', 'OFXServer'),
            '/OFXServer/ofxsrvr.dll': ('Access Softek', 'OFXServer'),
        }

        parsed = urlparse(self.ofxurl)

        try:
            row = path_map[parsed.path]
            self.software['Company'] = row[0]
            self.software['Product'] = row[1]
        except KeyError:
            pass

        # Fingerprint version number
        if self.software['Company'] == 'Enterprise Engineering':
            # EFTX has a splash page with version number by default
            rpat = r'Servlet Version ([0-9.]+)'
            match = re.search(rpat, req_results[REQ_NAME_GET_OFX].text)
            if match:
                self.software['Version'] = 'Servlet {}'.format(match.group(1))

    def _fingerprint_service_provider(self, req_results):

        # Determine which service provider (if any) is hosting this instance
        domain_map = {
            'ofx.netxclient.com': 'Pershing',
            'uat-ofx.netxclient.inautix.com': 'Pershing',
            'www.oasis.cfree.com': 'Fiserv - CheckFree - Oasis'
        }

        sp = ''

        parsed = urlparse(self.ofxurl)

        try:
            sp = domain_map[parsed.netloc]
        except KeyError:
            pass

        # Try the domain map first, fallback to SPNAME
        if sp == '':
            profrs = OFXFile(req_results[REQ_NAME_OFX_PROFILE].text)

            try:
                sp = profrs.profile['SPNAME']
            except KeyError: pass

        self.serviceprovider = sp


    def fingerprint(self, req_results):
        '''
        Determine software and web frameworks running on instance.
        '''
        self._fingerprint_httpserver(req_results)
        self._fingerprint_webframework(req_results)
        self._fingerprint_software(req_results)
        self._fingerprint_service_provider(req_results)

    def get_tls(self):
        try:
            return self.tls['working']
        except KeyError:
            return True

    def set_tls(self, working):
        self.tls['working'] = working


class OFXTestClient():

    _payload_func = {}

    # Whether to print to stdout
    _output = True

    cache = {}

    def __init__(self,
            timeout=(3.2, 27),
            wait=0,
            use_cache=False,
            output=False,
            version='102',
            tls_verify=True,
            proxy_url=None
            ):
        self.timeout = timeout
        self.wait = wait
        self.use_cache = use_cache
        self._output=output
        self.version = version
        self.tls_verify = tls_verify
        self.proxy_url = proxy_url

        if self.version[0] == '1':
            self.ofxheader = OFX_HEADER_100.format(version=self.version)
            self.content_type = 'text/sgml'
        elif self.version[0] == '2':
            self.ofxheader = OFX_HEADER_200.format(version=self.version)
            self.content_type = 'text/xml'
        else:
            raise ValueError(
                    'Unknown OFX version number {}'.format(self.version))

    def call_url_cached(self, url, tls_verify, body, method):
        '''
        return (request.response, boolean) - Response and whether it was
                cached.
        '''

        if method not in ['GET', 'POST']:
            raise ValueError("Method must be 'GET' or 'POST'")

        # Impersonate PFM
        headers = {
                'User-Agent': USER_AGENT,
                }

        if method == 'POST':
            headers['Content-Type'] = CONTENT_TYPE

        # Simple in memory cache to avoid duplicate calls to the same URL.
        try:
            r = self.cache[url]
            return (r, True)
        except KeyError:
            pass

        if self._output: print("{}".format(url))
        try:
            if self.proxy_url:
                s = requests.Session()
                s.proxies = {'http': self.proxy_url, 'https': self.proxy_url}

            if method == 'GET':
                if self.proxy_url:
                    r = s.get(
                            url,
                            headers=headers,
                            timeout=self.timeout,
                            verify=False
                            )
                else:
                    r = requests.get(
                            url,
                            headers=headers,
                            timeout=self.timeout,
                            verify=tls_verify
                            )
            elif method == 'POST':
                if self.proxy_url:
                    r = s.post(
                            url,
                            headers=headers,
                            timeout=self.timeout,
                            verify=False,
                            data=body
                            )
                else:
                    r = requests.post(
                            url,
                            headers=headers,
                            timeout=self.timeout,
                            verify=tls_verify,
                            data=body
                            )
            if self.use_cache:
                self.cache[url] = r
            return (r, False)
        except requests.ConnectionError as ex:
            if self._output: print('\tConnectionError: {}'.format(ex))
            # Set cache, but empty, to avoid further calls this run
            # Still cache connection errors even if use_cache == False
            self.cache[url] = None
        except requests.exceptions.ReadTimeout as ex:
            if self._output: print('\tConnectionError: {}'.format(ex))
            if wait > 0:
                if self._output:
                    print('\tWaiting for {} seconds'.format(self.wait))
                time.sleep(self.wait)

        return (None, False)

    def call_url_interactive(self, ofxurl, tls_verify, payload, method):
        res, was_cached = self.call_url_cached(
                ofxurl,
                tls_verify,
                payload,
                method
                )

        # Connection was completed successfully
        if res is not None:
            print_http_response(res)

    def send_req(self, req_name, si):
        '''
        Send a pre-defined request to the OFX server.
        '''

        res = None

        if req_name == REQ_NAME_GET_ROOT:
            parsed = urlparse(si.ofxurl)
            url = parsed.scheme + '://' + parsed.netloc
            res, was_cached = self.call_url_cached(
                    url,
                    self.tls_verify,
                    self.get_empty_payload(si),
                    REQ_METHODS[req_name]
                    )
        elif req_name == REQ_NAME_GET_OFX:
            res, was_cached = self.call_url_cached(
                    si.ofxurl,
                    self.tls_verify,
                    self.get_empty_payload(si),
                    REQ_METHODS[req_name]
                    )
        elif req_name == REQ_NAME_POST_OFX:
            res, was_cached = self.call_url_cached(
                    si.ofxurl,
                    self.tls_verify,
                    self.get_empty_payload(si),
                    REQ_METHODS[req_name]
                    )
        elif req_name == REQ_NAME_OFX_EMPTY:
            res, was_cached = self.call_url_cached(
                    si.ofxurl,
                    self.tls_verify,
                    self.get_ofx_empty_payload(si),
                    REQ_METHODS[req_name]
                    )
        elif req_name == REQ_NAME_OFX_PROFILE:
            res, was_cached = self.call_url_cached(
                    si.ofxurl,
                    self.tls_verify,
                    self.get_profile_payload(si),
                    REQ_METHODS[req_name]
                    )
        else:
            raise ValueError('Unknown request name: {}'.format(req_name))

        return res

    def _get_signonmsg_anonymous_payload(self, si):

        if self.content_type == 'text/sgml':
            ofx_fi_fmt =  \
'''<FI>
<ORG>{org}
<FID>{fid}
</FI>
'''

            ofx_signon_fmt = \
'''<SIGNONMSGSRQV1>
<SONRQ>
<DTCLIENT>{dt}
<USERID>anonymous00000000000000000000000
<USERPASS>anonymous00000000000000000000000
<GENUSERKEY>N
<LANGUAGE>ENG
{fi}<APPID>QWIN
<APPVER>2700
</SONRQ>
</SIGNONMSGSRQV1>'''

        elif self.content_type == 'text/xml':
            ofx_fi_fmt =  \
'''<FI>
<ORG>{org}</ORG>
<FID>{fid}</FID>
</FI>
'''

            ofx_signon_fmt = \
'''<SIGNONMSGSRQV1>
<SONRQ>
<DTCLIENT>{dt}</DTCLIENT>
<USERID>anonymous00000000000000000000000</USERID>
<USERPASS>anonymous00000000000000000000000</USERPASS>
<GENUSERKEY>N</GENUSERKEY>
<LANGUAGE>ENG</LANGUAGE>
{fi}<APPID>QWIN</APPID>
<APPVER>2700</APPVER>
</SONRQ>
</SIGNONMSGSRQV1>'''

        if si is None:
            fi = ''
        else:
            fi = ofx_fi_fmt.format(
                fid=si.fid,
                org=si.org
                )

        frag = ofx_signon_fmt.format(
                dt=dt_now(),
                fi=fi
                )
        return frag

    def get_empty_payload(self, si):
        return ''

    def get_ofx_empty_payload(self, si):

        ofx_body = \
'''<OFX>
</OFX>
'''
        return "{}{}{}".format(self.ofxheader, '\n', ofx_body)

    def get_profile_payload(self, si):

        if self.content_type == 'text/sgml':
            ofx_body_fmt = \
'''<OFX>
{signonmsg}
<PROFMSGSRQV1>
<PROFTRNRQ>
<TRNUID>{uid}
<PROFRQ>
<CLIENTROUTING>MSGSET
<DTPROFUP>19900101
</PROFRQ>
</PROFTRNRQ>
</PROFMSGSRQV1>
</OFX>
'''

        elif self.content_type == 'text/xml':
            ofx_body_fmt = \
'''<OFX>
{signonmsg}
<PROFMSGSRQV1>
<PROFTRNRQ>
<TRNUID>{uid}</TRNUID>
<PROFRQ>
<CLIENTROUTING>MSGSET</CLIENTROUTING>
<DTPROFUP>19900101</DTPROFUP>
</PROFRQ>
</PROFTRNRQ>
</PROFMSGSRQV1>
</OFX>
'''

        body = ofx_body_fmt.format(
                signonmsg=self._get_signonmsg_anonymous_payload(si),
                uid=uid())
        return "{}{}{}".format(self.ofxheader, '\n', body)

    def get_acctinfo_payload(self, si):
        '''
        ACCTINFO Request payload
        '''

        ofx_body_fmt = \
'''<OFX>
{signonmsg}
<SIGNUPMSGSRQV1>
<ACCTINFOTRNRQ>
<TRNUID>{uid}
<ACCTINFORQ>
<DTACCTUP>19900101
</ACCTINFORQ>
</ACCTINFOTRNRQ>
</SIGNUPMSGSRQV1>
</OFX>
'''

        body = ofx_body_fmt.format(
                signonmsg=self._get_signonmsg_anonymous_payload(si),
                uid=uid())
        return "{}{}{}".format(self.ofxheader, '\n', body)

    def get_invstmtrn_payload(self, si, brokerid, acctid):
        '''
        INVSTMTTRRQ Request payload
        '''

        ofx_body_fmt = \
'''<OFX>
{signonmsg}
<INVSTMTMSGSRQV1>
<INVSTMTTRNRQ>
<TRNUID>{uid}
<INVSTMTRQ>
<INVACCTFROM>
<BROKERID>{broker_id}
<ACCTID>{acct_id}
</INVACCTFROM>
<INCTRAN>
<INCLUDE>Y
</INCTRAN>
<INCOO>Y
<INCPOS>
<INCLUDE>Y
</INCPOS>
<INCBAL>Y
</INVSTMTRQ>
</INVSTMTTRNRQ>
</INVSTMTMSGSRQV1>
</OFX>
'''
        body = ofx_body_fmt.format(
                signonmsg=self._get_signonmsg_anonymous_payload(si),
                uid=uid(),
                broker_id=brokerid,
                acct_id = acctid)

        return "{}{}{}".format(self.ofxheader, '\n', body)


class OFXFile():
    '''
    Read and parse an OFX file.

    This is simplistic parsing of specific fields, mainly the header and PROFRS
    '''

    _file_str = ''
    _v2_dict = {}

    headers = {}
    version = None
    signon = {}
    profile = {}

    def __init__(self, file_str):
        self._file_str = file_str

        self._convert_newlines()
        self._parse_header()

        if self.major_version() == 2:
            self._v2_dict = xmlparse(file_str)

        self._parse_signon()
        self._parse_profile()

    def _convert_newlines(self):
        '''
        Convert from network newlines to platform newlines.

        For now, just blindly Windows to Unix.
        '''

        self._file_str = self._file_str.replace('\r\n', '\n')

    def _parse_header(self):
        # Parse Version 1 Header

        # Example:
        #
        # OFXHEADER:100
        # DATA:OFXSGML
        # VERSION:102
        # SECURITY:NONE
        # ENCODING:USASCII
        # CHARSET:1252
        # COMPRESSION:NONE
        # OLDFILEUID:NONE
        # NEWFILEUID:NONE

        if self._file_str.startswith('OFXHEADER'):
            # Assume well formed and parse based on NEWLINES
            for line in self._file_str.splitlines():
                # End of header
                if line == '' or line.startswith('<OFX>') or len(line) > 13:
                    break
                [k,v] = line.split(':')
                self.headers[k] = v

            try:
                self.version = int(self.headers[HDR_VERSION])
            except KeyError:
                raise ValueError("Parse Error: No version")

        # Parse Version 2 Header

        # Example:
        # <?OFX OFXHEADER="200" VERSION="203" SECURITY="NONE" OLDFILEUID="NONE" NEWFILEUID="NONE"?>

        elif self._file_str.find('<?OFX OFXHEADER') != -1:
            # Python (as of 3.7) has no way to read prolog declarations.
            # https://bugs.python.org/issue24287
            # So don't bother parsing as XML, just use a regex to read the
            # OFX header.

            # TODO: Pull ENCODING out of <?xml> declaration

            rpat = r'<\?OFX OFXHEADER="(?P<OFXHEADER>\d+)" VERSION="(?P<VERSION>\d+)" SECURITY="(?P<SECURITY>\w+)" OLDFILEUID="(?P<OLDFILEUID>\w+)" NEWFILEUID="(?P<NEWFILEUID>\w+)"\?>'

            match = re.search(rpat, self._file_str)
            if not match:
                raise ValueError("Parse Error: Unable to parse V2 header with regex")
            for field in HDR_FIELDS_V2:
                self.headers[field] = match.group(field)

            try:
                self.version = int(self.headers[HDR_VERSION])
                parsed = True
            except KeyError:
                raise ValueError("Parse Error: No version")

        else:
            raise ValueError("Parse Error: Unable to parse header")

    def major_version(self):
        if str(self.version).startswith('1'):
            return 1
        elif str(self.version).startswith('2'):
            return 2

    def find_span_value(self, value, ofx_str=None, casesen=False):
        '''
        Find the span ELEMENT which contains the given value.
        '''

        if not ofx_str: ofx_str = self._file_str

        if self.major_version() == 1:
            rpat = r'<([\w.+]+)>'+value

        elif self.major_version() == 2:
            rpat = r'<(?P<elm>[\w.+]+)>'+value+r'</(?P=elm)>'

        flags = 0 if casesen else re.IGNORECASE
        matches = re.finditer(rpat, ofx_str, flags)

        if matches:
            return [m.group(0) for m in matches]
        else:
            return None

    def _parse_element_block(self, element, ofx_str=None):
        '''
        Read the internal values of a block element including other elements.
        '''
        if not ofx_str: ofx_str = self._file_str

        rpat = r'<'+element+r'>(.*)</'+element+r'>'
        match = re.search(rpat, ofx_str, re.DOTALL)
        if match:
            return match.group(1)
        else:
            return None

    def _parse_element_span(self, element, ofx_str=None):
        '''
        Read the value of a span <ELEMENT> tag
        '''
        if not ofx_str: ofx_str = self._file_str

        rpat = r'<'+element+r'>([^<\n]+)'
        match = re.search(rpat, ofx_str)
        if match:
            return match.group(1)
        else:
            return None

    def _v2_retrieve_element(self, elmpath, etype):
        '''
        Walk a dictionary tree and retrieve values from it.

        tagpath -  ex: 'ofx:signonmsgsrsv1:sonrs:fi:org'
        etype - ex: 'string'
        '''
        val = None
        node = self._v2_dict
        elmlist = elmpath.split(':')

        for elm in elmlist:
            try:
                node = node[elm.upper()]
            except KeyError:
                break
            if elm == elmlist[-1]:
                if etype == 'string':
                    val = node
                if etype == 'bool':
                    if node == 'Y':
                        val = True
                    elif node == 'N':
                        val = False
                    else:
                        raise ValueError('Unknown value for {}: {}'.format(
                            elmpath, val))
                if etype == 'integer':
                    val = int(node)
                elif etype == 'exist':
                    val = True
                break

        return val


    def _path_to_dict(self, path, value):
        '''
        Given a string path, nest dictionaries and set a value.

        path - ex: 'investment:transactions'
        '''

        nodelist = path.split(':')
        node = self.profile

        for name in nodelist:
            try:
                node = node[name]
            except KeyError:
                if name == nodelist[-1] and value is not None:
                    node[name] = value
                else:
                    node[name] = dict()


    def _parse_signon(self):
        '''
        Parse a SIGNON response if one exists
        '''
        if self.major_version() == 1:
            # Confirm a SIGNON response exists
            rpat = r'<SONRS>'

            match = re.search(rpat, self._file_str)
            if not match:
                return

            # Get Server information
            elms = ('ORG', 'FID')
            for elm in elms:
                val = self._parse_element_span(elm)
                if val:
                    self.signon[elm] = val

        elif self.major_version() == 2:
            val = self._v2_retrieve_element(
                    'ofx:signonmsgsrsv1:sonrs:fi:org',
                    'string'
                    )
            if val:
                self.signon['ORG'] = val

            val = self._v2_retrieve_element(
                    'ofx:signonmsgsrsv1:sonrs:fi:fid',
                    'string'
                    )
            if val:
                self.signon['FID'] = val

    def _parse_profile(self):
        '''
        Parse a PROFILE response if one exists
        '''
        if self.major_version() == 1:
            # This is where we'd should start implementing a real SGML parser,
            # but I'm parsing with quick and loose regex as a first pass

            # Confirm that a PROFILE response exists
            profrs = self._parse_element_block('PROFRS')
            if not profrs:
                return

            # Get FI contact information
            elms = ('FINAME', 'ADDR1', 'ADDR2', 'ADDR3', 'CITY',
                    'STATE', 'POSTALCODE', 'COUNTRY', 'EMAIL')

            for elm in elms:
                val = self._parse_element_span(elm, profrs)
                if val:
                    self.profile[elm] = val

            # Get OFX URL
            # Technically this can be different for every message set,
            # in practice it's usually identical to the PROFILE server.
            # However, if it is different, it's usually the same for every
            # other message set besides PROFMSGSET.

            block = self._parse_element_block('SIGNONMSGSET', profrs)
            if block:
                val = self._parse_element_span('URL', block)
                if val:
                    self.profile['OFXURL'] = val
                val = self._parse_element_span('SPNAME', block)
                if val:
                    self.profile['SPNAME'] = val

            # Get FI capabilities
            block = self._parse_element_block('BANKMSGSET', profrs)
            if block:
                self.profile['BANKING'] = dict()
                b2 = self._parse_element_block('XFERPROF', block)
                if b2:
                    self.profile['BANKING']['INTRAXFR'] = True
                b2 = self._parse_element_block('EMAILPROF', block)
                if b2:
                    self.profile['BANKING']['MESSAGES'] = dict()
                    val = self._parse_element_span('CANEMAIL', b2)
                    if val == 'Y':
                        self.profile['BANKING']['MESSAGES']['EMAIL'] = True
                    val = self._parse_element_span('CANNOTIFY', b2)
                    if val == 'Y':
                        self.profile['BANKING']['MESSAGES']['NOTIFY'] = True

            block = self._parse_element_block('INVSTMTMSGSET', profrs)
            if block:
                self.profile['INVESTMENT'] = dict()
                val = self._parse_element_span('TRANDNLD', block)
                if val:
                    self.profile['INVESTMENT']['TRANSACTIONS'] = True
                val = self._parse_element_span('OODNLD', block)
                if val:
                    self.profile['INVESTMENT']['OPENORDERS'] = True
                val = self._parse_element_span('POSDNLD', block)
                if val:
                    self.profile['INVESTMENT']['POSITIONS'] = True
                val = self._parse_element_span('POSDNLD', block)
                if val:
                    self.profile['INVESTMENT']['POSITIONS'] = True
                val = self._parse_element_span('BALDNLD', block)
                if val:
                    self.profile['INVESTMENT']['BALANCES'] = True

            block = self._parse_element_block('SECLISTMSGSET', profrs)
            if block:
                val = self._parse_element_span('SECLISTRQDNLD', block)
                if val:
                    self.profile['INVESTMENT']['QUOTES'] = True

            block = self._parse_element_block('CREDITCARDMSGSET', profrs)
            if block:
                self.profile['CREDITCARD'] = dict()
                val = self._parse_element_span('CLOSINGAVAIL', block)
                if val == 'Y':
                    self.profile['CREDITCARD']['STATEMENT'] = True

            block = self._parse_element_block('BILLPAYMSGSET', profrs)
            if block:
                self.profile['BILLPAY'] = dict()

            block = self._parse_element_block('EMAILMSGSET', profrs)
            if block:
                self.profile['MESSAGING'] = dict()
                val = self._parse_element_span('MAILSUP')
                if val == 'Y':
                    self.profile['MESSAGING']['EMAIL'] = True
                val = self._parse_element_span('GETMIMESUP')
                if val == 'Y':
                    self.profile['MESSAGING']['MIME'] = True

            # Get Password Policy
            block = self._parse_element_block('SIGNONINFO', profrs)
            if block:
                self.profile['AUTHENTICATION'] = dict()
                val = self._parse_element_span('MIN', block)
                if val:
                    self.profile['AUTHENTICATION']['MINPASS'] = int(val)
                val = self._parse_element_span('MAX', block)
                if val:
                    self.profile['AUTHENTICATION']['MAXPASS'] = int(val)
                val = self._parse_element_span('CHARTYPE', block)
                if val:
                    self.profile['AUTHENTICATION']['COMPLEXITY'] = val
                val = self._parse_element_span('CASESEN', block)
                if val:
                    if val == 'Y':
                        self.profile['AUTHENTICATION']['CASESEN'] = True
                    elif val == 'N':
                        self.profile['AUTHENTICATION']['CASESEN'] = False
                    else:
                        raise ValueError(
                            'Unknown value for CASESEN: {}'.format(va))
                val = self._parse_element_span('SPECIAL', block)
                if val:
                    if val == 'Y':
                        self.profile['AUTHENTICATION']['SPECIAL'] = True
                    elif val == 'N':
                        self.profile['AUTHENTICATION']['SPECIAL'] = False
                    else:
                        raise ValueError(
                            'Unknown value for SPECIAL: {}'.format(va))
                val = self._parse_element_span('CLIENTUIDREQ')
                if val == 'Y':
                    try:
                        tmp = self.profile['AUTHENTICATION']['MFA']
                    except KeyError:
                        self.profile['AUTHENTICATION']['MFA'] = dict()
                    self.profile['AUTHENTICATION']['MFA']['CLIENTUID'] = True

        elif self.major_version() == 2:
            # Confirm that a PROFILE response exists
            if not self._v2_retrieve_element(
                    'ofx:profmsgsrsv1:proftrnrs:profrs',
                    'exist'):
                return

            # OFX Path, Retrieve Type, Profile Object Path
            profile_elms = [
                # Get FI contact information
                ('ofx:profmsgsrsv1:proftrnrs:profrs:finame',
                 'string',
                 'FINAME'),
                ('ofx:profmsgsrsv1:proftrnrs:profrs:addr1',
                 'string',
                 'ADDR1'),
                ('ofx:profmsgsrsv1:proftrnrs:profrs:addr2',
                 'string',
                 'ADDR2'),
                ('ofx:profmsgsrsv1:proftrnrs:profrs:addr3',
                 'string',
                 'ADDR3'),
                ('ofx:profmsgsrsv1:proftrnrs:profrs:city',
                 'string',
                 'CITY'),
                ('ofx:profmsgsrsv1:proftrnrs:profrs:state',
                 'string',
                 'STATE'),
                ('ofx:profmsgsrsv1:proftrnrs:profrs:postalcode',
                 'string',
                 'POSTALCODE'),
                ('ofx:profmsgsrsv1:proftrnrs:profrs:country',
                 'string',
                 'COUNTRY'),
                ('ofx:profmsgsrsv1:proftrnrs:profrs:email',
                 'string',
                 'EMAIL'),

                # Get OFX URL
                # Technically this can be different for every message set,
                # in practice it's usually identical to the PROFILE server.
                # However, if it is different, it's usually the same for every
                # other message set besides PROFMSGSET.

                ('ofx:profmsgsrsv1:proftrnrs:profrs:msgsetlist:signonmsgset:signonmsgsetv1:msgsetcore:url',
                 'string',
                 'OFXURL'),

                # Get FI capabilities

                # Investments
                ('ofx:profmsgsrsv1:proftrnrs:profrs:msgsetlist:invstmtmsgset',
                 'exist',
                 'INVESTMENT'),
                ('ofx:profmsgsrsv1:proftrnrs:profrs:msgsetlist:invstmtmsgset:invstmtmsgsetv1:trandnld',
                 'bool',
                 'INVESTMENT:TRANSACTIONS'),
                ('ofx:profmsgsrsv1:proftrnrs:profrs:msgsetlist:invstmtmsgset:invstmtmsgsetv1:oodnld',
                 'bool',
                 'INVESTMENT:OPENORDERS'),
                ('ofx:profmsgsrsv1:proftrnrs:profrs:msgsetlist:invstmtmsgset:invstmtmsgsetv1:posdnld',
                 'bool',
                 'INVESTMENT:POSITIONS'),
                ('ofx:profmsgsrsv1:proftrnrs:profrs:msgsetlist:invstmtmsgset:invstmtmsgsetv1:baldnld',
                 'bool',
                 'INVESTMENT:BALANCES'),
                ('ofx:profmsgsrsv1:proftrnrs:profrs:msgsetlist:invstmtmsgset:invstmtmsgsetv1:inv401kdnld',
                 'bool',
                 'INVESTMENT:401K'),
                ('ofx:profmsgsrsv1:proftrnrs:profrs:msgsetlist:seclistmsgset:seclistmsgsetv1:seclistrqdnld',
                 'bool',
                 'INVESTMENT:QUOTES'),

                # Taxes
                ('ofx:profmsgsrsv1:proftrnrs:profrs:msgsetlist:tax1099msgset:tax1099msgsetv1',
                 'exist',
                 'TAXES'),
                ('ofx:profmsgsrsv1:proftrnrs:profrs:msgsetlist:tax1099msgset:tax1099msgsetv1:tax1099dnld',
                 'bool',
                 'TAXES:1099'),
                ('ofx:profmsgsrsv1:proftrnrs:profrs:msgsetlist:tax1099msgset:tax1099msgsetv1:extd1099b',
                 'bool',
                 'TAXES:1099B'),
                # TODO: There could be multiple years returned.
                ('ofx:profmsgsrsv1:proftrnrs:profrs:msgsetlist:tax1099msgset:tax1099msgsetv1:taxyearsupported',
                 'string',
                 'TAXES:YEARS'),

                # Get Password Policy
                ('ofx:profmsgsrsv1:proftrnrs:profrs:signoninfolist:signoninfo',
                 'exist',
                 'AUTHENTICATION'),
                ('ofx:profmsgsrsv1:proftrnrs:profrs:signoninfolist:signoninfo:min',
                 'integer',
                 'AUTHENTICATION:MINPASS'),
                ('ofx:profmsgsrsv1:proftrnrs:profrs:signoninfolist:signoninfo:max',
                 'integer',
                 'AUTHENTICATION:MAXPASS'),
                ('ofx:profmsgsrsv1:proftrnrs:profrs:signoninfolist:signoninfo:chartype',
                 'string',
                 'AUTHENTICATION:COMPLEXITY'),
                ('ofx:profmsgsrsv1:proftrnrs:profrs:signoninfolist:signoninfo:casesen',
                 'bool',
                 'AUTHENTICATION:CASESEN'),
                ('ofx:profmsgsrsv1:proftrnrs:profrs:signoninfolist:signoninfo:special',
                 'bool',
                 'AUTHENTICATION:SPECIAL'),
                ('ofx:profmsgsrsv1:proftrnrs:profrs:signoninfolist:signoninfo:clientuidreq',
                 'bool',
                 'AUTHENTICATION:MFA:CLIENTUID'),
            ]

            for elm in profile_elms:
                val = self._v2_retrieve_element(elm[0], elm[1])
                if val:
                    # We set None to mean create a sub-dictionary
                    val = val if elm[1] != 'exist' else None
                    self._path_to_dict(elm[2], val)

    def get_version(self):
        '''
        Return string representation of OFX document version number.
        '''
        if self.version:
            return '.'.join(list(str(self.version)))
        else:
            return ''


class OFXServerTests():
    '''
    Run collection of OFX tests
    '''

    results = []
    profrs = None

    def __init__(self, server):
        self.si = server

    def run_tests(self, req_results):
        messages = []

        try:
            self.profrs = OFXFile(req_results[REQ_NAME_OFX_PROFILE].text)
        except ValueError:
            msg = 'Cannot read OFX PROFILE, some tests will not be run.'
            messages.append(msg)

        self.test_tls(self.si)
        self.test_content_type(req_results)
        self.test_server_diclosure(self.si)

        if self.profrs:
            self.test_mfa(req_results)
            self.test_password_policy(req_results)
            self.test_user_disclosure(req_results)

        self.test_null_values(req_results)
        self.test_500_http_response(req_results)
        self.test_internal_ip(req_results)

        return messages

    def test_tls(self, server):
        title = 'Transport Layer Security (TLS)'
        passed = True
        messages = []

        if not server.get_tls():
            passed = False
            msg = 'Unable to securely connect to the server over TLS'
            messages.append(msg)

        self.results.append({
            'Title': title,
            'Passed': passed,
            'Messages': messages
            })

    def test_mfa(self, req_results):
        title = 'Multi-Factor Authentication'
        passed = True
        messages = []

        if self.profrs.major_version() == 1:
            requirement = 103
        elif self.profrs.major_version() == 2:
            requirement = 203

        if self.profrs.version and self.profrs.version < requirement:
            passed = False
            msg = 'OFX protocol version ({}) does not support MFA'.format(
                    self.profrs.get_version())
            messages.append(msg)

        self.results.append({
            'Title': title,
            'Passed': passed,
            'Messages': messages
            })

    def test_password_policy(self, req_results):
        title = 'Password Policy'
        passed = True
        messages = []

        minpass = None
        requirement = 8
        try:
            minpass = self.profrs.profile['AUTHENTICATION']['MINPASS']
        except KeyError:
            pass
        if minpass and minpass < requirement:
            passed = False
            msg = 'Minimum password length ({}) is less than recommended ({})'.format(
                    minpass, requirement)
            messages.append(msg)

        self.results.append({
            'Title': title,
            'Passed': passed,
            'Messages': messages
            })

    def test_user_disclosure(self, req_results):
        title = 'Username Disclosure'
        passed = True
        messages = []

        common_aliases_exact = ['test', 'members', 'it', 'email', 'assist']

        common_aliases_in = ['info', 'support', 'service', 'reply', 'online',
        'help', 'webmaster', 'quicken', 'question', 'postmaster', 'client',
        'internet', 'bank', 'commerce', 'business', 'deposit', 'customer',
        'feedback', 'central', 'center', 'bookkeep', 'ask', 'virtual',
        'management', 'operation', 'contact', 'inbox', 'staff', 'investor']

        try:
            email = self.profrs.profile['EMAIL']
        except:
            email = ''

        # 1) Check that it has an @ sign
        # 2) Lowercase
        # 3) Check if common_aliases_exact doesn't match
        # 4) Check common_aliases_in is not in it
        # 5) Check if name == domain
        # 6) Check if it has a '.' or '_'
        #     a) Likely a username
        #     b) Mark as Error
        # 7) Else:
        #     a) Likely a username
        #     b) Mark as Warning

        if '@' in email:
            email_lc = email.lower()
            name = email_lc.split('@')[0]
            domain = email_lc.split('@')[1].split('.')[-2]

            if name in common_aliases_exact:
                pass
            elif any(substring in name for substring in common_aliases_in):
                pass
            elif name.startswith(domain):
                pass
            else:
                passed = False
                if '.' in name or '_' in name:
                    msg = 'Email address is likely a username: {}'.format(email)
                else:
                    msg = 'Email address may be a username: {}'.format(
                            email)
                messages.append(msg)

        self.results.append({
            'Title': title,
            'Passed': passed,
            'Messages': messages
            })

    def test_server_diclosure(self, server):
        title = 'Web Server Disclosure'
        passed = True
        messages = []

        # Because our current fingerprinting only uses server headers and
        # banners, we can assume if we've identified one, then it's a simple
        # information disclosure.

        # Only error on servers that diclose their version number

        s = server.httpserver
        if s != '' and any(str(num) in s for num in range(10)):
            passed = False
            msg = 'Web server discloses type and version: {}'.format(s)
            messages.append(msg)

        f = server.webframework
        if f != '' and any(str(num) in s for num in range(10)):
            passed = False
            msg = 'Web framework discloses type and version: {}'.format(f)
            messages.append(msg)

        self.results.append({
            'Title': title,
            'Passed': passed,
            'Messages': messages
            })

    def test_content_type(self, req_results):
        title = 'Incorrect Content-Type'
        passed = True
        messages = []

        for req_name in [
            REQ_NAME_POST_OFX,
            REQ_NAME_OFX_EMPTY,
            REQ_NAME_OFX_PROFILE]:

            # TODO: Check for OFX header
            if req_results[req_name].status_code == 400:
                continue

            try:
                ctype = req_results[req_name].headers['Content-Type'].split(';')[0]
            except KeyError:
                # TODO: test if content-length is 0, if not raise an error
                continue

            if ctype != CONTENT_TYPE:
                msg = '{}: Incorrect Content-Type in OFX response: {}'.format(
                        req_name, ctype)
                messages.append(msg)
                passed = False

        self.results.append({
            'Title': title,
            'Passed': passed, 'Messages': messages
            })

    def test_null_values(self, req_results):
        title = 'Null Values Returned'
        passed = True
        messages = []

        for req_name in [
            REQ_NAME_POST_OFX,
            REQ_NAME_OFX_EMPTY,
            REQ_NAME_OFX_PROFILE]:

            try:
                resp = OFXFile(req_results[req_name].text)
                matches = resp.find_span_value('null')
                for m in matches:
                    msg = '{}: null value returned: {}'.format(req_name, m)
                    messages.append(msg)
                    passed = False
            except ValueError:
                # Ignore if we didn't get an OFX reponse back
                pass

        self.results.append({
            'Title': title,
            'Passed': passed,
            'Messages': messages
            })

    def test_500_http_response(self, req_results):
        title = 'Internal Server Errors'
        passed = True
        messages = []

        # We'll ignore most 500 errors. Only complain about information
        # disclosure.

        for req_name in [
            REQ_NAME_POST_OFX,
            REQ_NAME_OFX_EMPTY,
            REQ_NAME_OFX_PROFILE]:

            if req_results[req_name].status_code != 500:
                continue

            body = req_results[req_name].text

            # Check for known bad return messages
            if body.startswith('Error 500:'):
                msg = '{}: Verbose error message: {}'.format(req_name,
                        body.splitlines()[0])
                messages.append(msg)
            elif req_name in [
                REQ_NAME_POST_OFX,
                REQ_NAME_OFX_EMPTY
                ]:
                msg = '{}: Unhandled exception parsing invalid input'.format(
                        req_name)
                messages.append(msg)
            passed = False

        self.results.append({
            'Title': title,
            'Passed': passed,
            'Messages': messages
            })

    def test_internal_ip(self, req_results):
        title = 'Internal IP Address Disclosure'
        passed = True
        messages = []

        for req_name in [
            REQ_NAME_GET_ROOT,
            REQ_NAME_GET_OFX,
            REQ_NAME_POST_OFX,
            REQ_NAME_OFX_EMPTY,
            REQ_NAME_OFX_PROFILE]:

            body = req_results[req_name].text

            if len(body) == 0:
                continue

            # regex for known internal IP addresses
            rpat = r'http[s]?://((localhost)|(127\.0\.0\.[0-9]{1,3})|(10\.[0-9]{1,3}\.[0-9]{1,3}\.[0-9]{1,3})):?[0-9]{0,5}/?[\w\-/]*'

            matches = re.finditer(rpat, body)

            if matches:
                for m in [m.group(0) for m in matches]:
                    msg = '{}: Internal IP returned: {}'.format(req_name, m)
                    messages.append(msg)
                    passed = False

        self.results.append({
            'Title': title,
            'Passed': passed,
            'Messages': messages
            })

