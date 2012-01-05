#!/usr/bin/env python
#
# Test suite for testing a market place download protocol entry point.
#
# This file is provided under the MIT license, see the file LICENSE for the
# exact licensing terms.
#
# Copyright (c) 2011-2012, Red Hat Inc.

import sys
import hmac
import hashlib
import time
import logging
import httplib as http

from sys import stdout, stderr
from httplib import HTTPConnection, HTTPSConnection
from urllib import urlencode, quote
from urlparse import urlsplit
from optparse import OptionParser


required_fields = ('greeting', 'first_name', 'last_name', 'address1',
    'city', 'country', 'postal_code', 'phone_number', 'email')

optional_fields = ('company', 'title', 'address2', 'address3',
    'state', 'fax_number', 'eula', 'eula_accepted')

example_data = {
    'greeting': 'Mr.',
    'first_name': 'Mark',
    'last_name': 'Place',
    'address1': '100 Commerce Blvd',
    'address2': 'Second Floor',
    'address3': 'Suite 300',
    'postal_code': '10001',
    'city': 'New York',
    'state': 'NY',
    'country': 'United States',
    'phone_number': '212 123-4567',
    'fax_number': '212 234-5678',
    'email': 'mplace@example.com',
    'eula': 'This is a EULA',
    'eula_accepted': 'true'
}

def get_example_data(fields):
    """Return a set of example data."""
    data = {}
    for key in fields:
        data[key] = example_data[key]
    return data

def add_signature(url, fields, secret, expiry=1800):
    """Add a signature and expiration to a field set."""
    parsed = urlsplit(url)
    fields['expires'] = str(int(time.time()) + expiry)
    s = 'POST\n'
    s += '%s\n' % parsed.netloc.lower()
    s += '%s\n' % (parsed.path or '/')
    qs = []
    for key in fields:
        value = quote(fields[key].encode('utf-8'), safe='~')
        qs.append('%s=%s' % (key, value))
    qs = '&'.join(sorted(qs))
    s += qs
    h = hmac.new(secret, s, hashlib.sha256)
    sig = h.digest().encode('base64').replace('\n', '').replace(' ', '')
    fields['signature'] = sig

def encode_fields(fields, charset=None):
    """Serialize a set of fields as application/x-www-form-urlencoded."""
    if charset is not None:
        fields = dict(((key, fields[key].encode(charset)) for key in fields))
    encoded = urlencode(fields)
    return encoded

def open_connection(url):
    """Open a HTTP/HTTPSConnection."""
    parsed = urlsplit(url)
    if parsed.scheme == 'https':
        cls = HTTPSConnection
    else:
        cls = HTTPConnection
    if ':' in parsed.netloc:
        host, port = parsed.netloc.split(':')
        port = int(port)
    elif parsed.scheme == 'https':
        host = parsed.netloc
        port = http.HTTPS_PORT
    else:
        host = parsed.netloc
        port = http.HTTP_PORT
    logging.debug('opening a HTTP connection to %s:%d' % (host, port))
    conn = cls(host, port)
    return conn

def get_redirected_url(url, method='GET'):
    parsed = urlsplit(url)
    conn = open_connection(url)
    headers = {}
    body = ''
    headers['Content-Length'] = str(len(body))
    headers['Accept'] = 'application/octet-stream'
    logging.debug('request: method = %s, url = %s'
                  % (method, url))
    conn.request(method, url, headers=headers, body=body)
    resp = conn.getresponse()
    logging.debug('response: status = %s, body = %s bytes, Content-Type = %s'
                  % (resp.status, resp.getheader('Content-Length', 'N/A'),
                     resp.getheader('Content-Type', 'N/A')))
    return resp

def make_request(url, fields, method='POST', charset='utf-8'):
    """Make a HTTP request and return the HTTPResponse object."""
    parsed = urlsplit(url)
    conn = open_connection(url)
    headers = {}
    if fields:
        headers['Content-Type'] = 'application/x-www-form-urlencoded'
        if charset is not None:
            headers['Content-Type'] += '; charset=%s' % charset
        body = encode_fields(fields, charset)
    else:
        body = ''
    headers['Content-Length'] = str(len(body))
    logging.debug('request: method = %s, body = %s bytes, Content-Type = %s'
                  % (method, len(body), headers.get('Content-Type', 'N/A')))
    conn.request(method, parsed.path, headers=headers, body=body)
    resp = conn.getresponse()
    logging.debug('response: status = %s, body = %s bytes, Content-Type = %s'
                  % (resp.status, resp.getheader('Content-Length', 'N/A'),
                     resp.getheader('Content-Type', 'N/A')))
    return resp


def test_download(url, filename, secret, download=False):
    """Try a download that should succeed."""
    fields = get_example_data(required_fields)
    fields['file'] = filename
    add_signature(url, fields, secret)
    stdout.write('Making an authenticated download request ... ')
    r = make_request(url, fields)
    stdout.write('DONE\n')
    if r.status == 303:
      stdout.write('  - Redirected (303) to Location = %s\n' % r.getheader('Location'))
      stdout.write('  - Trying this URL via HTTP GET ... ')
      r = get_redirected_url(r.getheader('Location'))
      stdout.write('DONE\n')
    stdout.write('Examining response ...\n')
    errors = 0
    if r.status == http.OK:
        stdout.write('  - response code = 200: OK\n')
    else:
        stdout.write('ERROR: response code = %s (expecting: 200)\n' % r.status)
        errors += 1
    ctype = r.getheader('Content-Type')
    if ctype == 'application/octet-stream':
        stdout.write('  - Content-Type = application/octet-stream: OK\n')
    else:
        stdout.write('ERROR: Content-Type = %s (expecting: application/octet-stream)\n' % ctype)
        errors += 1
    clen = r.getheader('Content-Length')
    if clen is not None:
        stdout.write('  - Content-Length = %s: OK\n' % clen)
        stdout.write('  - server NOT using chunked, but this is OK\n')
    elif r.getheader('Transfer-Encoding') == 'chunked':
        stdout.write('  - server is using chunked encoding, VERY GOOD\n')
    else:
        stdout.write('ERROR: content-length NOT set, and NOT using chunked either\n')
        errors += 1
    if r.getheader('Accept-Ranges') == 'bytes':
        stdout.write('  - server accepts byte ranges, VERY GOOD\n')
    else:
        stdout.write('  - server does NOT accept byte ranges, but this is OK\n')
    stdout.write('\n')
    if download:
        stdout.write('Downloading \'%s\' ... ' % filename)
        stdout.flush()
        fout = file(filename, 'w')
        while True:
            buf = r.read(4096)
            if not buf:
                break
            fout.write(buf)
        stdout.write('DONE\n')
    r.close()
    return errors


def test_unauthenticated_downloads(url, filename):
    """Test if the implementation accepts unauthenticated downloads."""
    fields = get_example_data(required_fields)
    fields['file'] = filename
    stdout.write('Making an unauthenticated download request ... ')
    r = make_request(url, fields)
    stdout.write('DONE\n')
    stdout.write('Examining response ...\n')
    stdout.write('  - response code = %s\n' % r.status)
    if r.status == http.OK:
        stdout.write('WARNING: this implementation accepts unauthenticated requests\n')
        stdout.write('WARNING: this may or not be OK\n')
    else:
        stdout.write('This implementation does NOT accept unauthenticated requests: OK\n')
    stdout.write('\n')


parser = OptionParser(usage='%prog [OPTIONS]... <url> <filename> <secret>')
parser.add_option('-s', '--save-file', help='save to local file',
                  action='store_true', dest='download')
parser.add_option('-d', '--debug', help='enable debugging', action='store_true')

opts, args = parser.parse_args()
if len(args) != 3:
    parser.error('expecting <url>, <filename> and <secret> arguments')
url, filename, secret = args

if opts.debug:
    level = logging.DEBUG
else:
    level = logging.INFO
format = '%(asctime)s %(levelname)s %(message)s'
logging.basicConfig(format=format, level=level)

stdout.write('Market Place Download Protocol v1.0 test client\n')
stdout.write('Testing the entry point at: %s\n\n' % url)

errors = test_download(url, filename, secret, download=opts.download)
if errors > 0:
    stdout.write('Encountered %d errors, this implementation is NOT compliant\n'
                 % errors)
    sys.exit(1)

stdout.write('No errors encountered, implementation is COMPLIANT\n')
stdout.write('Now doing some other tests, which do not impact compliance however\n\n')

test_unauthenticated_downloads(url, filename)
