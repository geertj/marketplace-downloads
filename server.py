#!/usr/bin/env python
#
# Example server that implements the Red Hat Market Place download protocol.
# By default, it will listen on localhost port 8080 and will serve any file
# from the current directory without authentication.
#
# This file is provided under the MIT license, see the file LICENSE for the
# exact licensing terms.
#
# Copyright (c) 2011, Red Hat Inc.

import hmac
import stat
import time
import os.path
import hashlib
import logging
import optparse
import urlparse
import httplib as http

from wsgiref.simple_server import make_server


class WSGIApp(object):
    
    def simple_response(self, code, headers=None, body=None):
        status = '%d %s' % (code, http.responses[code])
        if headers is None:
            headers = []
        if body is None:
            body = ''
        headers.append(('Content-Length', str(len(body))))
        self.start_response(status, headers)
        return [body]

    def _serve_file(self, fin):
        while True:
            buf = fin.read(4096)
            yield buf
            if not buf:
                break
        fin.close()

    def serve_file(self, fname, size=None):
        fin = file(fname)
        headers = []
        headers.append(('Content-Type', 'application/octet-stream'))
        if size is None:
            fin.seek(0, 2); size = fin.tell(); fin.seek(0)
        headers.append(('Content-Length', str(size)))
        self.start_response('200 Found', headers)
        return self._serve_file(fin)

    def __call__(self, environ, start_response):
        """Simple download app."""
        self.environ = environ
        self.start_response = start_response
        return self.handler(environ, start_response)


class DownloadApp(WSGIApp):

    required_fields = ('greeting', 'first_name', 'last_name', 'address1',
        'city', 'country', 'postal_code', 'phone_number', 'email', 'file')

    optional_fields = ('company', 'title', 'address2', 'address3',
        'state', 'fax_number', 'eula', 'eula_accepted', 'expires', 'signature')
    

    def __init__(self, directory, url, check, secret):
        self.directory = directory
        self.url = url
        self.check = check
        self.secret = secret
        self.logger = logging.getLogger('DownloadApp')

    def check_signature(self, fields):
        s = ''.join(['%s=%s\n' % (f, fields[f]) for f in sorted(fields)
                     if f != 'signature'])
        h = hmac.new(self.secret, s, hashlib.sha1)
        sig1 = h.digest().encode('base64')
        sig1 = sig1.replace(' ', '').replace('\n', '')
        sig2 = fields['signature'].replace(' ', '').replace('\n', '')
        if sig1 != sig2:
            self.logger.debug('signature mismatch')
            self.logger.debug('input to HMAC: %s' % repr(s))
            self.logger.debug('computed signature: %s' % sig1)
            self.logger.debug('received signature: %s' % sig2)
            return False
        now = time.time()
        expires = fields.get('expires')
        if expires and int(now) > int(expires):
            self.logger.debug('request expired, now=%s, expires=%s' % (now, expires))
            return False
        return True

    def handler(self, environ, start_response):
        url = environ['SCRIPT_NAME'] + environ['PATH_INFO']
        if url != self.url:
            self.logger.error('Not found: %s' % url)
            return self.simple_response(http.NOT_FOUND)
        method = environ['REQUEST_METHOD']
        if method != 'POST':
            return self.simple_response(http.METHOD_NOT_ALLOWED, [('Allow', 'POST')])
        ctype = environ.get('CONTENT_TYPE')
        if type is None:
            return self.simple_response(http.BAD_REQUEST)
        if ';' in ctype:
            ctype, opts = ctype.split(';')
        if ctype != 'application/x-www-form-urlencoded':
            return self.simple_response(http.UNSUPPORTED_MEDIA_TYPE)
        clen = environ.get('CONTENT_LENGTH')
        if clen is None:
            return self.simple_response(http.LENGTH_REQUIRED)
        clen = int(clen)
        body = self.environ['wsgi.input'].read(clen)
        fields = urlparse.parse_qs(body)
        for key in fields:
            self.logger.debug('field %s = %s' % (key, fields[key][0]))
        for f in self.required_fields:
            if f not in fields:
                self.logger.error('required field not provided: %s' % f)
                return self.simple_response(http.BAD_REQUEST)
        for f in fields:
            if f not in self.required_fields and f not in self.optional_fields:
                self.logger.error('unknown field: %s' % f)
                return self.simple_response(http.BAD_REQUEST)
        for f in fields:
            if len(fields[f]) != 1:
                self.logger.error('multiple values provided for: %s' % f)
                return self.simple_response(http.BAD_REQUEST)
        fields = dict(((f, fields[f][0]) for f in fields))
        # We accept any eula, but if one is provided, it has to be accepted.
        if fields.get('eula') and not \
                fields.get('eula_accepted', 'false') == 'true':
            self.logger.error('EULA not accepted')
            return self.simple_response(http.FORBIDDEN)
        if self.check and not self.check_signature(fields):
            self.logger.error('Signature mismatch')
            return self.simple_response(http.FORBIDDEN)
        # Serve any file from the indicated directory
        fname = os.path.join(self.directory, fields['file'])
        try:
            st = os.stat(fname)
        except OSError:
            st = None
        if st is None or not stat.S_ISREG(st.st_mode):
            self.logger.error('file not found: %s' % fields['file'])
            return self.simple_response(http.NOT_FOUND)
        return self.serve_file(fname, st.st_size)


parser = optparse.OptionParser()
parser.add_option('-l', '--listen', default='0.0.0.0:8080',
                  help='specify listen address (host:port)')
parser.add_option('-r', '--directory', default='.',
                  help='specify upload directory')
parser.add_option('-u', '--url', help='application path', default='/download')
parser.add_option('-c', '--check', help='check signature', action='store_true')
parser.add_option('-s', '--secret', help='shared secret for authentication')
parser.add_option('-d', '--debug', help='enable debugging', action='store_true')

opts, args = parser.parse_args()

try:
    address, port = opts.listen.split(':')
    port = int(port)
except (TypeError, ValueError):
    parser.error('specify --listen as host:port')
directory = os.path.abspath(opts.directory)
try:
    st = os.stat(directory)
except OSError:
    st = None
if st is None or not stat.S_ISDIR(st.st_mode):
    parser.error('directory does not exist: %s' % opts.directory)
if opts.check and not opts.secret:
    parser.error('--secret needs to be specified with --check')

if opts.debug:
    level = logging.DEBUG
else:
    level = logging.INFO
format = '%(asctime)s %(levelname)s %(message)s'
logging.basicConfig(format=format, level=level)

app = DownloadApp(directory, opts.url, opts.check, opts.secret)
server = make_server(address, port, app)

logging.debug('listening on %s:%s' % (address, port))
server.serve_forever()
