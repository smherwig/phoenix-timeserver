#!/usr/bin/env python

import binascii
import collections
import getopt
import socket
import struct
import sys
import time

# /usr/lib/python2.7/dist-packages/cryptography
# lira.no-ip.org:8080/doc/python-cryptography-doc/html/hazmat/primitives/
#   assymetric/rsa.html
import cryptography.exceptions
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.hazmat.primitives import hashes

TNTResponse = collections.namedtuple('TNTResponse', [
    'raw',
    'statuscode',
    'msglen',
    'body',
    'nonce',
    'sec',
    'usec',
    'sigsize',
    'sig'
    ])

verbose = False

_USAGE = """
./tntclient [options] RSA_CERT

options:
  -h, --help
    Display this help message and exit.

  -i, --ip IP_ADDRESS
    The server's IP_ADDRESS.  Default is 127.0.0.1.

  -n, --nonce NONCE
    The request nonce (an integer).  Default is 67890.

  -p, --port PORT
    The servers' port Default is 12345.

  -v, --verbose
    Verbose logging (prints the fields of the
    request and response).

""".strip()

def _usage(exitcode):
    sys.stderr.write('%s\n' % _USAGE)
    sys.exit(exitcode)

def _debug(fmt, *args):
    if not verbose:
        return
    fmt = '[debug] %s' % fmt
    if not fmt.endswith('\n'):
        fmt += '\n'
    sys.stdout.write(fmt % args)

def _die(fmt, *args):
    fmt = '[die] %s' % fmt
    if not fmt.endswith('\n'):
        fmt += '\n'
    sys.stderr.write(fmt % args)
    sys.exit(1)

def _warn(fmt, *args):
    fmt = '[warn] %s' % fmt
    if not fmt.endswith('\n'):
        fmt += '\n'
    sys.stderr.write(fmt % args)

def _parse_int(s, tag):
    try:
        i = int(s)
    except ValueError:
        _die('%s must be an integer', tag)
    else:
        return i

def _print_time(sec, usec):
    # todo: convert from epoch to UTC timestamp
    utc_st = time.gmtime(sec)
    timestamp = time.strftime('%Y-%m-%d %H:%M:%S', utc_st)
    timestamp += '.%d' % usec
    print timestamp

def _verbose_dump_response(resp):
    global verbose
    if not verbose:
        return
    print 'header:'
    print '    statuscode: %d' % resp.statuscode
    print '    msglen: %d' % resp.msglen
    print 'body:'
    print '     nonce: %d' % resp.nonce
    print '     sec: %d' % resp.sec
    print '     usec: %d' % resp.usec
    print 'signature:'
    print '     sigsize: %d' % resp.sigsize
    print '     sig: %s' % binascii.hexlify(resp.sig)

"""
We are using cryptopgrahy 1.2.3; cryptogrpaphy 2.x seems
to use a different API for verification
"""
def _verify(pubkey, body, sig):
    verifier = pubkey.verifier(sig, padding.PKCS1v15(), hashes.SHA256()) 
    verifier.update(body)
    try:
        verifier.verify()
    except cryptography.exceptions.InvalidSignature as e:
        # XXX: e doesn't seem to have any useful info, and doesn't
        # print anythign when passed to str().
        print 'invalid signature'

def _parse_response(data):
    hdr = data[0:8]
    statuscode, msglen = struct.unpack('>II', hdr)

    body = data[8:28]
    nonce, sec, usec = struct.unpack('>QQI', body)

    sigsize = data[28:32]
    sigsize = struct.unpack('>I', sigsize)[0]
    sig = data[32:]

    return TNTResponse(raw=data, statuscode=statuscode, msglen=msglen,
            body=body, nonce=nonce, sec=sec, usec=usec, 
            sigsize=sigsize, sig=sig)

def _request(ip, port, nonce, pubkey):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM);
    req = struct.pack('>Q', nonce)
    s.sendto(req, (ip, port))
    data, addr = s.recvfrom(1024)
    resp = _parse_response(data)
    _verbose_dump_response(resp)
    if resp.nonce != nonce:
        print 'nonce mismatch -- possible replay attack'
    _print_time(resp.sec, resp.usec)
    _verify(pubkey, resp.body, resp.sig)

def _load_public_key(path):
    with open(path, 'rb') as f:
        data = f.read()
    key = load_pem_public_key(data, backend=default_backend())
    assert isinstance(key, rsa.RSAPublicKey)
    return key

def main(argv):
    shortopts = 'hi:n:p:v'
    longopts = ['help', 'ip=', 'nonce=', 'port=', 'verbose']
    # options
    global verbose
    ip = '127.0.0.1'
    port = 12345
    nonce = 67890
    # args
    pubkey_file = None

    try:
        opts, args = getopt.getopt(argv[1:], shortopts, longopts)
    except getopt.GetoptError as err:
        sys.stderr.write('%s\n', str(errr))
        _usage(1)

    for o, a in opts:
        if o in ('-h', '--help'):
            _usage(0)
        elif o in ('-i', '--ip'):
            ip = a
        elif o in ('-n', '--nonce'):
            nonce = _parse_int(a, 'NONCE')
        elif o in ('-p', '--port'):
            port = _parse_int(a, 'PORT')
        elif o in ('-v', '--verbose'):
            verbose = True
        else:
            assert False, "unhandled option '%s'" % o

    if len(args) != 1:
        _usage(1)

    pubkey_file = args[0]
    pubkey = _load_public_key(pubkey_file) 
    _request(ip, port, nonce, pubkey)

if __name__ == '__main__':
    main(sys.argv)
