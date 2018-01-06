#!/usr/bin/env python
#Description:  SSLScrape is a tool that scans the internet and pulls hostnames from certificates.  This tools can be used to scan cloud ranges to find hostnames for your systems.  This tool is used for research purposes and please make sure to have proper approvals before scanning.

def banner():
#Our banner, doubled slashes added for proper formatting when banner is shown in STDOUT.
    print "-" * 70
    print """

  _________ _________.____       _________                                  
 /   _____//   _____/|    |     /   _____/ ________________  ______   ____  
 \_____  \ \_____  \ |    |     \_____  \_/ ___\_  __ \__  \ \____ \_/ __ \ 
 /        \/        \|    |___  /        \  \___|  | \// __ \|  |_> >  ___/ 
/_______  /_______  /|_______ \/_______  /\___  >__|  (____  /   __/ \___  >
        \/        \/         \/        \/     \/           \/|__|        \/ 

SSLScrape | A scanning tool for scaping hostnames from SSL certificates.
Written by Peter Kim <Author, The Hacker Playbook> and @bbuerhaus
                     <CEO, Secure Planet LLC>
"""
    print "Usage | python sslScrape.py [CIDR Range]"
    print "E.X   | python sslScrape.py 10.100.100.0/24"
    print "-" * 70


import sys, socket, ssl, requests, ipaddress
from requests.packages.urllib3.exceptions import InsecureRequestWarning, InsecurePlatformWarning, SNIMissingWarning
from socket import socket
from OpenSSL import SSL
from ndg.httpsclient.subj_alt_name import SubjectAltName
from pyasn1.codec.der import decoder as der_decoder
import masscan, errno, os, signal
from functools import wraps

#pip install ndg-httpsclient
#pip install python-masscan
class TimeoutError(Exception):
    pass

def timeout(seconds=10, error_message=os.strerror(errno.ETIME)):
    def decorator(func):
        def _handle_timeout(signum, frame):
            raise TimeoutError(error_message)

        def wrapper(*args, **kwargs):
            signal.signal(signal.SIGALRM, _handle_timeout)
            signal.alarm(seconds)
            try:
                result = func(*args, **kwargs)
            finally:
                signal.alarm(0)
            return result

        return wraps(func)(wrapper)

    return decorator


requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
requests.packages.urllib3.disable_warnings(InsecurePlatformWarning)
requests.packages.urllib3.disable_warnings(SNIMissingWarning)

@timeout(10)
def getDomainFromCert(ipAddr, port = 443):
    context = SSL.Context(SSL.TLSv1_METHOD)
    context.set_options(SSL.OP_NO_SSLv2)
    context.set_verify(SSL.VERIFY_NONE, callback)
    sock = socket()
    try:
        ssl_sock = SSL.Connection(context, sock)
        sock.settimeout(0.5)
        ssl_sock.connect((str(ipAddr), port))
    except:
        return False
    # do handshake
    try:
        # reset timeout for handshake
        sock.settimeout(None)
        # perform handshake
        ssl_sock.do_handshake()
        # get cert data
        cert = ssl_sock.get_peer_certificate()
        name = cert.get_subject().commonName.decode()
        # try to save all cn/alt names
        try:
            alt = get_subj_alt_name(cert)
            return alt
        except:
            # failed, just save the CN instead
            return [name]
        
    except:
        pass

def get_subj_alt_name(peer_cert):
    dns_name = []
    general_names = SubjectAltName()
    for i in range(peer_cert.get_extension_count()):
        ext = peer_cert.get_extension(i)
        ext_name = ext.get_short_name()
        if ext_name == "subjectAltName":
            ext_dat = ext.get_data()
            decoded_dat = der_decoder.decode(ext_dat, asn1Spec=general_names)

            for name in decoded_dat:
                if isinstance(name, SubjectAltName):
                    for entry in range(len(name)):
                        component = name.getComponentByPosition(entry)
                        dns_name.append(str(component.getComponent()))
    return dns_name

def callback(conn, cert, errno, depth, result):
    if depth == 0 and (errno == 9 or errno == 10):
        return False
    return True

if __name__ == "__main__":  
    banner()
    try:
        cidr =  sys.argv[1:][0]
    except:
        sys.exit(1)
    mas = masscan.PortScanner()
    mas.scan(cidr, ports='443')
    for host in mas.all_hosts:
        host = str(host)
        try:
            print host + ":" + ",".join(getDomainFromCert(host))
        except:
            print host + ":fail"


