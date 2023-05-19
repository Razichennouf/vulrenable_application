#!/usr/bin/env python

import os
import ssl
import argparse

from dsvpwa.server import VulnHTTPServer
from dsvpwa.handlers import VulnHTTPRequestHandler

BUILD_VER = os.getenv('BUILD_VER') or '0.0.1'
BUILD_REV = os.getenv('BUILD_REV') or 'dev'


def main():
    parser = argparse.ArgumentParser(
        prog='DSVPWA',
        description='Damn Simple Vulnerable Python Web Application'
    )
    parser.add_argument('--host', default='0.0.0.0', help='set the IP address to bind to (defaults to 0.0.0.0)')
    parser.add_argument('--port', type=int, default=os.getenv('DSVPWA_PORT', 443),
                        help='set the port number to bind to (defaults to 443)')
    parser.add_argument('--risk', type=int, default=os.getenv('DSVPWA_RISK', 1), choices=range(1, 4),
                        help='set the risk level in the range 1-3')
    parser.add_argument('--ssl', action='store_true', default=os.getenv('DSVPWA_SSL', False),
                        help='enable encryption (defaults to false)')
    parser.add_argument('--version', action='version',
                        version='%(prog)s v{} ({})'.format(BUILD_VER, BUILD_REV))

    args = parser.parse_args()
    proto = 'http' if not args.ssl else 'https'

    try:
        httpd = VulnHTTPServer((args.host, args.port), VulnHTTPRequestHandler)
        httpd.RequestHandlerClass.risk = args.risk

        if args.ssl:
            certfile = 'ssl/cert.pem'  # Replace with the path to your SSL certificate file
            keyfile = 'ssl/key.pem'  # Replace with the path to your SSL private key file

            ctx = ssl.create_default_context(ssl.Purpose.CLIENT_AUTH)
            #ctx.options |= ssl.OP_NO_TLSv1 | ssl.OP_NO_TLSv1_1  # Optional: Disable older TLS versions if desired
            ctx.load_cert_chain(certfile=certfile, keyfile=keyfile)

            httpd.socket = ctx.wrap_socket(httpd.socket, server_side=True)

        print('[*] Navigate to {}://{}:{} to access DSVPWA'.format(proto, args.host, args.port))
        httpd.serve_forever()

    except KeyboardInterrupt:
        print('[*] Quitting...')
        pass
    except Exception as ex:
        print("[!] Exception occurred ('%s')" % ex)
    finally:
        httpd.server_close()
        os._exit(0)


if __name__ == "__main__":
    main()
