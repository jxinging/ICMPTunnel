# coding: utf8
__author__ = 'JinXing'

from client import *
# from helper import *


def client_test():
    server = ThreadingTCPServer(("0.0.0.0", 1199), ClientRequestHandler)
    sa = server.socket.getsockname()
    print "Serving on", sa[0], "port", sa[1], "..."
    server.serve_forever(0.5)

if __name__ == "__main__":
    client_test()

