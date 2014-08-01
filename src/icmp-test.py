#coding:utf8

import sys
import time
import socket
import select
import binascii

icmp = socket.getprotobyname("icmp")
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
l = []
start_time = time.time()
cnt = 0
data_recved = 0
while 1:
    now = time.time()
    if now-start_time >= 1:
        print "package: %d, total_data: %d" % (cnt, data_recved)
        start_time = now
        cnt = 0
        data_recved = 0
    #l.append(sock)
    #print len(l)
    #sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    r, _, _ = select.select([sock], [], [], 0.1) 
    if r:
        data, addr = sock.recvfrom(4096)
        data_recved += len(data)
        cnt += 1
    #print addr, binascii.b2a_hex(data)
