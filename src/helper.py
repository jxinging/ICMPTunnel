# coding: utf8
__author__ = 'JinXing'


import threading
import struct
import ctypes
import logging

logger = logging
logging.basicConfig(level=logging.DEBUG)

MAX_BUF_LEN = 65536

# From /usr/include/linux/icmp.h
ICMP_ECHO_REPLY = 0
ICMP_ECHO = 8

config = {
    "peer": "14.17.123.11",
    "target_ip": "www.baidu.com",
    "target_port": 80
}


class SeqBuilder(object):
    def __init__(self):
        self.seq_lock = threading.RLock()
        self.seq_num = 0

    def __call__(self):
        with self.seq_lock:
            ret = self.seq_num
            self.seq_num += 1
        return ret

get_seq = SeqBuilder()


def checksum(source_string):
    """
    I'm not too confident that this is right but testing seems
    to suggest that it gives the same answers as in_cksum in ping.c
    """
    sum_ = 0
    count_to = (len(source_string) / 2) * 2
    for count in xrange(0, count_to, 2):
        this = ord(source_string[count + 1]) * 256 + ord(source_string[count])
        sum_ += this
        sum_ &= 0xffffffff  # Necessary?

    if count_to < len(source_string):
        sum_ += ord(source_string[len(source_string) - 1])
        sum_ &= 0xffffffff  # Necessary?

    sum_ = (sum_ >> 16) + (sum_ & 0xffff)
    sum_ += (sum_ >> 16)
    answer = ~sum_
    answer &= 0xffff

    # Swap bytes. Bugger me if I know why.
    answer = answer >> 8 | (answer << 8 & 0xff00)

    return answer


class ICMPPacket(object):
    @classmethod
    def _checksum(cls, data):
        if len(data) % 2:
            odd_byte = ord(data[-1])
            data = data[:-1]
        else:
            odd_byte = 0
        words = struct.unpack("!%sH" % (len(data) / 2), data)
        total = 0
        for word in words:
            total += word
        else:
            total += odd_byte
        total = (total >> 16) + (total & 0xffff)
        total += total >> 16
        return ctypes.c_ushort(~total).value

    @classmethod
    def parse(cls, buf):
        type_, code, checksum, id_, seq = struct.unpack("!BBHHH", buf[20:28])
        return type_, id_, seq, buf[28:]

    @classmethod
    def create(cls, type_, code, id_, seq, data):
        packfmt = "!BBHHH%ds" % (len(data))
        args = [type_, code, 0, id_, seq, data]
        args[2] = cls._checksum(struct.pack(packfmt, *args))
        return struct.pack(packfmt, *args)


if __name__ == "__main__":
    import socket
    import os
    icmp = socket.getprotobyname("icmp")
    icmp_sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, icmp)
    send_data = ICMPPacket.create(ICMP_ECHO, 0, os.getpid(), 0, "x"*64)
    icmp_sock.sendto(send_data, (socket.gethostbyname("10.19.190.24"), 0))
    data, addr = icmp_sock.recvfrom(MAX_BUF_LEN)
    print addr, ICMPPacket.parse(data)
