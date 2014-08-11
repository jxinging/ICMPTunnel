# coding: utf8
__author__ = 'JinXing'

import struct
import random


def icmp_checksum(source_string):
    """
    I'm not too confident that this is right but testing seems
    to suggest that it gives the same answers as in_cksum in ping.c
    """
    # return random.randint(0, 0xFFFF)
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


def encrypt(data):
    return data
    # return ''.join(map(lambda x: chr(ord(x) ^ 0x08), data))


def decrypt(data):
    return data
    # return encrypt(data)

class ICMPPocket(object):
    def __init__(self, type_, id_, seq, data, checksum=0, code=0, addr=None):
        self.type = type_
        self.code = code
        self.checksum = checksum
        self.id = id_
        self.seq = seq
        self.data = data
        self.addr = addr

    def __str__(self):
        return "addr: %s, type:%d, id:%d, seq:%d, data:%s ..." % \
            (self.addr, self.type, self.id, self.seq, str(self.data[:64]))

    @classmethod
    def parse(cls, obj, buflen=None):
        if buflen is not None:
            # socket
            raw, addr = obj.recvfrom(buflen)
            addr = addr[0]
        else:
            raw = obj
            addr = None
        type_, code, checksum, id_, seq = struct.unpack("!BBHHH", raw[20:28])
        data = decrypt(raw[28:])
        return cls(type_, id_, seq, data, checksum, code, addr)

    def create(self):
        packfmt = "!BBHHH%ds" % (len(self.data))
        # checksum = random.randint(0, 0xFFFF)  # save cpu
        data = encrypt(self.data)
        args = [self.type, self.code, 0, self.id, self.seq, data]
        # print args
        args[2] = icmp_checksum(struct.pack(packfmt, *args))
        return struct.pack(packfmt, *args)

    def sendto(self, sock, host):
        sock.sendto(self.create(), (host, 0))
