# coding: utf8
__author__ = 'JinXing'

import struct

"""
头部结构定义：
版本(1字节),类型(1字节,最高位用来标识来自哪一端),数据
"""

MSG_VERSION = 1

MSG_TYPE_ACK = 0x01
MSG_TYPE_CLOSE = 0x02
MSG_TYPE_DATA = 0x04

MSG_FROM_CLIENT = 0x00  # 最高位为0
MSG_FROM_SERVER = 0x80  # 最高位为1

HEAD_FMT_STR = "BB"


class Message(object):
    FROM_TYPE = None
    ACCEPT_FROM = None

    def __init__(self, type_, data="", from_type=None):
        # assert isinstance(data, basestring)   # save cpu
        self.type = type_
        self.data = data
        if from_type is None:
            from_type = self.FROM_TYPE
        self.from_type = from_type

    @classmethod
    def ack_msg(cls, ack_seq):
        return cls(MSG_TYPE_ACK, ack_seq)

    @classmethod
    def close_msg(cls):
        return cls(MSG_TYPE_ACK)

    @classmethod
    def data_msg(cls, data):
        return cls(MSG_TYPE_ACK, data)

    @classmethod
    def decode(cls, raw):
        assert len(raw) >= 2
        ver, type_ = struct.unpack(HEAD_FMT_STR, raw[:2])
        assert ver == MSG_VERSION, "message version error"
        from_type = type_ & 0x80
        type_ &= 0x7F
        # assert from_type == cls.ACCEPT_FROM
        return cls(type_, raw[2:], from_type)

    def __str__(self):
        from_type = self.from_type
        from_str = "unknown(%r)" % from_type
        if from_type == MSG_FROM_CLIENT:
            from_str = "client"
        elif from_type == MSG_FROM_SERVER:
            from_str = "server"
        return "from:%s, type:%d, data:%r" % (from_str, self.type, self.data)

    def encode(self):
        p = struct.pack(HEAD_FMT_STR, MSG_VERSION, self.from_type | self.type)
        return p+self.data

    def is_ack(self):
        return self.type == MSG_TYPE_ACK

    def is_close(self):
        return self.type == MSG_TYPE_CLOSE

    def is_data(self):
        return self.type == MSG_TYPE_DATA

    def is_client_msg(self):
        return self.from_type == MSG_FROM_CLIENT

    def is_server_msg(self):
        return self.from_type == MSG_FROM_SERVER


class ClientMessage(Message):
    FROM_TYPE = MSG_FROM_CLIENT
    ACCEPT_FROM = MSG_FROM_SERVER


class ServerMessage(Message):
    FROM_TYPE = MSG_FROM_SERVER
    ACCEPT_FROM = MSG_FROM_CLIENT


def test():
    cm = ClientMessage(MSG_TYPE_ACK, struct.pack("B", 10))
    print str(cm)
    raw = cm.encode()
    print ClientMessage.decode(raw)
    print str(list(raw))
    print ClientMessage.decode(raw)

    sm = ServerMessage(MSG_TYPE_DATA, "XXmsgdataXX")
    print str(sm)
    raw = sm.encode()
    print list(raw)
    print ServerMessage.decode(raw)
    rl = list(raw)
    rl[0] = chr(10)
    raw = "".join(rl)
    print ServerMessage.decode(raw)


if __name__ == "__main__":
    test()

