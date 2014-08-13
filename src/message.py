# coding: utf8
__author__ = 'JinXing'

import struct

"""
头部结构定义：
版本(1字节),类型(1字节,最高位用来标识来自哪一端),数据
"""

MSG_VERSION = 1

MSG_TYPE_CONN = 0x01  # 建立新连接
MSG_TYPE_ACK = 0x02
MSG_TYPE_CLOSE = 0x04
MSG_TYPE_DATA = 0x08
MSG_TYPE_KEEPALIVE = 0x16    # 保活

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
    def connect_msg(cls, ip=None, port=None):
        """构造建立新连接的消息
        ip: 该连接最终请求的 IP
        port: 该连接最终请求的 port
        未指定 ip,port 时使用配置的默认值
        """
        data = ""
        if ip and port:
            data = "%s:%d" % (ip, port)
        return cls(MSG_TYPE_CONN, data)

    @classmethod
    def ack_msg(cls, ack_seq_ranges):
        ack_data = "".join(map(lambda x: struct.pack("H", x), ack_seq_ranges))
        return cls(MSG_TYPE_ACK, ack_data)

    @classmethod
    def close_msg(cls):
        return cls(MSG_TYPE_CLOSE)

    @classmethod
    def data_msg(cls, data):
        return cls(MSG_TYPE_DATA, data)

    @classmethod
    def keepalive_msg(cls):
        return cls(MSG_TYPE_KEEPALIVE)

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
        return "from:%s, type:%d, data:%r" % (from_str, self.type, str(self.data)[:8])

    def encode(self):
        p = struct.pack(HEAD_FMT_STR, MSG_VERSION, self.from_type | self.type)
        # print p, self.data
        return p+self.data

    def is_connect(self):
        return self.type == MSG_TYPE_CONN

    def is_ack(self):
        return self.type == MSG_TYPE_ACK

    def is_close(self):
        return self.type == MSG_TYPE_CLOSE

    def is_data(self):
        return self.type == MSG_TYPE_DATA

    def is_keepalive(self):
        return self.type == MSG_TYPE_KEEPALIVE

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

