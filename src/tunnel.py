# coding: utf8
__author__ = 'JinXing'

import time
from _icmp import ICMPPocket
from message import (
    ClientMessage, ServerMessage, Message,
    MSG_TYPE_ACK, MSG_TYPE_CLOSE, MSG_TYPE_DATA
)
from config import *


ICMP_SEQ_MAX = 0xFFFF   # icmp seq 的最大值 (icmp 协议定义seq占2字节)


class BaseTunnel(object):
    MessageCls = Message
    ICMP_TYPE = 8

    def __init__(self, id_, send_seq, recv_seq, socket, icmp_socket, peer):
        self.id = id_
        self.send_seq = send_seq
        self.recv_seq = recv_seq
        self.socket = socket    # tcp socket
        self.icmp_socket = icmp_socket

        self.tcp_send_bufs = []
        self.icmp_send_bufs = {}    # seq:data
        self.icmp_recv_bufs = {}    # seq:data
        self.icmp_wait_ack_bufs = {}    # seq: [timeout, data]

        self.last_live = time.time()   # 上一次收到数据包的时间戳
        self.closing = False
        self.close_timeout = 0
        self.socket_closed = False

        self.peer = peer
        self.trans_bytes = 0
        self.send_count = 0
        self.data_send_count = 0
        self.retry_count = 0

        self.ack_seqs = set()
        self.ack_seqs_timeout = 0

        self.blocked = False

    @staticmethod
    def next_seq(seq):
        return (seq + 1) % ICMP_SEQ_MAX

    def update_send_seq(self):
        self.send_seq = self.next_send_seq()
        return self.send_seq

    def next_send_seq(self):
        return self.next_seq(self.send_seq)

    def update_recv_seq(self):
        self.recv_seq = self.next_recv_seq()
        return self.recv_seq

    def next_recv_seq(self):
        return self.next_seq(self.recv_seq)

    def send_icmp_connect(self, ip=None, port=None):
        msg = self.MessageCls.connect_msg(ip, port)
        data = msg.encode()
        # self.update_send_seq()
        self.icmp_wait_ack_bufs[self.send_seq] = (time.time()+ACK_TIMEOUT, data)
        return self._send_icmp(data, self.ICMP_TYPE, self.send_seq)

    def check_send_ack_timeout(self):
        now_time = time.time()
        if self.ack_seqs_timeout != 0 and \
                now_time >= self.ack_seqs_timeout:
            return True
        return False

    def send_icmp_ack(self, ack_seq=None, delay=True):
        if ack_seq is not None:
            self.ack_seqs.add(ack_seq)

        if delay:
            if self.ack_seqs_timeout == 0:
                # logger.debug("set ack_seqs_timeout")
                self.ack_seqs_timeout = time.time() + ACK_TIMEOUT/4
            if not self.check_send_ack_timeout():
                return

        logger.debug("send ack: %d, %s", self.recv_seq, self.ack_seqs)
        ack_seqs = []
        for seq in self.ack_seqs:
            if seq > self.recv_seq:
                ack_seqs.append(seq)

        msg = self.MessageCls.ack_msg(self.recv_seq, ack_seqs)
        self.ack_seqs = set()
        self.ack_seqs_timeout = 0
        return self._send_icmp(msg.encode(), self.ICMP_TYPE, self.send_seq)

    def send_icmp_close(self):
        msg = self.MessageCls.close_msg()
        return self._send_icmp(msg.encode(), self.ICMP_TYPE, self.send_seq)

    def send_icmp_data(self, data, seq=None):
        msg = self.MessageCls.data_msg(data)
        self.data_send_count += 1
        return self._send_icmp(msg.encode(), self.ICMP_TYPE, seq)

    def send_icmp_keepalive(self):
        msg = self.MessageCls.keepalive_msg()
        return self._send_icmp(msg.encode(), self.ICMP_TYPE, self.send_seq)

    def _send_icmp(self, data, type_, seq=None):
        if seq is None:
            seq = self.send_seq
            self.update_send_seq()
        self.send_count += 1
        return ICMPPocket(type_, self.id, seq, AUTH_STR+data).sendto(self.icmp_socket, self.peer)

    def process_icmp(self, icmp_p, msg):
        if msg.from_type != self.MessageCls.ACCEPT_FROM:
            # logger.debug("msg from type error: %s", str(msg))
            return
        # logger.debug("msg: %s", str(msg))
        self.last_live = time.time()
        if msg.is_data():
            # logger.debug("icmp_p.seq: %d, self.recv_seq: %d", icmp_p.seq, self.recv_seq)
            send_ack = True
            if icmp_p.seq == self.recv_seq:
                self.tcp_send_bufs.append(msg.data)
                # logger.debug("transmit %d.%d", self.id, icmp_p.seq)
                next_seq = self.update_recv_seq()  # 只有 data 包才消耗 seq

                while next_seq in self.icmp_recv_bufs:
                    # logger.debug("transmit %d.%d", self.id, next_seq)
                    self.tcp_send_bufs.append(self.icmp_recv_bufs[next_seq])
                    del self.icmp_recv_bufs[next_seq]
                    next_seq = self.update_recv_seq()   # **

            # 缓存后续的包(recv_seq 接近最大值时小于当前 recv_seq 的包也接收)
            elif icmp_p.seq > self.recv_seq or \
                            self.recv_seq > (ICMP_SEQ_MAX - MAX_WAIT_ACK_POCKETS):
                if len(self.icmp_recv_bufs) >= MAX_WAIT_ACK_POCKETS*2:
                    logger.warn("recv buf len %d, drop data %d.%d",
                                len(self.icmp_recv_bufs), icmp_p.id, icmp_p.seq)
                    send_ack = False
                else:
                    self.icmp_recv_bufs[icmp_p.seq] = msg.data
                    logger.info("cached data %d.%d, cached pockets: %d, recv_seq: %d",
                                icmp_p.id, icmp_p.seq, len(self.icmp_recv_bufs), self.recv_seq)
            elif icmp_p.seq < self.recv_seq:
                logger.info("drop data %d.%d, recv_seq: %d",
                            icmp_p.id, icmp_p.seq, self.recv_seq)
                send_ack = True

            if send_ack:
                self.send_icmp_ack(icmp_p.seq)

        elif msg.is_ack():
            # self.update_recv_seq()  # **

            logger.debug("recv ack: %s", msg.data)
            recv_seq_str, ack_seqs_str = msg.data.split(",", 1)
            peer_recv_seq = int(recv_seq_str)
            ack_seqs = []
            if ack_seqs_str:
                ack_seqs = map(int, ack_seqs_str.split(","))

            # 把对端已经收到但没有及时得到 ack 的包从队列中删除
            for seq in sorted(self.icmp_wait_ack_bufs.keys()):
                if seq < peer_recv_seq:
                    del self.icmp_wait_ack_bufs[seq]
                else:
                    break
            for seq in sorted(self.icmp_send_bufs.keys()):
                if seq < peer_recv_seq:
                    del self.icmp_send_bufs[seq]
                else:
                    break

            # 从队列中删除已确认的数据包
            for ack_seq in ack_seqs:
                if ack_seq in self.icmp_wait_ack_bufs:
                    # logger.debug("ack %d.%d", self.id, ack_seq)
                    self.trans_bytes += len(self.icmp_wait_ack_bufs[ack_seq][1])
                    del self.icmp_wait_ack_bufs[ack_seq]

                # 有可能收到 ack 包时，数据包已经被重新加入到发送队列
                if ack_seq in self.icmp_send_bufs:
                    self.trans_bytes += len(self.icmp_send_bufs[ack_seq])
                    del self.icmp_send_bufs[ack_seq]

            # 立即发送对端期待的数据包
            next_seq = peer_recv_seq
            while next_seq in self.icmp_wait_ack_bufs:
                _, data = self.icmp_wait_ack_bufs[next_seq]
                self.retry_count += 1
                logger.debug("direct send expected data %d.%d", self.id, next_seq)
                self.send_icmp_data(data, next_seq)
                self.icmp_wait_ack_bufs[next_seq] = (time.time() + ACK_TIMEOUT, data)
                next_seq = BaseTunnel.next_seq(next_seq)

            # Server.process_recv_icmp() 还会对该类消息进行其他处理

        elif msg.is_close():
            pass
            # self.update_recv_seq()  # **
            # Server.process_recv_icmp() 还会对该类消息进行其他处理

        elif msg.is_connect():
            # self.update_recv_seq()  # ** 创建连接的消息不占用 seq num
            # 创建新连接消息由 Server.process_recv_icmp() 处理
            pass

        elif msg.is_keepalive():
            pass
            # self.update_recv_seq()  # **
            #self.send_icmp_keepalive()

        else:
            logger.warn("error msg type: %s", str(msg))

        return msg


class ClientTunnel(BaseTunnel):
    MessageCls = ClientMessage
    ICMP_TYPE = 8

    def __init__(self, id_, socket, icmp_sock, server):
        # BaseTunnel.__init__(self, id_, 10, 11, socket, icmp_sock, server)
        BaseTunnel.__init__(self, id_, 0, 0, socket, icmp_sock, server)


class ServerTunnel(BaseTunnel):
    MessageCls = ServerMessage
    ICMP_TYPE = 0

    def __init__(self, id_, socket, icmp_sock, client):
        # BaseTunnel.__init__(self, id_, 11, 10, socket, icmp_sock, client)
        BaseTunnel.__init__(self, id_, 0, 0, socket, icmp_sock, client)
