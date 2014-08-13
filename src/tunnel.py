# coding: utf8
__author__ = 'JinXing'

import struct
import time
from _icmp import ICMPPocket
from message import (
    ClientMessage, ServerMessage, Message,
    MSG_TYPE_ACK, MSG_TYPE_CLOSE, MSG_TYPE_DATA
)
from config import *


ICMP_SEQ_MAX = 0xFFFF  # icmp seq 的最大值 (icmp 协议定义seq占2字节)


class BaseTunnel(object):
    MessageCls = Message
    ICMP_TYPE = 8

    def __init__(self, id_, send_seq, recv_seq, socket, icmp_socket, peer):
        self.id = id_
        self.send_seq = send_seq
        self.recv_seq = recv_seq
        self.socket = socket  # tcp socket
        self.icmp_socket = icmp_socket

        self.tcp_send_bufs = []
        self.icmp_send_bufs = {}  # seq:data
        self.icmp_recv_bufs = {}  # seq:data
        self.icmp_wait_ack_bufs = {}  # seq: [timeout, data]

        self.last_live = time.time()  # 上一次收到数据包的时间戳
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
        self.peer_cached_seqs = set()

        self.blocked = False

    @staticmethod
    def seq_distance(seq_base, seq):
        """计算两个 seq 值间的距离
        如果 seq 晚于 seq_base 返回正数, 否则返回负数
        """
        seq_litter, seq_big = sorted((seq_base, seq))
        directly_dist = seq_big - seq_litter
        loop_dist = ICMP_SEQ_MAX - seq_big + seq_litter
        dist = min(directly_dist, loop_dist)
        # logger.debug("seq_distance(%d, %d), directly_dist: %d, loop_dist: %d",
        # seq_base, seq, directly_dist, loop_dist)
        if seq >= seq_base:
            return dist
        else:
            return -dist

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
        # self.icmp_wait_ack_bufs[self.send_seq] = (time.time()+ACK_TIMEOUT, data)
        return self._send_icmp(data, self.ICMP_TYPE, self.send_seq)

    def check_send_ack_timeout(self):
        now_time = time.time()
        if self.ack_seqs_timeout == 0:
            # 即使没有数据包需要确认也会定时发送 ack 包, 防止有 ack 包丢失时可能出现的两端同时阻塞等待
            self.ack_seqs_timeout = time.time() + ACK_TIMEOUT

        if self.ack_seqs_timeout != 0 and \
                now_time >= self.ack_seqs_timeout:
            return True
        return False

    def send_icmp_ack(self, ack_seq=None, delay=True):
        if ack_seq is not None:
            self.ack_seqs.add(ack_seq)

        if delay:
            timeout = time.time() + ACK_TIMEOUT / 10.0
            if self.ack_seqs_timeout == 0 or timeout < self.ack_seqs_timeout:
                logger.debug("set ack_seqs_timeout %d", self.ack_seqs_timeout)
                self.ack_seqs_timeout = timeout
            if not self.check_send_ack_timeout():
                return

        # logger.debug("send ack: %d, %s", self.recv_seq, self.ack_seqs)
        # ack_seqs = []
        # for seq in self.ack_seqs:
        # if seq > self.recv_seq:
        #         ack_seqs.append(seq)

        # logger.info("tunnel %d icmp_recv_buf: %s", self.id, self.icmp_recv_bufs.keys())
        # 每次 ack 都告知对端当前的 recv_ack 以及从 recv_ack 开始所有已经缓存的数据包
        # 每两个元素表示一个已缓存数据包的 seq 闭区间(recv_ack 不包括在内)
        ack_seq_ranges = []
        range_l = self.recv_seq
        last_seq = range_l
        for seq in sorted(filter(lambda x: x > self.recv_seq, self.icmp_recv_bufs.keys())):
            if seq != self.next_seq(last_seq):
                range_r = last_seq
                ack_seq_ranges.append(range_l)
                ack_seq_ranges.append(range_r)
                range_l = seq
            last_seq = seq
        ack_seq_ranges.append(range_l)
        ack_seq_ranges.append(last_seq)
        #
        # if len(ack_seq_ranges) % 2 != 0:
        #     ack_seq_ranges.append(ack_seq_ranges[-1])

        # ack_data = ",".join(map(str, ack_seq_ranges))
        logger.info("send ack: %s", ack_seq_ranges)
        msg = self.MessageCls.ack_msg(ack_seq_ranges)

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
        return ICMPPocket(type_, self.id, seq, AUTH_STR + data).sendto(self.icmp_socket, self.peer)

    def process_icmp(self, icmp_p, msg):
        if msg.from_type != self.MessageCls.ACCEPT_FROM:
            # logger.debug("msg from type error: %s", str(msg))
            return
        logger.debug("tunnel %d recv icmp msg %d: %s", icmp_p.id, icmp_p.seq, str(msg))
        self.last_live = time.time()
        if msg.is_data():
            send_ack = False
            seq_dist = self.seq_distance(self.recv_seq, icmp_p.seq)

            if seq_dist == 0:
                send_ack = True
                self.tcp_send_bufs.append(msg.data)
                # logger.debug("transmit %d.%d", self.id, icmp_p.seq)
                next_seq = self.update_recv_seq()  # 只有 data 包才消耗 seq

                while next_seq in self.icmp_recv_bufs:
                    # logger.debug("transmit %d.%d", self.id, next_seq)
                    self.tcp_send_bufs.append(self.icmp_recv_bufs[next_seq])
                    del self.icmp_recv_bufs[next_seq]
                    next_seq = self.update_recv_seq()  # **

            # 缓存后续的包
            elif 0 < seq_dist < MAX_CACHE_POCKETS:
                self.icmp_recv_bufs[icmp_p.seq] = msg.data
                logger.debug("cached data %d.%d, cached pockets: %d, recv_seq: %d",
                             icmp_p.id, icmp_p.seq, len(self.icmp_recv_bufs), self.recv_seq)
                send_ack = True
            # 丢弃
            else:
                logger.info("drop data %d.%d, recv_seq: %d",
                            icmp_p.id, icmp_p.seq, self.recv_seq)
                if seq_dist < 0:  # 已经接收过的包
                    send_ack = True
                else:  # 超过缓存接收范围的包
                    send_ack = False

            if send_ack:
                self.send_icmp_ack(icmp_p.seq)

        elif msg.is_ack():
            # self.update_recv_seq()  # **
            logger.debug("tunnel %d recv ack: %s", self.id, msg.data)
            ack_nums = len(msg.data)/2
            ack_seq_ranges = struct.unpack("%dH" % ack_nums, msg.data)

            peer_recv_seq = ack_seq_ranges[0]
            # 把对端已处理的数据包从队列中删除
            for seq in self.icmp_wait_ack_bufs.keys():
                if seq < peer_recv_seq:
                    del self.icmp_wait_ack_bufs[seq]
            for seq in self.icmp_send_bufs.keys():
                if seq < peer_recv_seq:
                    del self.icmp_send_bufs[seq]

            peer_recved_seqs = []
            # 第一组数据包含 recv_seq, 需要特殊处理
            peer_recved_seqs += range(ack_seq_ranges[0] + 1, ack_seq_ranges[1] + 1)
            for i in xrange(2, len(ack_seq_ranges), 2):
                range_l = ack_seq_ranges[i]
                range_r = ack_seq_ranges[i + 1]
                peer_recved_seqs += range(range_l, range_r + 1)
            peer_recved_seqs = set(peer_recved_seqs)

            # 从队列中删除对端已接收的数据包
            for recved_seq in peer_recved_seqs:
                _, data = self.icmp_wait_ack_bufs.get(recved_seq, (None, None))
                if data is None:
                    data = self.icmp_send_bufs.get(recved_seq)
                    if data:
                        del self.icmp_send_bufs[recved_seq]
                else:
                    # 已确认的包只是标记超时为0， 但不从队列中删除
                    # 因为此时虽然收到了 ack，但该包只是被对端缓存
                    # 因此这里要继续保存在确认队列中占位, 直到 peer_recv_seq 大于该包的 seq
                    self.icmp_wait_ack_bufs[recved_seq] = (0, data)

                if data:
                    self.trans_bytes += len(data)

            # 立即发送对端期待的数据包
            max_recved_seq = 0
            if peer_recved_seqs:
                max_recved_seq = max(peer_recved_seqs)
            next_seq = peer_recv_seq
            while next_seq < self.send_seq and next_seq < max_recved_seq and next_seq not in peer_recved_seqs:
                timeout, data = self.icmp_wait_ack_bufs.get(next_seq, (None, None))
                if data and (time.time() > (timeout - ACK_TIMEOUT/2.0) or self.blocked):
                    del self.icmp_wait_ack_bufs[next_seq]
                else:
                    # if next_seq == peer_recv_seq:
                    # logger.error("tunnel %d, Can't find peer request pocket %d", self.id, next_seq)
                    #     self.closing = True
                    #     self.send_icmp_close()
                    #     if not self.close_timeout:
                    #         self.close_timeout = time.time() + CLOSE_TIMEOUT
                    break

                self.retry_count += 1
                logger.debug("direct send expected data %d.%d", self.id, next_seq)
                self.send_icmp_data(data, next_seq)
                self.icmp_wait_ack_bufs[next_seq] = (time.time() + ACK_TIMEOUT, data)
                next_seq = BaseTunnel.next_seq(next_seq)

                # break   # 暂时只发一个包， 看看效果
                # Server.process_recv_icmp() 还会对该类消息进行其他处理

        elif msg.is_close():
            pass
            # self.update_recv_seq()  # **
            # Server.process_recv_icmp() 还会对该类消息进行其他处理

        elif msg.is_connect():
            # self.update_recv_seq()  # ** 创建连接的消息不占用 seq num
            # 创建新连接消息由 Server.process_recv_icmp() 处理
            # self.send_icmp_ack(icmp_p.seq, False)
            pass

        elif msg.is_keepalive():
            # self.update_recv_seq()  # **
            if not self.closing:
                self.send_icmp_ack(None, False)

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


if __name__ == "__main__":
    print BaseTunnel.seq_distance(10, 99)
    print BaseTunnel.seq_distance(10, ICMP_SEQ_MAX - 10)
    print BaseTunnel.seq_distance(ICMP_SEQ_MAX - 10, 10)
    print BaseTunnel.seq_distance(0, 4722)

    t = BaseTunnel(1, 0, 12, None, None, None)
    t.recv_seq = 12
    t.icmp_recv_bufs = {
        13: None,
        20: None,
        21: None,
        22: None,
        23: None,
        24: None,

        30: None,
        31: None,
        32: None,
        33: None,

        36: None,

        41: None,
        42: None,

        51: None
    }

    t.send_icmp_ack(None, False)
