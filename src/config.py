# coding: utf8
__author__ = 'JinXing'


import logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s [%(levelname)s]# %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S', filemode='a+'
)
logger = logging

MAX_POCKET_SIZE = 1024
AUTH_STR = "^tun@icmp$"
AUTH_STR_LEN = len(AUTH_STR)

# 一次可发送的 TCP 数据包长度:
# 最大 ICMP 包长度 - 20字节IP包头 - 8字节ICMP包头 - 认证字符串长度 - 2字节自定义消息头
TCP_BUF_LEN = MAX_POCKET_SIZE - 20 - 8 - len(AUTH_STR) - 2

MAX_WAIT_ACK_POCKETS = 64   # 最多等待确认的数据包数量

ACK_TIMEOUT = 0.5   # 确认超时时长
KEEPALIVE_TIMEOUT = ACK_TIMEOUT * 10    # 保活超时时长
CLOSE_TIMEOUT = KEEPALIVE_TIMEOUT * 2   # 关闭 tunnel 后等待的时长

ICMP_SEQ_MAX = 0xFFFF   # icmp seq 的最大值 (icmp 协议定义seq占2字节)
