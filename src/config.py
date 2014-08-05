# coding: utf8
__author__ = 'JinXing'


import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging

MAX_POCKET_SIZE = 1024
MAGIC_ID = "tunnel@tcpovericmp"
TCP_BUF_LEN = MAX_POCKET_SIZE - len(MAGIC_ID) - 20 - 8

MAX_BUFS_LEN = 16
BLOCK_TIME = 10
ACK_TIMEOUT = 0.5
