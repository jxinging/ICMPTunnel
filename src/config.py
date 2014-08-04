# coding: utf8
__author__ = 'JinXing'


import logging
logging.basicConfig(level=logging.DEBUG)
logger = logging

MAX_BUF_LEN = 4096
MAGIC_ID = "tunnel@tcpovericmp"
TCP_BUF_LEN = MAX_BUF_LEN - len(MAGIC_ID) - 20 - 8

MAX_BUFS_LEN = 256
BLOCK_TIME = 10