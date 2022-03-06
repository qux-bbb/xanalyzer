# coding:utf8

import sys
import time
import logging


log = logging.getLogger('x_analyzer')


def init_log():
    # 指定logger输出格式 -8s: 指定宽度为8，减号表示左对齐
    formatter = logging.Formatter('%(asctime)s %(levelname)-8s: %(message)s')

    cur_time = time.strftime('%Y%m%d_%H%M%S')
    # 文件日志
    file_handler = logging.FileHandler(f'x_analyzer_{cur_time}.log')
    file_handler.setFormatter(formatter)  # 可以通过setFormatter指定输出格式
    # 控制台日志
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)

    log.addHandler(file_handler)
    log.addHandler(console_handler)
    # 指定日志的最低输出级别，默认为WARNING级别
    log.setLevel(logging.INFO)
