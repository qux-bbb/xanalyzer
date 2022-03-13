# coding:utf8

import os
import sys
import logging

from xanalyzer.config import Config


log = logging.getLogger('xanalyzer')


def init_log():
    # 指定logger输出格式 -8s: 指定宽度为8，减号表示左对齐
    formatter = logging.Formatter('%(asctime)s %(levelname)-8s: %(message)s')

    if Config.conf['save_flag']:
        # 文件日志
        log_path = os.path.join(Config.conf['analyze_path'], 'xanalyzer.log')
        file_handler = logging.FileHandler(log_path, encoding='utf8')
        file_handler.setFormatter(formatter)  # 可以通过setFormatter指定输出格式
        log.addHandler(file_handler)
    # 控制台日志
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setFormatter(formatter)
    log.addHandler(console_handler)
    # 指定日志的最低输出级别，默认为WARNING级别
    log.setLevel(logging.INFO)
