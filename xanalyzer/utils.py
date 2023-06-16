import logging
import os

import coloredlogs

from xanalyzer.config import Config

log = logging.getLogger("xanalyzer")


def init_log():
    # 指定logger输出格式 -8s: 指定宽度为8，减号表示左对齐
    basic_fmt = "%(asctime)s %(levelname)-8s: %(message)s"

    coloredlogs.install(fmt=basic_fmt)

    if Config.conf["save_flag"]:
        # 文件日志
        log_path = os.path.join(Config.conf["analyze_path"], "xanalyzer.log")
        file_handler = logging.FileHandler(log_path, encoding="utf8")
        file_formatter = logging.Formatter(basic_fmt)
        file_handler.setFormatter(file_formatter)  # 可以通过setFormatter指定输出格式
        log.addHandler(file_handler)
