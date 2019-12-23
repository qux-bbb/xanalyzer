# coding:utf8

import os
import sys

from x_analyzer.config import Config


def color(text, color_code):
    if sys.platform == 'win32' and os.getenv('TERM') != 'xterm':
        return text
    return '\x1b[{}m{}\x1b[0m'.format(color_code, text)


def red(text):
    return color(text, 31)


def green(text):
    return color(text, 32)


def yellow(text):
    return color(text, 33)


def blue(text):
    return color(text, 34)


def bold(text):
    return color(text, 1)


def log_red(text):
    """
    重要日志
    """
    log_file = open(Config.log_file_path, 'a')
    message = '[!] {}'.format(text)
    print(red(message))
    log_file.write('{}\n'.format(message))
    log_file.close()


def log(text):
    """
    普通日志
    """
    log_file = open(Config.log_file_path, 'a')
    message = '[*] {}'.format(text)
    print(message)
    log_file.write('{}\n'.format(message))
    log_file.close()