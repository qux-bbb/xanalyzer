#! /usr/bin/env python
# coding:utf8

import argparse

from xanalyzer.file import FileAnalyzer
from xanalyzer.url import UrlAnalyzer
from xanalyzer.utils import log, init_log
from xanalyzer.config import Config


def main():
    parser = argparse.ArgumentParser(
        prog='xanalyzer',
        description='Process some files and urls.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', nargs='+', help='analyze one or more files')
    group.add_argument('-u', '--url', help='analyze the url')
    parser.add_argument('-s', '--save', action='store_true', help='save log and data')
    args = parser.parse_args()

    Config.init(args.save)
    init_log()
    
    if args.file:
        for file_path in args.file:
            log.info('processing {}'.format(file_path))
            file_analyzer = FileAnalyzer(file_path)
            file_analyzer.run()
    if args.url:
        log.info('processing {}'.format(args.url))
        url_analyzer = UrlAnalyzer(args.url)
        url_analyzer.run()
        # TODO 增加url的处理方式, 集成 WebSiteLinkScanner 和 PageFinder

    if Config.conf['save_flag']:
        log.info('the log and data are saved to {} folder'.format(Config.conf['analyze_path']))


if __name__ == "__main__":
    main()
