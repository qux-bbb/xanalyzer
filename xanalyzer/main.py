#! /usr/bin/env python
# coding:utf8

import argparse

from xanalyzer.file import FileAnalyzer
from xanalyzer.url import UrlAnalyzer
from xanalyzer.utils import log, init_log


def main():
    parser = argparse.ArgumentParser(
        prog='xanalyzer',
        description='Process some files and urls.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', nargs='+')
    group.add_argument('-u', '--url')
    parser.add_argument('-s', '--save_log', action='store_true')
    args = parser.parse_args()
    
    init_log(args.save_log)
    
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


if __name__ == "__main__":
    main()
