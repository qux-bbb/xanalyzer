#! /usr/bin/env python
# coding:utf8

import argparse

from x_analyzer.file import FileAnalyzer
from x_analyzer.utils import log, init_log


def main():
    parser = argparse.ArgumentParser(
        prog='x_analyzer',
        description='Process some files and urls.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', nargs='+')
    group.add_argument('-u', '--url')
    args = parser.parse_args()
    
    init_log()
    
    if args.file:
        for file_path in args.file:
            log.info('processing {}'.format(file_path))
            file_analyzer = FileAnalyzer(file_path)
            file_analyzer.run()
    if args.url:
        log.info('processing {}'.format(args.url))
        # TODO 增加url的处理方式, 集成 WebSiteLinkScanner 和 PageFinder
        pass


if __name__ == "__main__":
    main()
