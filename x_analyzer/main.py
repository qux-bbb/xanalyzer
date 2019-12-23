#! /usr/bin/env python
# coding:utf8

import argparse

from x_analyzer.config import Config
from x_analyzer.file import FileAnalyzer
from x_analyzer.utils import log


def main():
    parser = argparse.ArgumentParser(
        prog='x_analyzer',
        description='Process some files and urls.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', nargs='+')
    group.add_argument('-u', '--url')
    args = parser.parse_args()
    
    Config.set_log_file_path()
    
    if args.file:
        for file_path in args.file:
            log('processing {}'.format(file_path))
            file_analyzer = FileAnalyzer(file_path)
            file_analyzer.run()
    if args.url:
        log('processing {}'.format(args.url))
        # TODO 增加url的处理方式, 集成 WebSiteLinkScanner 和 PageFinder
        pass


if __name__ == "__main__":
    main()
