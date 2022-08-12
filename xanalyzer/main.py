#! /usr/bin/env python
# coding:utf8

import os
import argparse
from pathlib import Path

from xanalyzer.file import FileAnalyzer
from xanalyzer.url import UrlAnalyzer
from xanalyzer.utils import log, init_log
from xanalyzer.config import Config


def main():
    parser = argparse.ArgumentParser(
        prog='xanalyzer',
        description='Process some files and urls.')
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument('-f', '--file', nargs='+', help='analyze one or more files, can be a folder path')
    group.add_argument('-u', '--url', help='analyze the url')
    group.add_argument('--version', action='store_true', help='print version info')
    parser.add_argument('-s', '--save', action='store_true', help='save log and data')
    args = parser.parse_args()

    if args.version:
        print(Config.VERSION)
        return

    Config.init(args.save)
    init_log()

    log.info('=' * 80)
    
    if args.file:
        file_paths = []
        for the_path in args.file:
            if os.path.exists(the_path):
                if os.path.isdir(the_path):
                    for a_path in Path(the_path).iterdir():
                        if a_path.is_file():
                            file_paths.append(str(a_path))
                        else:
                            log.warning(f'{a_path} is not a file, will be ignored')
                else:
                    file_paths.append(the_path)
            else:
                log.warning('{} does not exist!!!'.format(the_path))
        for file_path in file_paths:
            log.info('processing {}'.format(file_path))
            file_analyzer = FileAnalyzer(file_path)
            file_analyzer.run()
            log.info('-' * 80)
    if args.url:

        log.info('processing {}'.format(args.url))
        url_analyzer = UrlAnalyzer(args.url)
        url_analyzer.run()
        log.info('-' * 80)

    if Config.conf['save_flag']:
        log.info('the log and data are saved to {} folder'.format(Config.conf['analyze_path']))


if __name__ == "__main__":
    main()
