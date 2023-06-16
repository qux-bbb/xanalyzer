import argparse
import os
from pathlib import Path

from xanalyzer.config import Config
from xanalyzer.file import FileAnalyzer
from xanalyzer.url import UrlAnalyzer
from xanalyzer.utils import init_log, log

file_path_list = []


def get_all_path(the_path):
    """获取所有路径，深度优先

    Args:
        the_path (string): 一个路径
    """
    if os.path.isfile(the_path):
        file_path_list.append(the_path)
        return

    a_path = None
    for a_path in Path(the_path).iterdir():
        get_all_path(a_path)

    if not a_path:  # 空文件夹，提示一下
        log.warning(f"folder is empty: {the_path}")


def main():
    parser = argparse.ArgumentParser(
        prog="xanalyzer", description="Process some files and urls."
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-f",
        "--file",
        nargs="+",
        help="analyze one or more files, can be a folder path",
    )
    group.add_argument("-u", "--url", help="analyze the url")
    group.add_argument("--version", action="store_true", help="print version info")
    parser.add_argument("-s", "--save", action="store_true", help="save log and data")
    parser.add_argument("--deep", action="store_true", help="analyze deeply")
    args = parser.parse_args()

    if args.version:
        print(Config.VERSION)
        return

    Config.init(args.save)
    init_log()

    log.info("=" * 80)

    deep_flag = args.deep

    if args.file:
        for the_path in args.file:
            if not os.path.exists(the_path):
                log.warning("{} does not exist!!!".format(the_path))
                continue
            get_all_path(the_path)
        for file_path in file_path_list:
            log.info("processing {}".format(file_path))
            file_analyzer = FileAnalyzer(file_path)
            file_analyzer.run()
            log.info("-" * 80)
    if args.url:
        log.info("processing {}".format(args.url))
        url_analyzer = UrlAnalyzer(args.url, deep_flag)
        url_analyzer.run()
        log.info("-" * 80)

    if Config.conf["save_flag"]:
        log.info(
            "the log and data are saved to {} folder".format(
                Config.conf["analyze_path"]
            )
        )


if __name__ == "__main__":
    main()
