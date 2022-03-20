# coding:utf8

from pathlib import Path
from xanalyzer.file import FileAnalyzer

cur_dir_path = Path(__file__).parent


def test_common_filetype():
    upxed_path = cur_dir_path / 'test_data' / 'Hello_upx.exe_'
    file_analyzer = FileAnalyzer(upxed_path)
    assert file_analyzer.get_type() == 'PE32 executable (console) Intel 80386, for MS Windows, UPX compressed'


def test_chinese_name_filetype():
    chinese_name_path = cur_dir_path / 'test_data' / '中文名测试.txt'
    file_analyzer = FileAnalyzer(chinese_name_path)
    file_analyzer.get_type()
    assert file_analyzer.get_type() == 'UTF-8 Unicode text, with no line terminators'
